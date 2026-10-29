package posture

// Behavioural tests for observed mode. They run the inert probes inside a
// real srt and compare with the model. Opt-in: set AGENTREACH_SRT to the srt
// binary (make test-srt). They use fixture homes only, never the real home.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func srtBinary(t *testing.T) string {
	t.Helper()
	p := os.Getenv("AGENTREACH_SRT")
	if p == "" {
		t.Skip("set AGENTREACH_SRT to the srt binary to run behavioural tests (make test-srt)")
	}
	return p
}

func (f fixture) observe(srt string, listeners ...string) *Snapshot {
	return Collect(context.Background(), Options{Home: f.home, Probe: true, Observe: true, SRTPath: srt,
		ManagedDir: f.managed, PlistPath: "-", Listeners: listeners})
}

func srtReachFile(t *testing.T, snap *Snapshot, suffix string) ReachFile {
	t.Helper()
	for _, r := range snap.ReachFiles {
		if strings.HasSuffix(r.Path, suffix) {
			return r
		}
	}
	t.Fatalf("no reach_file row ending %s", suffix)
	return ReachFile{}
}

func srtReachHost(t *testing.T, snap *Snapshot, target string) ReachHost {
	t.Helper()
	for _, h := range snap.ReachHosts {
		if h.Target == target {
			return h
		}
	}
	t.Fatalf("no reach_host row %s", target)
	return ReachHost{}
}

func srtBool(b *bool) string {
	if b == nil {
		return "null"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestSRTDenyReadObserved(t *testing.T) {
	srt := srtBinary(t)
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".ssh", "id_x"), "fixture key\n")
	f.write(filepath.Join(f.home, ".aws", "credentials"), "[default]\n")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"filesystem":{"denyRead":["~/.ssh"]}}}`)
	snap := f.observe(srt)
	if !snap.Observed {
		t.Fatalf("observed mode did not run: tool=%q errors=%v", snap.ObservedTool, snap.Errors)
	}
	ssh := srtReachFile(t, snap, "/.ssh")
	aws := srtReachFile(t, snap, "/.aws/credentials")
	if ssh.ObservedViaSandbox == nil || *ssh.ObservedViaSandbox {
		t.Errorf("~/.ssh under denyRead: observed_via_sandbox = %s, want false", srtBool(ssh.ObservedViaSandbox))
	}
	if aws.ObservedViaSandbox == nil || !*aws.ObservedViaSandbox {
		t.Errorf("~/.aws/credentials with no rule: observed_via_sandbox = %s, want true", srtBool(aws.ObservedViaSandbox))
	}
	for _, r := range []ReachFile{ssh, aws} {
		if r.ModelAgrees == nil || !*r.ModelAgrees {
			t.Errorf("%s: model_agrees = %s (model reachable_via_bash=%s, observed=%s)", r.Path,
				srtBool(r.ModelAgrees), srtBool(r.ReachableViaBash), srtBool(r.ObservedViaSandbox))
		}
	}
}

func TestSRTLoopbackObserved(t *testing.T) {
	srt := srtBinary(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	// wantModel is allowed_by_sandbox: reach through the sandbox proxy.
	// The probe is a direct dial, so for an allowedDomains literal the two
	// differ by design.
	cases := []struct {
		name, network string
		wantObserved  bool
		wantModel     bool
		darwinOnly    bool
	}{
		// No rule: a direct dial to a host port is refused (macOS seatbelt;
		// on Linux the sandbox's loopback is its own).
		{"no rule", `{}`, false, false, false},
		// allowLocalBinding opens direct loopback dials on macOS only.
		{"allowLocalBinding", `{"allowLocalBinding":true}`, true, true, true},
		// An allowedDomains entry governs the proxy, not a direct dial.
		{"allowedDomains literal", `{"allowedDomains":["` + addr + `"]}`, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.darwinOnly && runtime.GOOS != "darwin" {
				t.Skip("allowLocalBinding has no effect on Linux (settings-reference)")
			}
			f := newFixture(t)
			f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"network":`+tc.network+`}}`)
			snap := f.observe(srt, addr)
			if !snap.Observed {
				t.Fatalf("observed mode did not run: tool=%q errors=%v", snap.ObservedTool, snap.Errors)
			}
			h := srtReachHost(t, snap, addr)
			if h.ObservedViaSandbox == nil || *h.ObservedViaSandbox != tc.wantObserved {
				t.Errorf("observed_via_sandbox = %s, want %v", srtBool(h.ObservedViaSandbox), tc.wantObserved)
			}
			if h.AllowedBySandbox == nil || *h.AllowedBySandbox != tc.wantModel {
				t.Errorf("model allowed_by_sandbox = %s (rule %q), want %v; srt observed %s",
					srtBool(h.AllowedBySandbox), h.SandboxRule, tc.wantModel, srtBool(h.ObservedViaSandbox))
			}
		})
	}
}
