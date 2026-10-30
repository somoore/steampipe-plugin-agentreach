package posture

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReviewLedger records explicit human review decisions for instruction
// files: "I read this exact content and accept it". A decision is keyed by
// path and SHA-256, so an edit after the review is visible as
// changed_since_review. The ledger is the user's own file; the collector
// only reads it, and only the agentreach CLI's review command writes it.
type ReviewLedger struct {
	Version int      `json:"version"`
	Reviews []Review `json:"reviews"`
	path    string
}

// Review is one decision.
type Review struct {
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	ReviewedAt time.Time `json:"reviewed_at"`
	Note       string    `json:"note,omitempty"`
}

// DefaultReviewLedgerPath is ~/.config/agentreach/reviews.json.
func DefaultReviewLedgerPath(home string) string {
	return filepath.Join(home, ".config", "agentreach", "reviews.json")
}

// LoadReviewLedger reads a ledger; a missing file is an empty ledger.
func LoadReviewLedger(path string) (*ReviewLedger, error) {
	l := &ReviewLedger{Version: 1, path: path}
	b, err := readFileLimited(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(b, l); err != nil {
		return &ReviewLedger{Version: 1, path: path}, err
	}
	l.path = path
	return l, nil
}

func loadReviewLedger(path, home string, snap *Snapshot) *ReviewLedger {
	if path == "" {
		path = DefaultReviewLedgerPath(home)
	}
	l, err := LoadReviewLedger(path)
	if err != nil {
		snap.Errors = append(snap.Errors, "review ledger: "+path+": "+err.Error()+"; review decisions ignored")
	}
	return l
}

// Status reports whether this content was reviewed, and whether the path
// was reviewed with different content.
func (l *ReviewLedger) Status(path, sha string) (reviewed, changed bool) {
	if l == nil || sha == "" {
		return false, false
	}
	seenPath := false
	for _, r := range l.Reviews {
		if r.Path != path {
			continue
		}
		seenPath = true
		if strings.EqualFold(r.SHA256, sha) {
			return true, false
		}
	}
	return false, seenPath
}

// Add records a review of path at its current content and saves the
// ledger. Earlier decisions for the same path are kept as history.
func (l *ReviewLedger) Add(path, sha, note string, at time.Time) error {
	if reviewed, _ := l.Status(path, sha); !reviewed {
		l.Reviews = append(l.Reviews, Review{Path: path, SHA256: sha, ReviewedAt: at.UTC(), Note: note})
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// markInstructionTrust decides which instruction files count as untrusted
// sources. Provenance decides; content signals only ask for a review.
//
//   - plugin-provided (plugin not disabled), or last committed by someone
//     outside the repository's identity set: untrusted unless this exact
//     content is in the review ledger;
//   - writable by group or others: untrusted regardless of review, since
//     anyone in that class can change it after the review;
//   - reviewed earlier but changed since: untrusted until reviewed again.
//
// Hidden Unicode, HTML comments, external URLs and @imports are recorded in
// review_signals. They justify a look; they do not by themselves make a file
// untrusted, and matching the repository's git identity does not make a
// file trustworthy either: it only means agentreach has no provenance signal.
func (c *ccCollector) markInstructionTrust() {
	for i := range c.snap.InstructionFiles {
		f := &c.snap.InstructionFiles[i]
		if f.Agent != AgentClaudeCode {
			continue
		}
		markTrust(f, c.reviews)
	}
}

func markTrust(f *InstructionFile, l *ReviewLedger) {
	var sig []string
	if f.HiddenUnicode > 0 {
		sig = append(sig, "hidden_unicode")
	}
	if f.HTMLComments > 0 {
		sig = append(sig, "html_comments")
	}
	if f.ExternalURLs > 0 {
		sig = append(sig, "external_urls")
	}
	if f.ExternalIncludes > 0 {
		sig = append(sig, "external_includes")
	}
	f.ReviewSignals = strings.Join(sig, ",")
	f.Reviewed, f.ChangedSinceReview = l.Status(f.Path, f.SHA256)
	if f.PluginEnabled != nil && !*f.PluginEnabled {
		return // a disabled plugin's files do not load
	}
	var why []string
	if f.WritableBy != "" && f.WritableBy != "owner" {
		why = append(why, "writable by "+f.WritableBy)
	}
	if f.ChangedSinceReview {
		why = append(why, "changed since review")
	}
	if !f.Reviewed {
		switch {
		case f.PluginName != "":
			why = append(why, "plugin "+f.PluginName)
		case f.ThirdParty:
			who := f.GitLastAuthor
			switch {
			case who == "":
				who = "someone else"
			case codingAgentIdentity(who):
				// A coding agent's commit in your repository: you did not
				// write it, but no other person did either. It can still carry
				// text the agent picked up from content it read.
				who = "a coding agent (" + who + "), not one of your git identities"
			}
			if f.GitUncommitted {
				who += ", with uncommitted changes on this machine since"
			}
			why = append(why, "last commit by "+who)
		}
	}
	f.Untrusted = len(why) > 0
	f.UntrustedReason = strings.Join(why, "; ")
}

// codingAgentIdentity reports git author emails coding agents commit as.
func codingAgentIdentity(email string) bool {
	switch strings.ToLower(email) {
	case "noreply@anthropic.com":
		return true
	}
	return false
}
