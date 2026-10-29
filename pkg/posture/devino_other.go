//go:build !unix

package posture

// devIno is unavailable here; observed directory probes then read as
// unreachable rather than trusting a listing that may be of a mask.
func devIno(string) string { return "" }
