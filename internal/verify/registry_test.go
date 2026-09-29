package verify

import (
	"os"
	"strings"
	"testing"
)

// TestEveryKnownClaimTypeIsInTheFormatRegistry keeps the verifier's registry and the specification's
// claim table from parting company.
//
// The two are maintained by hand in different files, and they had already drifted: the verifier
// accepted loomseal.agentrun/1 while the format's table did not list it, so a producer reading the
// spec would not know the type existed and a reader checking the spec against a bundle would find a
// type the document does not admit. A registry is only useful while it is the same registry
// everywhere.
func TestEveryKnownClaimTypeIsInTheFormatRegistry(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../FORMAT.md")
	if err != nil {
		t.Fatalf("read FORMAT.md: %v", err)
	}
	spec := string(raw)
	for claimType := range knownClaimTypes {
		if !strings.Contains(spec, "`"+claimType+"`") {
			t.Errorf("the verifier accepts %s but FORMAT.md's claim registry does not list it",
				claimType)
		}
	}
}

// TestReservedRegistryRowsStayOutOfTheKnownSet pins the other direction: a row FORMAT.md marks
// reserved must not sit in the verifier's known set, because "known" reads in every report as
// "checked against a registry entry", and claiming that for a type nothing emits is false. The
// row enters the set the day something emits it, never before.
func TestReservedRegistryRowsStayOutOfTheKnownSet(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../FORMAT.md")
	if err != nil {
		t.Fatalf("read FORMAT.md: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "reserved") || !strings.Contains(line, "`") {
			continue
		}
		start := strings.Index(line, "`")
		end := strings.Index(line[start+1:], "`")
		if end < 0 {
			continue
		}
		name := line[start+1 : start+1+end]
		if !strings.Contains(name, "/") {
			continue
		}
		if knownClaimTypes[name] {
			t.Errorf("%s is marked reserved in FORMAT.md but sits in the verifier's known set", name)
		}
	}
}
