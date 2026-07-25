package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// The plugin advertised "10 framework coverage" long after it had grown to 15
// selectable baselines across 13 frameworks. Nobody noticed because nothing
// tied the number in the description to the table it describes, and the stale
// figure propagated outward: into the registry index (generated from
// plugin.yaml), the README, and three pages of the website.
//
// For a compliance plugin the count is not marketing trivia — it is the answer
// to "is my framework covered?" — so it is pinned here to the table itself.
//
// FedRAMP Low/Moderate/High are three baselines of ONE framework. Counting
// them as three would overstate coverage, so the headline number collapses
// them and the baseline count is reported alongside.
func TestDocumentedFrameworkCountMatchesTheTable(t *testing.T) {
	baselines := len(frameworksByName)

	distinct := map[string]bool{}
	for id := range frameworksByName {
		if strings.HasPrefix(id, "fedramp-") {
			distinct["fedramp"] = true
			continue
		}
		distinct[id] = true
	}
	frameworks := len(distinct)

	if frameworks == 0 || baselines < frameworks {
		t.Fatalf("implausible counts: %d frameworks, %d baselines", frameworks, baselines)
	}

	// plugin.yaml is the source the registry index is generated from, so a
	// stale number there is the one that reaches users.
	manifest, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatalf("read plugin.yaml: %v", err)
	}
	want := strconv.Itoa(frameworks)
	if !strings.Contains(string(manifest), want+"-framework") {
		t.Errorf("plugin.yaml does not advertise %s-framework coverage; the table has %d frameworks (%d baselines).\n"+
			"Update the description — this number reaches users through the registry index.",
			want, frameworks, baselines)
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	if !strings.Contains(string(readme), want+" frameworks") {
		t.Errorf("README.md does not state %s frameworks (table has %d frameworks, %d baselines)", want, frameworks, baselines)
	}
}
