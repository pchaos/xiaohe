//go:build windows

package apprules

import "testing"

// TestListProcessesSmoke locks the enumeration contract the UI picker relies
// on: a snapshot returns entries with a name and an image path (entries whose
// path cannot be read are skipped, so every returned entry must be complete).
func TestListProcessesSmoke(t *testing.T) {
	list, err := ListProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("expected at least the current test process")
	}
	for _, p := range list {
		if p.Name == "" || p.Path == "" {
			t.Errorf("incomplete process entry: %+v", p)
		}
	}
}
