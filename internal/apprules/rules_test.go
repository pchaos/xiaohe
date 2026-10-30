package apprules

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// --- ExpandWildcards ---

func TestExpandWildcardsKeepsLiteral(t *testing.T) {
	in := "C:\\Games\\app.exe"
	got := ExpandWildcards([]string{in})
	if len(got) != 1 || got[0] != in {
		t.Fatalf("literal path must pass through unchanged: got %v", got)
	}
}

func TestExpandWildcardsExpands(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.exe", "b.exe", "c.txt"} {
		if err := writeFile(t, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	pattern := filepath.Join(dir, "*.exe")
	got := ExpandWildcards([]string{pattern})
	if len(got) != 2 {
		t.Fatalf("want 2 exe matches, got %v", got)
	}
	// filepath.Glob returns sorted matches.
	want0 := filepath.Join(dir, "a.exe")
	want1 := filepath.Join(dir, "b.exe")
	if got[0] != want0 || got[1] != want1 {
		t.Fatalf("want %q,%q got %v", want0, want1, got)
	}
}

func TestExpandWildcardsWindowsSeparators(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"x.exe", "y.exe"} {
		if err := writeFile(t, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	// Windows-style input must yield Windows-style output.
	pattern := strings.ReplaceAll(filepath.Join(dir, "*.exe"), "/", "\\")
	got := ExpandWildcards([]string{pattern})
	want0 := strings.ReplaceAll(filepath.Join(dir, "x.exe"), "/", "\\")
	want1 := strings.ReplaceAll(filepath.Join(dir, "y.exe"), "/", "\\")
	if len(got) != 2 || got[0] != want0 || got[1] != want1 {
		t.Fatalf("win-style want %q,%q got %v", want0, want1, got)
	}
}

func TestExpandWildcardsDropsEmptyMatches(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "*.nomatch")
	got := ExpandWildcards([]string{"C:\\Apps\\keep.exe", empty})
	if len(got) != 1 || got[0] != "C:\\Apps\\keep.exe" {
		t.Fatalf("empty wildcard entry must be dropped, got %v", got)
	}
}

// --- Derive: loose ---

func TestDeriveLooseOnlyBlacklistBlocks(t *testing.T) {
	opts := Options{
		Blacklist: []string{"C:\\Games\\evil.exe", "C:\\Tools\\leak.exe"},
		CoreExe:   "C:\\Core\\aether.exe",
	}
	rules, err := Derive(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("loose mode must produce only blacklist rules, got %d: %+v", len(rules), rules)
	}
	for i, r := range rules {
		if r.Action != "block" || r.Program == "" || r.RemoteIP != "" {
			t.Fatalf("rule %d must be program block without remoteip: %+v", i, r)
		}
		if r.Name != "AE-App-"+strconv.Itoa(i) {
			t.Fatalf("rule %d name = %q", i, r.Name)
		}
	}
}

func TestDeriveLooseEmptyLists(t *testing.T) {
	rules, err := Derive(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("empty lists must yield zero rules, got %+v", rules)
	}
}

// --- Derive: strict ---

func TestDeriveStrictSequence(t *testing.T) {
	opts := Options{
		Strict:    true,
		Whitelist: []string{"C:\\Apps\\b.exe", "C:\\Apps\\a.exe"}, // shuffled on purpose
		Blacklist: []string{"C:\\Apps\\evil.exe"},
		CoreExe:   "C:\\Core\\aether.exe",
		XiaoheExe: "C:\\Xiaohe\\Xiaohe.exe",
	}
	rules, err := Derive(opts)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		action, program, remoteip string
	}
	wants := []want{
		{"allow", "", "127.0.0.0/8,::1/128"},
		{"allow", "", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"},
		{"allow", "C:\\Core\\aether.exe", ""},
		{"allow", "C:\\Xiaohe\\Xiaohe.exe", ""},
		{"allow", "C:\\Apps\\a.exe", ""},
		{"allow", "C:\\Apps\\b.exe", ""},
		{"block", "C:\\Apps\\evil.exe", ""},
		{"block", "", ""}, // catch-all
	}
	if len(rules) != len(wants) {
		t.Fatalf("want %d rules, got %d: %+v", len(wants), len(rules), rules)
	}
	for i, w := range wants {
		r := rules[i]
		if r.Action != w.action || r.Program != w.program || r.RemoteIP != w.remoteip {
			t.Errorf("rule %d = %+v, want %+v", i, r, w)
		}
	}
}

func TestDeriveStrictSameProgramBothLists(t *testing.T) {
	opts := Options{
		Strict:    true,
		Whitelist: []string{"C:\\Apps\\x.exe"},
		Blacklist: []string{"C:\\Apps\\x.exe"},
	}
	rules, err := Derive(opts)
	if err != nil {
		t.Fatal(err)
	}
	var allowX, blockX bool
	for _, r := range rules {
		if r.Program == "C:\\Apps\\x.exe" && r.Action == "allow" {
			allowX = true
		}
		if r.Program == "C:\\Apps\\x.exe" && r.Action == "block" {
			blockX = true
		}
	}
	if !allowX || !blockX {
		t.Fatalf("same program in both lists must yield both rules (block wins by firewall default): %+v", rules)
	}
}

func TestDeriveStrictEmptyListsBaselineOnly(t *testing.T) {
	rules, err := Derive(Options{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	// No core/self paths configured: loopback + LAN allows + catch-all block.
	if len(rules) != 3 {
		t.Fatalf("want baseline 3 rules, got %+v", rules)
	}
	if rules[0].RemoteIP == "" || rules[1].RemoteIP == "" {
		t.Fatalf("first two must be remoteip allows: %+v", rules)
	}
	if rules[2].Action != "block" || rules[2].Program != "" || rules[2].RemoteIP != "" {
		t.Fatalf("last must be catch-all block: %+v", rules[2])
	}
}

// --- Derive: cap ---

func TestDeriveCapLimit(t *testing.T) {
	many := make([]string, 0, MaxListLen)
	for i := range MaxListLen {
		many = append(many, "C:\\Apps\\app"+strconv.Itoa(i)+".exe")
	}
	if _, err := Derive(Options{Blacklist: many}); err != nil {
		t.Fatalf("%d entries must pass the cap: %v", MaxListLen, err)
	}
	many = append(many, "C:\\Apps\\overflow.exe")
	if _, err := Derive(Options{Blacklist: many}); err == nil {
		t.Fatalf("%d entries must exceed the cap with an error", MaxListLen+1)
	}
}

// --- Derive: dedupe ---

func TestDeriveDedupe(t *testing.T) {
	rules, err := Derive(Options{
		Strict:    true,
		Whitelist: []string{"C:\\Apps\\b.exe", "C:\\Apps\\a.exe", "C:\\Apps\\b.exe", "C:\\Apps\\a.exe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var allows []string
	for _, r := range rules {
		if r.Action == "allow" && r.Program != "" {
			allows = append(allows, r.Program)
		}
	}
	if len(allows) != 2 || allows[0] != "C:\\Apps\\a.exe" || allows[1] != "C:\\Apps\\b.exe" {
		t.Fatalf("dupes must collapse and sort: %v", allows)
	}
}

// --- Rule.Args ---

func TestRuleArgsProgramWithSpace(t *testing.T) {
	r := Rule{Name: "AE-App-0", Action: "block", Program: "C:\\Program Files\\My App\\app.exe"}
	args := r.Args()
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"name=AE-App-0", "dir=out", "action=block", "program=C:\\Program Files\\My App\\app.exe"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %v missing %q", args, want)
		}
	}
	// The program path must be a single argv element (exec.Command, no shell).
	for _, a := range args {
		if strings.HasPrefix(a, "program=") && a != "program=C:\\Program Files\\My App\\app.exe" {
			t.Errorf("args %v: program split across tokens", args)
		}
	}
}

// --- helpers ---

func writeFile(t *testing.T, path string) error {
	t.Helper()
	return os.WriteFile(path, []byte("x"), 0o644)
}

func TestRuleArgsEmbeddedQuote(t *testing.T) {
	r := Rule{Name: "AE-App-0", Action: "block", Program: `C:\Apps\We"ird\app.exe`}
	for _, a := range r.Args() {
		if a == `program=C:\Apps\We"ird\app.exe` {
			return
		}
	}
	t.Fatalf("embedded quote must pass as one literal token: %v", r.Args())
}

func TestDeriveCapLimitWhitelist(t *testing.T) {
	many := make([]string, 0, MaxListLen+1)
	for i := range MaxListLen + 1 {
		many = append(many, "C:\\Apps\\app"+strconv.Itoa(i)+".exe")
	}
	if _, err := Derive(Options{Strict: true, Whitelist: many}); err == nil {
		t.Fatal("whitelist over the cap must error")
	}
	if _, err := Derive(Options{Strict: true, Whitelist: many[:MaxListLen]}); err != nil {
		t.Fatalf("whitelist at the cap must pass: %v", err)
	}
}

func TestExistingOnly(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "real.exe")
	if err := writeFile(t, f); err != nil {
		t.Fatal(err)
	}
	got := ExistingOnly([]string{f, filepath.Join(dir, "missing.exe")})
	if len(got) != 1 || got[0] != f {
		t.Fatalf("only existing paths must survive: %v", got)
	}
}
