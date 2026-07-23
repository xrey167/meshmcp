package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
)

// resetLocaleForTest re-arms the once-per-process locale resolution so each
// test can pin its own environment. Tests only — production resolves once.
func resetLocaleForTest(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range []string{"MESHMCP_LANG", "LC_ALL", "LANG"} {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	trLocale = sync.OnceValue(resolveLocale)
}

// TestTrGermanGoldenPath proves the proving locale actually proves something:
// the golden-path strings translate, format verbs survive, and the catalog's
// keys exactly match what the call sites pass (a drifted key would silently
// fall back to English — this test is the drift alarm).
func TestTrGermanGoldenPath(t *testing.T) {
	resetLocaleForTest(t, map[string]string{"MESHMCP_LANG": "de"})
	for key, want := range map[string]string{
		"wrote %s":                     "%s geschrieben",
		"Safe by default":              "Sicher voreingestellt",
		"joining the mesh…":            "trete dem Mesh bei…",
		"requesting access as %s":      "fordere Zugang an als %s",
		"✗ your request was declined.": "✗ deine Anfrage wurde abgelehnt.",
	} {
		if got := tr(key); got != want {
			t.Errorf("tr(%q) = %q, want %q", key, got, want)
		}
	}
	// An untranslated string degrades to itself, never to a blank.
	if got := tr("some brand new string"); got != "some brand new string" {
		t.Errorf("untranslated string mutated: %q", got)
	}
}

// TestTrLocaleResolution pins the precedence and parsing: MESHMCP_LANG wins,
// then LC_ALL, then LANG; region/encoding suffixes are stripped; unknown
// locales and empty environments mean English (identity).
func TestTrLocaleResolution(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"explicit override", map[string]string{"MESHMCP_LANG": "de", "LANG": "fr_FR.UTF-8"}, "de"},
		{"lc_all beats lang", map[string]string{"LC_ALL": "de_DE.UTF-8", "LANG": "fr_FR.UTF-8"}, "de"},
		{"lang suffix stripped", map[string]string{"LANG": "de_AT.UTF-8"}, "de"},
		{"bcp47 dash", map[string]string{"LANG": "de-CH"}, "de"},
		{"empty means english", map[string]string{}, "en"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetLocaleForTest(t, tc.env)
			if got := trLocale(); got != tc.want {
				t.Errorf("locale = %q, want %q", got, tc.want)
			}
		})
	}

	// Unknown locale: tr is the identity function.
	resetLocaleForTest(t, map[string]string{"MESHMCP_LANG": "xx"})
	if got := tr("Safe by default"); got != "Safe by default" {
		t.Errorf("unknown locale must fall back to English, got %q", got)
	}
}

// TestCatalogKeysMatchCallSites is the drift alarm for the whole catalog: every
// German key must be a string the code actually passes to tr(). It greps the
// package source for `tr("` literals and asserts every catalog key appears.
func TestCatalogKeysMatchCallSites(t *testing.T) {
	used := trCallSiteLiterals(t)
	for key := range catalogs["de"] {
		if !used[key] {
			t.Errorf("catalog key %q is not used by any tr(...) call site — translation would never show (key drift?)", key)
		}
	}
}

// trCallSiteLiterals scans this package's source for tr("…") string literals.
func trCallSiteLiterals(t *testing.T) map[string]bool {
	t.Helper()
	used := map[string]bool{}
	re := regexp.MustCompile(`tr\(("(?:[^"\\]|\\.)*")`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			if lit, err := strconv.Unquote(m[1]); err == nil {
				used[lit] = true
			}
		}
	}
	return used
}
