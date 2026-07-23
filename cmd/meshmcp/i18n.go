package main

import (
	"os"
	"strings"
	"sync"
)

// The i18n foundation (gap 11): user-facing strings route through tr() so they
// can localize BEFORE they multiply further. The design keeps call sites
// honest and failure soft:
//
//   - The English text IS the catalog key. A call site stays readable, and a
//     locale missing a string degrades to English — never a blank, never a
//     panic. English needs no catalog at all.
//   - The locale comes from $MESHMCP_LANG (explicit override), else the
//     language prefix of $LC_ALL / $LANG ("de" from "de_DE.UTF-8").
//   - Scope discipline: only HUMAN terminal lines are translated. Error
//     VALUES, JSON fields, and log records stay English — they are matched by
//     code (hintFor, tests, scripts) and are part of the machine surface.
//   - Keys carry no ambient indentation; layout is composed at the call site,
//     so a translation can never break alignment.
//
// German is the proving second locale, covering the golden path (init → up →
// join). To add a locale: add its map below and translate any subset —
// whatever is missing simply stays English.

// resolveLocale reads the environment; trLocale caches it once per process
// (tests re-arm the OnceValue to pin their own environment).
func resolveLocale() string {
	for _, v := range []string{os.Getenv("MESHMCP_LANG"), os.Getenv("LC_ALL"), os.Getenv("LANG")} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		// "de_DE.UTF-8" → "de"; "de-AT" → "de".
		v = strings.ToLower(v)
		if i := strings.IndexAny(v, "_-."); i > 0 {
			v = v[:i]
		}
		return v
	}
	return "en"
}

var trLocale = sync.OnceValue(resolveLocale)

// tr returns msg in the active locale, or msg itself when no translation
// exists (English, unknown locales, untranslated strings).
func tr(msg string) string {
	loc := trLocale()
	if loc == "en" {
		return msg
	}
	if cat, ok := catalogs[loc]; ok {
		if t, ok := cat[msg]; ok {
			return t
		}
	}
	return msg
}

// catalogs maps locale → English text → translation.
var catalogs = map[string]map[string]string{
	"de": {
		// air init / air up — scaffold summary
		"wrote %s":        "%s geschrieben",
		"using %s":        "verwende %s",
		"Safe by default": "Sicher voreingestellt",
		"deny-by-default — no tool is reachable until you grant it": "standardmäßig verweigert — kein Tool ist erreichbar, bis du es freigibst",
		"audit on — ":       "Audit aktiv — ",
		"Identity":          "Identität",
		"mesh key detected": "Mesh-Schlüssel erkannt",
		"Next:":             "Weiter:",
		"one step left — set your mesh setup key:":     "ein Schritt fehlt noch — setze deinen Mesh-Setup-Schlüssel:",
		"no config at %s — scaffolding a safe default": "keine Konfiguration unter %s — erzeuge eine sichere Vorgabe",
		"bringing up %s":    "starte %s",
		"joining the mesh…": "trete dem Mesh bei…",
		"one step left — your mesh setup key isn't set.": "ein Schritt fehlt noch — dein Mesh-Setup-Schlüssel ist nicht gesetzt.",
		"Get a key from your NetBird dashboard, then:":   "Hol dir einen Schlüssel aus deinem NetBird-Dashboard, dann:",

		// air join — the pairing golden path
		"requesting access as %s":                                                            "fordere Zugang an als %s",
		"waiting for approval… (Ctrl-C to stop)":                                             "warte auf Freigabe… (Strg-C zum Abbrechen)",
		"approved — you're recognized on the mesh as %s":                                     "freigegeben — du bist im Mesh erkannt als %s",
		"recognition is not access — ask the operator to grant the specific tools you need.": "Erkennung ist kein Zugriff — bitte den Operator, dir die benötigten Tools gezielt freizugeben.",
		"✗ your request was declined.":                                                       "✗ deine Anfrage wurde abgelehnt.",
		"✗ your request was declined: ":                                                      "✗ deine Anfrage wurde abgelehnt: ",
		"If you think this is a mistake, contact the gateway's operator, then run `air join` again — a fresh request re-queues for approval.": "Wenn das ein Irrtum ist, wende dich an den Operator des Gateways und führe `air join` erneut aus — eine neue Anfrage wird wieder zur Freigabe vorgelegt.",
		"Contact the gateway's operator, then run `air join` again to re-queue.":                                                              "Wende dich an den Operator des Gateways und führe `air join` erneut aus.",

		// error presenter frame
		"(run with --verbose or MESHMCP_LOG=debug for diagnostic logging)": "(mit --verbose oder MESHMCP_LOG=debug für Diagnose-Ausgaben starten)",
	},
}
