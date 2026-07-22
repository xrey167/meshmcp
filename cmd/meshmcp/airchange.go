package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/xrey167/meshmcp/air"
)

// Air · Change — what changed on my reachable mesh since last I looked.
//
// `air catalog` shows what you can reach now; `air change` shows the DELTA from
// a saved snapshot: a backend appeared or left, or one flipped a capability
// (moved address, became steerable/resumable, changed transport). The first run
// against a fresh --snapshot saves a baseline; later runs diff against it (and
// --update rolls the baseline forward). The pure diff lives in air/change.go.
func cmdAirChange(args []string) error {
	fs := flag.NewFlagSet("air change", flag.ExitOnError)
	o := meshFlags(fs)
	snapshot := fs.String("snapshot", "", "snapshot file to diff against (created on first run)")
	update := fs.Bool("update", false, "after diffing, roll the snapshot forward to the current catalog")
	asJSON := fs.Bool("json", false, "print the delta (or the baseline) as JSON")
	resolve := fs.String("resolve", "", "discover the control endpoint from a domain's ARD DNS record instead of a positional address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snapshot == "" {
		return errors.New("air change: --snapshot <file> is required (the baseline to diff against)")
	}

	// Reach the gateway the same two ways `air catalog` does: a known control
	// address, or ARD leg-2 DNS discovery from a domain (--resolve).
	control, catalogURL := "", "http://air-control"+airCatalogPath
	switch {
	case *resolve != "":
		if fs.NArg() != 0 {
			return errors.New("air change: give either --resolve <domain> or a <control-ip:port>, not both")
		}
		u, via, err := air.ResolveCatalog(net.LookupTXT, net.LookupSRV, *resolve)
		if err != nil {
			return fmt.Errorf("air change: %w", err)
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("air change: resolved a bad catalog url %q: %w", u, err)
		}
		// Pin to the well-known path, trusting the resolved record only for host:port.
		control = parsed.Host
		catalogURL = parsed.Scheme + "://" + parsed.Host + airCatalogPath
		fmt.Fprintln(os.Stderr, dim("resolved "+*resolve+" → "+catalogURL+" (via "+via+")"))
	case fs.NArg() == 1:
		control = fs.Arg(0)
	default:
		return errors.New("usage: meshmcp air change [flags] <control-ip:port> --snapshot <file>  (or --resolve <domain>)")
	}

	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	cur, _, err := air.FetchCatalog(hc, catalogURL)
	if err != nil {
		return fmt.Errorf("air change: %w", err)
	}

	old, existed, err := loadCatalogSnapshot(*snapshot)
	if err != nil {
		return fmt.Errorf("air change: %w", err)
	}
	// First run: save a baseline and stop — there is nothing to diff against yet.
	if !existed {
		if err := saveCatalogSnapshot(*snapshot, cur); err != nil {
			return fmt.Errorf("air change: %w", err)
		}
		if *asJSON {
			return printDeltaJSON(map[string]any{"baseline": *snapshot, "endpoints": len(cur.Endpoints)})
		}
		fmt.Println(okLine("baseline saved to %s", *snapshot) + dim(fmt.Sprintf(" · %d endpoint(s)", len(cur.Endpoints))))
		return nil
	}

	delta := air.DiffCatalogs(old, cur)
	if *update {
		if err := saveCatalogSnapshot(*snapshot, cur); err != nil {
			return fmt.Errorf("air change: %w", err)
		}
	}
	if *asJSON {
		return printDeltaJSON(delta)
	}
	renderCatalogDelta(delta)
	if *update && !delta.Empty() {
		fmt.Fprintln(os.Stderr, dim("snapshot rolled forward to current"))
	}
	return nil
}

// loadCatalogSnapshot reads a saved catalog, reporting existed=false (not an
// error) when the file is absent so the first run can write a baseline.
func loadCatalogSnapshot(path string) (cat air.Catalog, existed bool, err error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return air.Catalog{}, false, nil
	}
	if err != nil {
		return air.Catalog{}, false, err
	}
	if err := json.Unmarshal(data, &cat); err != nil {
		return air.Catalog{}, false, fmt.Errorf("snapshot %s is not a catalog: %w", path, err)
	}
	return cat, true, nil
}

// saveCatalogSnapshot writes the catalog as indented JSON.
func saveCatalogSnapshot(path string, cat air.Catalog) error {
	data, err := json.MarshalIndent(cat.Sorted(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// renderCatalogDelta prints the delta as coloured lines: additions green,
// removals red, capability changes amber with each field's old→new value.
func renderCatalogDelta(d air.CatalogDelta) {
	if d.Empty() {
		fmt.Println(dim("no changes since the last snapshot"))
		return
	}
	for _, e := range d.Added {
		fmt.Println(green("+ ") + bold(e.Name) + dim("  "+e.Address+"  "+e.Transport+catalogCapsSuffix(e)))
	}
	for _, e := range d.Removed {
		fmt.Println(red("- ") + bold(e.Name) + dim("  "+e.Address+"  "+e.Transport))
	}
	for _, c := range d.Changed {
		fmt.Print(amber("~ ") + bold(c.Name) + "  ")
		for i, f := range c.Fields {
			if i > 0 {
				fmt.Print(dim(" · "))
			}
			fmt.Print(dim(f+" ") + changeVal(f, c.From) + dim("→") + changeVal(f, c.To))
		}
		fmt.Println()
	}
	fmt.Fprintln(os.Stderr, dim(d.Summary()+" since the last snapshot"))
}

// catalogCapsSuffix renders an added entry's capabilities as a dim suffix.
func catalogCapsSuffix(e air.CatalogEntry) string {
	c := catalogCaps(e)
	if c == "—" {
		return ""
	}
	return "  " + c
}

// changeVal formats one capability field's value for a change line.
func changeVal(field string, e air.CatalogEntry) string {
	switch field {
	case "address":
		return e.Address
	case "transport":
		return e.Transport
	case "steerable":
		return fmt.Sprintf("%t", e.Steerable)
	case "resumable":
		return fmt.Sprintf("%t", e.Resumable)
	}
	return ""
}

// printJSON marshals v as indented JSON to stdout.
func printDeltaJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
