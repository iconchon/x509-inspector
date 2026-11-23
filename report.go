package main

import (
	"fmt"
	"strings"

	"x509inspector/engine"
)

var sevMark = map[string]string{engine.SevError: "[ERROR]", engine.SevWarn: "[WARN ]", engine.SevInfo: "[INFO ]", engine.SevOK: "[ OK  ]"}

// TextReport renders a plain-text report (used by CLI and export).
func TextReport(r *engine.Report, verbose bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "X.509 Inspector %s — laporan\n", version)
	fmt.Fprintf(&b, "Waktu validasi : %s\n", r.At)
	fmt.Fprintf(&b, "Ringkasan      : %d error, %d peringatan, %d info, %d ok\n",
		r.Counts[engine.SevError], r.Counts[engine.SevWarn], r.Counts[engine.SevInfo], r.Counts[engine.SevOK])
	for _, n := range r.Notes {
		writeFinding(&b, n, "")
	}
	objs := map[string]*engine.Object{}
	for _, o := range r.Objects {
		objs[o.ID] = o
	}
	for _, f := range r.Files {
		b.WriteString("\n" + strings.Repeat("=", 78) + "\n")
		fmt.Fprintf(&b, "FILE: %s  (%s, %d byte)\n", f.Name, f.Format, f.Size)
		if f.Path != "" {
			fmt.Fprintf(&b, "      %s\n", f.Path)
		}
		fmt.Fprintf(&b, "      SHA-256 %s\n", f.SHA256)
		for _, fd := range f.Findings {
			writeFinding(&b, fd, "  ")
		}
		for _, id := range f.Objects {
			o := objs[id]
			if o == nil {
				continue
			}
			b.WriteString("\n  " + strings.Repeat("-", 74) + "\n")
			fmt.Fprintf(&b, "  [%s] %s — %s\n", strings.ToUpper(o.Worst), o.Label, o.Where)
			if o.Role != "" {
				fmt.Fprintf(&b, "  Peran: %s\n", o.Role)
			}
			for _, kv := range o.Summary {
				fmt.Fprintf(&b, "    %-18s %s\n", kv.K+":", kv.V)
			}
			if len(o.Chain) > 0 {
				b.WriteString("    Rantai:\n")
				for i, l := range o.Chain {
					fmt.Fprintf(&b, "      %s%s [%s] %s\n", strings.Repeat("  ", i), l.Label, l.Status, l.Note)
				}
			}
			for _, fd := range o.Findings {
				if !verbose && fd.Sev == engine.SevOK {
					continue
				}
				writeFinding(&b, fd, "    ")
			}
		}
	}
	return b.String()
}

func writeFinding(b *strings.Builder, f engine.Finding, ind string) {
	fmt.Fprintf(b, "%s%s %-13s %s\n", ind, sevMark[f.Sev], f.Cat, f.Msg)
	if f.Detail != "" {
		for _, l := range strings.Split(f.Detail, "\n") {
			fmt.Fprintf(b, "%s                        %s\n", ind, l)
		}
	}
	if f.Ref != "" {
		fmt.Fprintf(b, "%s                        Ref: %s\n", ind, f.Ref)
	}
}
