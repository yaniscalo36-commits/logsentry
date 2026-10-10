package main

import (
	"fmt"
	"io"
	"strings"
)

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
)

type palette bool

func (p palette) c(code, s string) string {
	if !p {
		return s
	}
	return code + s + reset
}

func sevColor(s Severity) string {
	switch s {
	case Critical:
		return bold + magenta
	case High:
		return red
	case Medium:
		return yellow
	}
	return blue
}

const dateFmt = "02/01 15:04:05"

// printText affiche le rapport dans le terminal.
func printText(w io.Writer, r *Report, alerts []Alert, color bool) {
	p := palette(color)
	st := r.Stats

	fmt.Fprintf(w, "\n%s %d fichier(s) · %d lignes · %d événements analysés\n",
		p.c(bold, "logsentry"), len(st.Files), st.Lines, st.Events)
	if st.Events > 0 {
		fmt.Fprintf(w, "%s\n", p.c(dim, fmt.Sprintf("période : %s → %s", st.First.Format(dateFmt), st.Last.Format(dateFmt))))
	}

	fmt.Fprintf(w, "\n%s %s · %s · %s · %s\n", p.c(bold, "Alertes :"),
		p.c(sevColor(Critical), fmt.Sprintf("%d critique(s)", r.Count(Critical))),
		p.c(sevColor(High), fmt.Sprintf("%d haute(s)", r.Count(High))),
		p.c(sevColor(Medium), fmt.Sprintf("%d moyenne(s)", r.Count(Medium))),
		p.c(sevColor(Low), fmt.Sprintf("%d faible(s)", r.Count(Low))))

	if len(r.Alerts) == 0 {
		fmt.Fprintf(w, "\n%s Aucune activité suspecte détectée.\n\n", p.c(green, "✔"))
		return
	}

	for _, a := range alerts {
		label := strings.ToUpper(a.Severity.String())
		fmt.Fprintf(w, "\n%s %s — %s\n", p.c(sevColor(a.Severity), "["+label+"]"), p.c(bold, a.Title), p.c(cyan, a.IP))
		when := a.First.Format(dateFmt)
		if !a.Last.Equal(a.First) {
			when += " → " + a.Last.Format("15:04:05")
		}
		fmt.Fprintf(w, "  %s\n", p.c(dim, fmt.Sprintf("%s · %d événement(s) · MITRE %s %s", when, a.Count, a.Technique.ID, a.Technique.Name)))
		fmt.Fprintf(w, "  %s\n", a.Detail)
		fmt.Fprintf(w, "  %s %s\n", p.c(cyan, "→"), a.Advice)
		if len(a.Evidence) > 0 {
			fmt.Fprintf(w, "  %s\n", p.c(dim, "preuve : "+shorten(a.Evidence[len(a.Evidence)-1], 140)))
		}
	}

	fmt.Fprintf(w, "\n%s\n", p.c(bold, "IP les plus dangereuses"))
	for i, at := range r.Attackers {
		if i == 5 {
			break
		}
		fmt.Fprintf(w, "  %-16s %s  %d alerte(s), %d événement(s)  %s\n",
			at.IP, p.c(sevColor(at.MaxSeverity), fmt.Sprintf("%-9s", at.MaxSeverity)), at.Alerts, at.Events,
			p.c(dim, strings.Join(dedupe(at.Rules), ", ")))
	}
	fmt.Fprintln(w)
}

func shorten(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range list {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
