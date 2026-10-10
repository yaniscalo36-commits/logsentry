//go:build !(js && wasm)

// logsentry est un mini SIEM : il analyse des logs SSH et web pour détecter des attaques.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func main() {
	cfg := DefaultConfig
	asJSON := flag.Bool("json", false, "afficher le résultat en JSON")
	htmlOut := flag.String("html", "", "écrire un tableau de bord HTML dans ce fichier")
	minSev := flag.String("min-severity", "faible", "n'afficher que les alertes à partir de cette sévérité (faible, moyenne, haute, critique)")
	failOn := flag.String("fail-on", "", "code de sortie 2 si une alerte atteint cette sévérité (pour cron / CI)")
	noColor := flag.Bool("no-color", false, "désactiver les couleurs")
	flag.IntVar(&cfg.BruteForceThreshold, "bf-threshold", cfg.BruteForceThreshold, "nombre d'échecs SSH pour déclarer un brute-force")
	flag.DurationVar(&cfg.BruteForceWindow, "bf-window", cfg.BruteForceWindow, "fenêtre de temps du brute-force")
	flag.IntVar(&cfg.ScanThreshold, "scan-threshold", cfg.ScanThreshold, "nombre de 404 pour déclarer un scan")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage : logsentry [options] <fichier de log>...

Détecte les attaques dans des logs SSH (auth.log) et web (access.log Nginx / Apache).

Exemples :
  logsentry /var/log/auth.log /var/log/nginx/access.log
  logsentry -html rapport.html testdata/*.log
  logsentry -fail-on haute -json /var/log/auth.log

Options :
`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	min, ok := ParseSeverity(*minSev)
	if !ok {
		fatal("-min-severity doit valoir faible, moyenne, haute ou critique")
	}
	var fail Severity
	if *failOn != "" {
		if fail, ok = ParseSeverity(*failOn); !ok {
			fatal("-fail-on doit valoir faible, moyenne, haute ou critique")
		}
	}
	if cfg.BruteForceThreshold < 2 || cfg.ScanThreshold < 2 {
		fatal("les seuils doivent être d'au moins 2")
	}

	events, st, err := ReadLogs(flag.Args(), time.Now())
	if err != nil {
		fatal(err.Error())
	}
	r := Analyze(events, st, cfg)

	shown := r.Alerts[:0:0]
	for _, a := range r.Alerts {
		if a.Severity >= min {
			shown = append(shown, a)
		}
	}

	if *asJSON {
		out := *r
		out.Alerts = shown
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	} else {
		printText(os.Stdout, r, shown, !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout))
	}

	if *htmlOut != "" {
		if err := writeHTML(*htmlOut, r); err != nil {
			fatal("rapport HTML : " + err.Error())
		}
		fmt.Fprintf(os.Stderr, "Tableau de bord écrit dans %s\n", *htmlOut)
	}

	if fail > 0 {
		for _, a := range r.Alerts {
			if a.Severity >= fail {
				os.Exit(2)
			}
		}
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "Erreur :", msg)
	os.Exit(1)
}
