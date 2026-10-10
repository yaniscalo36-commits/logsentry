package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Severity classe les alertes, de la simple information à l'incident avéré.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"", "faible", "moyenne", "haute", "critique"}[s]
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func ParseSeverity(s string) (Severity, bool) {
	for sev := Low; sev <= Critical; sev++ {
		if strings.EqualFold(s, sev.String()) {
			return sev, true
		}
	}
	return 0, false
}

// Technique MITRE ATT&CK associée à une alerte.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (t Technique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(t.ID, ".", "/") + "/"
}

var (
	tBruteForce = Technique{"T1110.001", "Brute Force: Password Guessing"}
	tBruteGen   = Technique{"T1110", "Brute Force"}
	tValidAcct  = Technique{"T1078", "Valid Accounts"}
	tExploitApp = Technique{"T1190", "Exploit Public-Facing Application"}
	tWordlist   = Technique{"T1595.003", "Active Scanning: Wordlist Scanning"}
	tScanning   = Technique{"T1595", "Active Scanning"}
)

type Alert struct {
	Rule      string    `json:"rule"`
	Title     string    `json:"title"`
	Severity  Severity  `json:"severity"`
	IP        string    `json:"ip"`
	Count     int       `json:"count"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Detail    string    `json:"detail"`
	Advice    string    `json:"advice"`
	Technique Technique `json:"mitre"`
	Evidence  []string  `json:"evidence"`
}

// Config regroupe les seuils de détection (modifiables en ligne de commande).
type Config struct {
	BruteForceThreshold int           // échecs SSH dans la fenêtre
	BruteForceWindow    time.Duration //
	EnumThreshold       int           // comptes différents essayés
	ScanThreshold       int           // réponses 404 dans la fenêtre
	ScanWindow          time.Duration //
}

var DefaultConfig = Config{
	BruteForceThreshold: 10,
	BruteForceWindow:    5 * time.Minute,
	EnumThreshold:       5,
	ScanThreshold:       30,
	ScanWindow:          5 * time.Minute,
}

// ---------- Règles web à base de motifs ----------

type webRule struct {
	id, title string
	severity  Severity
	technique Technique
	match     func(Event) bool
	detail    string
	advice    string
}

var (
	sqliRe = regexp.MustCompile(`(?i)(union(\s|/\*.*?\*/)+(all\s+)?select|'\s*(or|and)\s+'?\w+'?\s*=\s*'?\w+|\b(sleep|benchmark|pg_sleep)\s*\(|information_schema|;\s*(drop|delete|insert|update)\s|'\s*--|\border\s+by\s+\d+\s*--|\bwaitfor\s+delay\b)`)
	xssRe  = regexp.MustCompile(`(?i)(<\s*script|javascript:|\bon(error|load|mouseover|focus|click)\s*=|<\s*(svg|img|iframe)[^>]*\bon\w+|document\.cookie|alert\s*\()`)
	travRe = regexp.MustCompile(`(?i)(\.\./|\.\.\\|\.\.\.\.//|/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|c:\\windows)`)
	sensRe = regexp.MustCompile(`(?i)^/(\.env|\.git/|\.svn/|\.htaccess|\.htpasswd|\.ds_store|\.aws/|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|server-status|backup\.(sql|zip|tar\.gz)|dump\.sql|config\.php\.bak|id_rsa)`)
	toolRe = regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb/|ffuf|wfuzz|wpscan|nuclei|acunetix|nessus|openvas|hydra|feroxbuster)`)
)

var webRules = []webRule{
	{
		id: "WEB-SQLI", title: "Tentative d'injection SQL", severity: High, technique: tExploitApp,
		match:  func(e Event) bool { return sqliRe.MatchString(e.Path) },
		detail: "Requêtes contenant des fragments SQL (UNION SELECT, ' OR 1=1, SLEEP()…).",
		advice: "Vérifier que l'application utilise des requêtes paramétrées et regarder les réponses 500, signe possible d'une requête qui a cassé la base.",
	},
	{
		id: "WEB-XSS", title: "Tentative de XSS", severity: Medium, technique: tExploitApp,
		match:  func(e Event) bool { return xssRe.MatchString(e.Path) },
		detail: "Requêtes contenant du JavaScript (<script>, onerror=, document.cookie…).",
		advice: "Vérifier l'échappement des données affichées et mettre en place une Content-Security-Policy.",
	},
	{
		id: "WEB-TRAVERSAL", title: "Tentative de path traversal", severity: High, technique: tExploitApp,
		match:  func(e Event) bool { return travRe.MatchString(e.Path) },
		detail: "Requêtes cherchant à sortir du dossier web (../, /etc/passwd, win.ini…).",
		advice: "Ne jamais construire un chemin de fichier à partir d'un paramètre utilisateur sans liste blanche.",
	},
	{
		id: "WEB-SENSITIVE", title: "Recherche de fichiers sensibles", severity: Medium, technique: tWordlist,
		match:  func(e Event) bool { return sensRe.MatchString(e.Path) },
		detail: "Accès à des fichiers qui ne doivent jamais être publics (.env, .git, sauvegardes, clés…).",
		advice: "Vérifier qu'aucun de ces fichiers n'a été servi avec un code 200, et bloquer ces chemins au niveau du serveur web.",
	},
	{
		id: "WEB-TOOL", title: "Outil d'attaque identifié", severity: Medium, technique: tScanning,
		match:  func(e Event) bool { return toolRe.MatchString(e.UA) },
		detail: "Le User-Agent correspond à un outil d'audit ou d'attaque connu.",
		advice: "Si ce scan n'est pas autorisé, bloquer l'IP (pare-feu, fail2ban) et vérifier les autres alertes de cette IP.",
	},
}

// ---------- Moteur de détection ----------

// Detect applique toutes les règles et renvoie les alertes triées par gravité puis par date.
func Detect(events []Event, cfg Config) []Alert {
	var alerts []Alert
	alerts = append(alerts, detectSSH(events, cfg)...)
	alerts = append(alerts, detectWebPatterns(events)...)
	alerts = append(alerts, detectWebScan(events, cfg)...)

	sort.SliceStable(alerts, func(i, j int) bool {
		if alerts[i].Severity != alerts[j].Severity {
			return alerts[i].Severity > alerts[j].Severity
		}
		return alerts[i].First.Before(alerts[j].First)
	})
	return alerts
}

func evidence(evs []Event, max int) []string {
	var out []string
	for i, e := range evs {
		if i == max {
			break
		}
		out = append(out, e.Source+"  "+e.Raw)
	}
	return out
}

// maxInWindow renvoie le plus grand nombre d'événements tombant dans une même fenêtre glissante.
func maxInWindow(evs []Event, window time.Duration) int {
	best, start := 0, 0
	for end := range evs {
		for evs[end].Time.Sub(evs[start].Time) > window {
			start++
		}
		if n := end - start + 1; n > best {
			best = n
		}
	}
	return best
}

func detectSSH(events []Event, cfg Config) []Alert {
	failures := map[string][]Event{}
	invalidUsers := map[string]map[string]bool{}
	invalidEvents := map[string][]Event{}
	var alerts []Alert

	for _, e := range events {
		switch e.Kind {
		case SSHFailed:
			failures[e.IP] = append(failures[e.IP], e)
		case SSHInvalidUser:
			if invalidUsers[e.IP] == nil {
				invalidUsers[e.IP] = map[string]bool{}
			}
			invalidUsers[e.IP][e.User] = true
			invalidEvents[e.IP] = append(invalidEvents[e.IP], e)
		case SSHAccepted:
			// Connexion réussie depuis une IP qui vient de faire du brute-force : compte probablement compromis.
			prev := failures[e.IP]
			if len(prev) >= cfg.BruteForceThreshold && maxInWindow(prev, cfg.BruteForceWindow) >= cfg.BruteForceThreshold {
				alerts = append(alerts, Alert{
					Rule: "SSH-COMPROMISE", Title: "Connexion SSH réussie après un brute-force",
					Severity: Critical, IP: e.IP, Count: 1, First: e.Time, Last: e.Time,
					Detail: fmt.Sprintf("Le compte « %s » s'est connecté (%s) depuis %s après %d échecs depuis cette même IP. Le compte est très probablement compromis.",
						e.User, e.Method, e.IP, len(prev)),
					Advice:    fmt.Sprintf("Traiter comme un incident : couper la session, changer le mot de passe de « %s », vérifier ses actions (historique, crontab, clés SSH ajoutées) et désactiver l'authentification SSH par mot de passe.", e.User),
					Technique: tValidAcct,
					Evidence:  append(evidence(prev[max(0, len(prev)-2):], 2), e.Source+"  "+e.Raw),
				})
			}
		}
	}

	for ip, evs := range failures {
		peak := maxInWindow(evs, cfg.BruteForceWindow)
		if peak < cfg.BruteForceThreshold {
			continue
		}
		users := map[string]bool{}
		for _, e := range evs {
			users[e.User] = true
		}
		alerts = append(alerts, Alert{
			Rule: "SSH-BRUTEFORCE", Title: "Brute-force SSH",
			Severity: High, IP: ip, Count: len(evs), First: evs[0].Time, Last: evs[len(evs)-1].Time,
			Detail: fmt.Sprintf("%d échecs d'authentification sur %d compte(s), dont %d en moins de %s.",
				len(evs), len(users), peak, humanDuration(cfg.BruteForceWindow)),
			Advice:    "Bloquer l'IP (fail2ban), désactiver la connexion par mot de passe (PasswordAuthentication no) et interdire root (PermitRootLogin no).",
			Technique: tBruteForce,
			Evidence:  evidence(evs, 3),
		})
	}

	for ip, users := range invalidUsers {
		if len(users) < cfg.EnumThreshold {
			continue
		}
		names := make([]string, 0, len(users))
		for u := range users {
			names = append(names, u)
		}
		sort.Strings(names)
		evs := invalidEvents[ip]
		alerts = append(alerts, Alert{
			Rule: "SSH-ENUM", Title: "Essai de comptes inexistants",
			Severity: Medium, IP: ip, Count: len(evs), First: evs[0].Time, Last: evs[len(evs)-1].Time,
			Detail:    fmt.Sprintf("%d noms de comptes différents essayés : %s.", len(names), truncateList(names, 8)),
			Advice:    "Comportement typique d'un robot qui teste des comptes par défaut. Vérifier qu'aucun de ces comptes n'existe avec un mot de passe faible.",
			Technique: tBruteGen,
			Evidence:  evidence(evs, 3),
		})
	}
	return alerts
}

func detectWebPatterns(events []Event) []Alert {
	type key struct{ rule, ip string }
	hits := map[key][]Event{}
	var order []key
	for _, e := range events {
		if e.Kind != WebRequest {
			continue
		}
		for _, r := range webRules {
			if r.match(e) {
				k := key{r.id, e.IP}
				if hits[k] == nil {
					order = append(order, k)
				}
				hits[k] = append(hits[k], e)
			}
		}
	}

	var alerts []Alert
	for _, k := range order {
		evs := hits[k]
		var r webRule
		for _, wr := range webRules {
			if wr.id == k.rule {
				r = wr
			}
		}
		detail := fmt.Sprintf("%d requête(s). %s", len(evs), r.detail)
		if ok := countStatus(evs, 200); ok > 0 && r.id != "WEB-TOOL" {
			detail += fmt.Sprintf(" Attention : %d ont reçu une réponse 200.", ok)
		}
		alerts = append(alerts, Alert{
			Rule: r.id, Title: r.title, Severity: r.severity, IP: k.ip,
			Count: len(evs), First: evs[0].Time, Last: evs[len(evs)-1].Time,
			Detail: detail, Advice: r.advice, Technique: r.technique, Evidence: evidence(evs, 3),
		})
	}
	return alerts
}

func detectWebScan(events []Event, cfg Config) []Alert {
	notFound := map[string][]Event{}
	for _, e := range events {
		if e.Kind == WebRequest && e.Status == 404 {
			notFound[e.IP] = append(notFound[e.IP], e)
		}
	}
	var alerts []Alert
	for ip, evs := range notFound {
		peak := maxInWindow(evs, cfg.ScanWindow)
		if peak < cfg.ScanThreshold {
			continue
		}
		dur := humanDuration(evs[len(evs)-1].Time.Sub(evs[0].Time))
		alerts = append(alerts, Alert{
			Rule: "WEB-SCAN", Title: "Scan de répertoires",
			Severity: Medium, IP: ip, Count: len(evs), First: evs[0].Time, Last: evs[len(evs)-1].Time,
			Detail:    fmt.Sprintf("%d pages introuvables (404) demandées en %s : l'IP teste une liste de chemins.", len(evs), dur),
			Advice:    "Limiter le débit par IP (rate limiting) et vérifier qu'aucun chemin découvert n'expose une interface d'administration.",
			Technique: tWordlist,
			Evidence:  evidence(evs, 3),
		})
	}
	return alerts
}

// humanDuration affiche une durée lisible : « 56 s », « 5 min », « 1 h 20 min ».
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		if s := int(d.Seconds()) % 60; s != 0 {
			return fmt.Sprintf("%d min %d s", int(d.Minutes()), s)
		}
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
}

func countStatus(evs []Event, status int) int {
	n := 0
	for _, e := range evs {
		if e.Status == status {
			n++
		}
	}
	return n
}

func truncateList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf("… (+%d)", len(items)-max)
}
