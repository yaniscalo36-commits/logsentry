//go:build ignore

// Génère des logs de démonstration réalistes : go run testdata/generate.go
//
// Les adresses IP utilisées sont réservées à la documentation (RFC 5737) :
// 192.0.2.0/24, 198.51.100.0/24 et 203.0.113.0/24. Elles n'appartiennent à personne.
//
// Scénario du 9 octobre 2026 :
//   - trafic légitime toute la journée (SSH par clé, visites web) ;
//   - 14h02 : brute-force SSH depuis 203.0.113.45, puis connexion RÉUSSIE sur « deploy » ;
//   - 198.51.100.23 rate 3 connexions : pas assez pour être suspect (test des faux positifs) ;
//   - 15h10 : scan de répertoires avec gobuster depuis 198.51.100.77 ;
//   - 16h20 : injection SQL avec sqlmap depuis 203.0.113.99 ;
//   - 17h05 : XSS et path traversal depuis 192.0.2.200.
package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	loc  = time.FixedZone("CEST", 2*3600)
	day  = time.Date(2026, 10, 9, 0, 0, 0, 0, loc)
	rng  = rand.New(rand.NewSource(42))
	pid  = 2000
	auth []line
	web  []line
)

type line struct {
	t time.Time
	s string
}

func at(h, m, s int) time.Time {
	return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second)
}

func sshd(t time.Time, msg string) {
	pid++
	auth = append(auth, line{t, fmt.Sprintf("%s web-01 sshd[%d]: %s", t.Format("Jan _2 15:04:05"), pid, msg)})
}

func access(t time.Time, ip, method, path string, status, size int, ua string) {
	web = append(web, line{t, fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`,
		ip, t.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, size, ua)})
}

const browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"

func main() {
	// ---------- Trafic légitime ----------
	for _, h := range []int{8, 9, 12, 13, 17, 18} {
		t := at(h, rng.Intn(60), rng.Intn(60))
		sshd(t, "Accepted publickey for admin from 192.0.2.10 port 52044 ssh2: ED25519 SHA256:k3yF1ng3rpr1nt")
	}
	pages := []string{"/", "/blog", "/blog/securiser-ssh", "/contact", "/static/style.css", "/static/app.js", "/images/logo.png", "/a-propos"}
	for i := 0; i < 900; i++ {
		t := at(7, 0, 0).Add(time.Duration(rng.Intn(15*3600)) * time.Second)
		ip := fmt.Sprintf("192.0.2.%d", 20+rng.Intn(150))
		access(t, ip, "GET", pages[rng.Intn(len(pages))], 200, 500+rng.Intn(20000), browser)
	}
	for i := 0; i < 25; i++ { // quelques 404 normaux (liens cassés)
		t := at(7, 0, 0).Add(time.Duration(rng.Intn(15*3600)) * time.Second)
		access(t, fmt.Sprintf("192.0.2.%d", 20+rng.Intn(150)), "GET", "/ancien-article", 404, 150, browser)
	}

	// ---------- Utilisateur qui se trompe de mot de passe (ne doit PAS alerter) ----------
	for i := 0; i < 3; i++ {
		sshd(at(10, 15, i*40), "Failed password for marie from 198.51.100.23 port 41022 ssh2")
	}
	sshd(at(10, 17, 30), "Accepted password for marie from 198.51.100.23 port 41030 ssh2")

	// ---------- Brute-force SSH puis compromission ----------
	attacker := "203.0.113.45"
	users := []string{"root", "admin", "test", "oracle", "ubuntu", "pi", "guest", "postgres", "user", "ftp"}
	t := at(14, 2, 0)
	for i := 0; i < 80; i++ {
		u := users[i%len(users)]
		port := 40000 + rng.Intn(20000)
		if u != "root" && u != "admin" {
			sshd(t, fmt.Sprintf("Invalid user %s from %s port %d", u, attacker, port))
			sshd(t, fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2", u, attacker, port))
		} else {
			sshd(t, fmt.Sprintf("Failed password for %s from %s port %d ssh2", u, attacker, port))
		}
		t = t.Add(time.Duration(1+rng.Intn(3)) * time.Second)
	}
	for i := 0; i < 6; i++ {
		sshd(t, fmt.Sprintf("Failed password for deploy from %s port %d ssh2", attacker, 40000+rng.Intn(20000)))
		t = t.Add(2 * time.Second)
	}
	sshd(t.Add(3*time.Second), fmt.Sprintf("Accepted password for deploy from %s port 58122 ssh2", attacker))

	// ---------- Scan de répertoires (gobuster) ----------
	words := []string{"admin", "backup", "old", "test", "dev", "api", "login", "dashboard", "uploads", "tmp", "private", "config", "db", "panel", "cgi-bin", "includes", "logs", "data", "secret", "staging"}
	t = at(15, 10, 0)
	for i := 0; i < 160; i++ {
		access(t, "198.51.100.77", "GET", "/"+words[i%len(words)]+fmt.Sprint(i/len(words)), 404, 153, "gobuster/3.6")
		t = t.Add(time.Duration(200+rng.Intn(300)) * time.Millisecond)
	}
	for _, p := range []string{"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql", "/.aws/credentials", "/server-status"} {
		access(t, "198.51.100.77", "GET", p, 404, 153, "gobuster/3.6")
		t = t.Add(300 * time.Millisecond)
	}

	// ---------- Injection SQL (sqlmap) ----------
	t = at(16, 20, 0)
	for _, q := range []string{
		"1%27", "1%27%20AND%201%3D1--%20-", "1%27%20OR%20%271%27%3D%271", "1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--%20-",
		"1%27%20AND%20SLEEP(5)--%20-", "1%20ORDER%20BY%2010--%20-", "-1%20UNION%20SELECT%20table_name%2C2%20FROM%20information_schema.tables--%20-",
		"1%2527%2520OR%25201%253D1--",
	} {
		access(t, "203.0.113.99", "GET", "/produits?id="+q, 500, 312, "sqlmap/1.8.4#stable (https://sqlmap.org)")
		t = t.Add(time.Duration(1+rng.Intn(4)) * time.Second)
	}

	// ---------- XSS et path traversal ----------
	t = at(17, 5, 0)
	for _, p := range []string{
		"/recherche?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
		"/recherche?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
		"/contact?nom=%3Csvg%20onload%3Dalert(1)%3E",
		"/telecharger?fichier=..%2F..%2F..%2Fetc%2Fpasswd",
		"/telecharger?fichier=....%2F%2F....%2F%2Fetc%2Fshadow",
		"/static/..%252f..%252f..%252fwindows%252fwin.ini",
	} {
		access(t, "192.0.2.200", "GET", p, 400, 0, "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
		t = t.Add(time.Duration(5+rng.Intn(20)) * time.Second)
	}

	write("testdata/auth.log", auth)
	write("testdata/access.log", web)
}

func write(path string, lines []line) {
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].t.Before(lines[j].t) })
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l.s + "\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%s : %d lignes\n", path, len(lines))
}
