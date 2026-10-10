package main

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 9, 14, 0, 0, 0, time.UTC)

func ssh(kind Kind, ip, user string, sec int) Event {
	return Event{Time: t0.Add(time.Duration(sec) * time.Second), Kind: kind, IP: ip, User: user, Method: "password"}
}

func web(ip, path string, status int, ua string, sec int) Event {
	return Event{Time: t0.Add(time.Duration(sec) * time.Second), Kind: WebRequest, IP: ip, Method: "GET", Path: path, Status: status, UA: ua}
}

func rules(alerts []Alert) map[string]Alert {
	m := map[string]Alert{}
	for _, a := range alerts {
		m[a.Rule+"|"+a.IP] = a
	}
	return m
}

func TestBruteForceThenCompromise(t *testing.T) {
	var evs []Event
	for i := 0; i < 12; i++ {
		evs = append(evs, ssh(SSHFailed, "203.0.113.45", "root", i*5))
	}
	evs = append(evs, ssh(SSHAccepted, "203.0.113.45", "deploy", 100))

	got := rules(Detect(evs, DefaultConfig))
	bf, ok := got["SSH-BRUTEFORCE|203.0.113.45"]
	if !ok || bf.Count != 12 || bf.Severity != High {
		t.Fatalf("brute-force non détecté : %+v", got)
	}
	c, ok := got["SSH-COMPROMISE|203.0.113.45"]
	if !ok || c.Severity != Critical || c.Technique.ID != "T1078" {
		t.Fatalf("compromission non détectée : %+v", got)
	}
}

func TestSlowFailuresAreNotBruteForce(t *testing.T) {
	// 12 échecs étalés sur 2 heures : jamais 10 dans une fenêtre de 5 minutes.
	var evs []Event
	for i := 0; i < 12; i++ {
		evs = append(evs, ssh(SSHFailed, "198.51.100.23", "marie", i*600))
	}
	evs = append(evs, ssh(SSHAccepted, "198.51.100.23", "marie", 8000))
	if a := Detect(evs, DefaultConfig); len(a) != 0 {
		t.Fatalf("faux positif : %+v", a)
	}
}

func TestUserEnumeration(t *testing.T) {
	var evs []Event
	for i, u := range []string{"admin", "test", "oracle", "pi", "guest"} {
		evs = append(evs, ssh(SSHInvalidUser, "203.0.113.7", u, i))
	}
	if _, ok := rules(Detect(evs, DefaultConfig))["SSH-ENUM|203.0.113.7"]; !ok {
		t.Fatal("énumération non détectée")
	}
}

func TestWebPayloads(t *testing.T) {
	cases := []struct {
		path, ua, rule string
	}{
		{"/produits?id=1 UNION ALL SELECT NULL,NULL--", "", "WEB-SQLI"},
		{"/produits?id=1' OR '1'='1", "", "WEB-SQLI"},
		{"/produits?id=1' AND SLEEP(5)-- -", "", "WEB-SQLI"},
		{"/q?s=<script>alert(1)</script>", "", "WEB-XSS"},
		{"/q?s=<img src=x onerror=alert(1)>", "", "WEB-XSS"},
		{"/dl?f=../../../etc/passwd", "", "WEB-TRAVERSAL"},
		{"/.env", "", "WEB-SENSITIVE"},
		{"/.git/config", "", "WEB-SENSITIVE"},
		{"/", "sqlmap/1.8", "WEB-TOOL"},
		{"/", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "WEB-TOOL"},
	}
	for _, c := range cases {
		got := rules(Detect([]Event{web("192.0.2.200", c.path, 400, c.ua, 0)}, DefaultConfig))
		if _, ok := got[c.rule+"|192.0.2.200"]; !ok {
			t.Errorf("%s non détecté pour %q (alertes : %v)", c.rule, c.path, keys(got))
		}
	}
}

func TestLegitimateTrafficIsQuiet(t *testing.T) {
	var evs []Event
	paths := []string{"/", "/blog/union-europeenne-et-select-committee", "/recherche?q=rock+and+roll", "/images/logo.png", "/contact?nom=O'Neil"}
	for i := 0; i < 200; i++ {
		evs = append(evs, web(fmt.Sprintf("192.0.2.%d", i%50), paths[i%len(paths)], 200, "Mozilla/5.0", i*30))
	}
	if a := Detect(evs, DefaultConfig); len(a) != 0 {
		t.Fatalf("faux positifs sur du trafic normal : %+v", a)
	}
}

func TestDirectoryScan(t *testing.T) {
	var evs []Event
	for i := 0; i < 40; i++ {
		evs = append(evs, web("198.51.100.77", fmt.Sprintf("/test%d", i), 404, "curl/8", i))
	}
	if _, ok := rules(Detect(evs, DefaultConfig))["WEB-SCAN|198.51.100.77"]; !ok {
		t.Fatal("scan non détecté")
	}
}

func TestDemoScenario(t *testing.T) {
	evs, st, err := ReadLogs([]string{"testdata/auth.log", "testdata/access.log"}, ref)
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(evs, st, DefaultConfig)
	got := rules(r.Alerts)
	for _, want := range []string{
		"SSH-COMPROMISE|203.0.113.45", "SSH-BRUTEFORCE|203.0.113.45", "SSH-ENUM|203.0.113.45",
		"WEB-SCAN|198.51.100.77", "WEB-TOOL|198.51.100.77", "WEB-SENSITIVE|198.51.100.77",
		"WEB-SQLI|203.0.113.99", "WEB-TOOL|203.0.113.99",
		"WEB-XSS|192.0.2.200", "WEB-TRAVERSAL|192.0.2.200",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("alerte attendue absente : %s", want)
		}
	}
	// Marie (3 échecs puis succès) et le trafic normal ne doivent rien déclencher.
	for _, a := range r.Alerts {
		if a.IP == "198.51.100.23" || a.IP == "192.0.2.10" {
			t.Errorf("faux positif : %s sur %s", a.Rule, a.IP)
		}
	}
	if r.Attackers[0].IP != "203.0.113.45" {
		t.Errorf("l'attaquant le plus grave devrait être 203.0.113.45, obtenu %s", r.Attackers[0].IP)
	}
}

func keys(m map[string]Alert) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
