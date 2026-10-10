package main

import (
	"strings"
	"testing"
	"time"
)

var ref = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func TestParseSSHFailed(t *testing.T) {
	ev, ok := parseSSH("Oct  9 14:02:11 srv sshd[1234]: Failed password for invalid user oracle from 203.0.113.45 port 51234 ssh2", ref)
	if !ok || ev.Kind != SSHFailed || ev.User != "oracle" || ev.IP != "203.0.113.45" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	if ev.Time.Year() != 2026 || ev.Time.Day() != 9 || ev.Time.Hour() != 14 {
		t.Fatalf("date incorrecte : %v", ev.Time)
	}
}

func TestParseSSHAcceptedISO(t *testing.T) {
	ev, ok := parseSSH("2026-10-09T14:05:00.123456+02:00 srv sshd[99]: Accepted password for deploy from 203.0.113.45 port 40000 ssh2", ref)
	if !ok || ev.Kind != SSHAccepted || ev.User != "deploy" || ev.Method != "password" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
}

func TestParseSSHInvalidUser(t *testing.T) {
	ev, ok := parseSSH("Oct 9 14:02:10 srv sshd[1234]: Invalid user admin from 203.0.113.45 port 51234", ref)
	if !ok || ev.Kind != SSHInvalidUser || ev.User != "admin" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
}

func TestSyslogYearRollover(t *testing.T) {
	// Une ligne « Dec 31 » lue le 10 janvier appartient à l'année précédente.
	jan := time.Date(2027, 1, 10, 0, 0, 0, 0, time.UTC)
	ev, ok := parseSSH("Dec 31 23:59:59 srv sshd[1]: Invalid user x from 192.0.2.1", jan)
	if !ok || ev.Time.Year() != 2026 {
		t.Fatalf("année %d, attendu 2026", ev.Time.Year())
	}
}

func TestParseSSHIgnoresOtherLines(t *testing.T) {
	for _, l := range []string{
		"Oct  9 14:02:11 srv CRON[1]: pam_unix(cron:session): session opened",
		"Oct  9 14:02:11 srv sshd[1]: Connection closed by 192.0.2.1 port 22",
		"n'importe quoi",
	} {
		if _, ok := parseSSH(l, ref); ok {
			t.Errorf("ligne acceptée à tort : %s", l)
		}
	}
}

func TestParseWeb(t *testing.T) {
	ev, ok := parseWeb(`198.51.100.7 - - [09/Oct/2026:14:03:12 +0200] "GET /search?q=%2527%20OR%201%3D1-- HTTP/1.1" 200 512 "-" "sqlmap/1.8"`, ref)
	if !ok || ev.Kind != WebRequest || ev.Status != 200 || ev.UA != "sqlmap/1.8" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	if !strings.Contains(ev.Path, "' OR 1=1--") {
		t.Fatalf("double encodage non décodé : %q", ev.Path)
	}
}

func TestReadLogsSortsAndCounts(t *testing.T) {
	evs, st, err := ReadLogs([]string{"testdata/auth.log", "testdata/access.log"}, ref)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events == 0 || st.Events != len(evs) || st.Lines < st.Events {
		t.Fatalf("stats incohérentes : %+v", st)
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].Time.Before(evs[i-1].Time) {
			t.Fatal("événements non triés")
		}
	}
}
