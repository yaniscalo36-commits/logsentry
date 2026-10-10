package main

import (
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// Format « combined » de Nginx et Apache :
// 203.0.113.9 - - [09/Oct/2026:14:03:12 +0200] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
var webRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?`)

func parseWeb(line string, _ time.Time) (Event, bool) {
	m := webRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return Event{}, false
	}
	status, _ := strconv.Atoi(m[5])
	return Event{
		Time:   ts,
		Kind:   WebRequest,
		IP:     m[1],
		Method: m[3],
		Path:   decodePath(m[4]),
		Status: status,
		UA:     m[6],
	}, true
}

// decodePath décode l'URL jusqu'à deux fois : les attaquants encodent souvent
// deux fois (%2527 → %27 → ') pour échapper aux filtres naïfs.
func decodePath(p string) string {
	for i := 0; i < 2; i++ {
		d, err := url.QueryUnescape(p)
		if err != nil || d == p {
			break
		}
		p = d
	}
	return p
}
