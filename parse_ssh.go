package main

import (
	"regexp"
	"strings"
	"time"
)

// En-tête syslog classique (« Oct  9 14:02:11 serveur sshd[123]: ») ou ISO 8601
// (« 2026-10-09T14:02:11.123+02:00 serveur sshd[123]: »), utilisé par les distributions récentes.
var (
	syslogPrefix = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(.*)$`)
	isoPrefix    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+sshd(?:\[\d+\])?:\s+(.*)$`)

	sshFailedRe   = regexp.MustCompile(`^Failed (?:password|publickey|keyboard-interactive/pam) for (invalid user )?(\S*) from (\S+) port \d+`)
	sshInvalidRe  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	sshAcceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
)

func parseSSH(line string, ref time.Time) (Event, bool) {
	var ts time.Time
	var msg string
	if m := syslogPrefix.FindStringSubmatch(line); m != nil {
		ts = parseSyslogTime(m[1], ref)
		msg = m[2]
	} else if m := isoPrefix.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			return Event{}, false
		}
		ts, msg = t, m[2]
	} else {
		return Event{}, false
	}
	if ts.IsZero() {
		return Event{}, false
	}

	switch {
	case strings.HasPrefix(msg, "Failed "):
		if m := sshFailedRe.FindStringSubmatch(msg); m != nil {
			return Event{Time: ts, Kind: SSHFailed, User: m[2], IP: m[3]}, true
		}
	case strings.HasPrefix(msg, "Invalid user "):
		if m := sshInvalidRe.FindStringSubmatch(msg); m != nil {
			return Event{Time: ts, Kind: SSHInvalidUser, User: m[1], IP: m[2]}, true
		}
	case strings.HasPrefix(msg, "Accepted "):
		if m := sshAcceptedRe.FindStringSubmatch(msg); m != nil {
			return Event{Time: ts, Kind: SSHAccepted, User: m[2], IP: m[3], Method: m[1]}, true
		}
	}
	return Event{}, false
}

// parseSyslogTime gère l'absence d'année dans le format syslog : on prend l'année
// de référence, et l'année précédente si la date tombe dans le futur.
func parseSyslogTime(s string, ref time.Time) time.Time {
	t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(s), " "), ref.Location())
	if err != nil {
		t, err = time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(s), " "), ref.Location())
		if err != nil {
			return time.Time{}
		}
	}
	t = t.AddDate(ref.Year(), 0, 0)
	if t.After(ref.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}
