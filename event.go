package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// Kind est le type d'événement extrait d'une ligne de log.
type Kind int

const (
	SSHFailed      Kind = iota // échec d'authentification SSH
	SSHInvalidUser             // tentative sur un compte inexistant
	SSHAccepted                // connexion SSH réussie
	WebRequest                 // requête HTTP (access.log)
)

// Event est une ligne de log normalisée, quel que soit son format d'origine.
type Event struct {
	Time   time.Time
	Kind   Kind
	IP     string
	User   string // SSH
	Method string // web
	Path   string // web (déjà décodé)
	Status int    // web
	UA     string // web
	Source string // fichier:ligne
	Raw    string
}

// Parser transforme une ligne en événement. ok=false si la ligne ne le concerne pas.
type Parser func(line string, ref time.Time) (Event, bool)

var parsers = []Parser{parseSSH, parseWeb}

// Stats résume la lecture des fichiers.
type Stats struct {
	Files   []string
	Lines   int
	Events  int
	Ignored int
	First   time.Time
	Last    time.Time
}

// Source est un flux de log nommé : un fichier sur disque, ou un texte fourni par le navigateur.
type Source struct {
	Name   string
	Reader io.Reader
}

// ReadLogs lit tous les fichiers et renvoie les événements triés par date.
func ReadLogs(paths []string, ref time.Time) ([]Event, Stats, error) {
	var sources []Source
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, Stats{Files: paths}, err
		}
		defer f.Close()
		sources = append(sources, Source{Name: p, Reader: f})
	}
	return ReadSources(sources, ref)
}

// ReadSources analyse des flux de logs et renvoie les événements triés par date.
func ReadSources(sources []Source, ref time.Time) ([]Event, Stats, error) {
	var events []Event
	var st Stats
	for _, s := range sources {
		st.Files = append(st.Files, s.Name)
		evs, lines, err := parseStream(s.Reader, s.Name, ref)
		if err != nil {
			return nil, st, fmt.Errorf("%s : %w", s.Name, err)
		}
		st.Lines += lines
		events = append(events, evs...)
	}

	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	st.Events = len(events)
	st.Ignored = st.Lines - st.Events
	if len(events) > 0 {
		st.First, st.Last = events[0].Time, events[len(events)-1].Time
	}
	return events, st, nil
}

func parseStream(r io.Reader, name string, ref time.Time) ([]Event, int, error) {
	var events []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		for _, p := range parsers {
			if ev, ok := p(line, ref); ok {
				ev.Source = fmt.Sprintf("%s:%d", name, n)
				ev.Raw = line
				events = append(events, ev)
				break
			}
		}
	}
	return events, n, sc.Err()
}
