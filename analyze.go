package main

import (
	"sort"
	"time"
)

// Attacker résume l'activité malveillante d'une IP.
type Attacker struct {
	IP          string   `json:"ip"`
	MaxSeverity Severity `json:"maxSeverity"`
	Alerts      int      `json:"alerts"`
	Events      int      `json:"events"`
	Rules       []string `json:"rules"`
}

// Bucket compte les événements d'une heure donnée.
type Bucket struct {
	Hour      time.Time `json:"hour"`
	Total     int       `json:"total"`
	Malicious int       `json:"malicious"`
}

type Report struct {
	Stats     Stats      `json:"stats"`
	Alerts    []Alert    `json:"alerts"`
	Attackers []Attacker `json:"attackers"`
	Timeline  []Bucket   `json:"timeline"`
	BySev     [5]int     `json:"-"`
}

func (r *Report) Count(s Severity) int { return r.BySev[s] }

// Analyze lance la détection et prépare les vues agrégées du rapport.
func Analyze(events []Event, st Stats, cfg Config) *Report {
	r := &Report{Stats: st, Alerts: Detect(events, cfg)}

	byIP := map[string]*Attacker{}
	for _, a := range r.Alerts {
		r.BySev[a.Severity]++
		at := byIP[a.IP]
		if at == nil {
			at = &Attacker{IP: a.IP}
			byIP[a.IP] = at
		}
		at.Alerts++
		at.Events += a.Count
		at.Rules = append(at.Rules, a.Rule)
		if a.Severity > at.MaxSeverity {
			at.MaxSeverity = a.Severity
		}
	}
	for _, at := range byIP {
		r.Attackers = append(r.Attackers, *at)
	}
	sort.Slice(r.Attackers, func(i, j int) bool {
		a, b := r.Attackers[i], r.Attackers[j]
		if a.MaxSeverity != b.MaxSeverity {
			return a.MaxSeverity > b.MaxSeverity
		}
		return a.Events > b.Events
	})

	r.Timeline = timeline(events, byIP)
	return r
}

// timeline regroupe les événements par heure. Un événement est « malveillant »
// s'il provient d'une IP ayant déclenché au moins une alerte.
func timeline(events []Event, attackers map[string]*Attacker) []Bucket {
	if len(events) == 0 {
		return nil
	}
	start := events[0].Time.Truncate(time.Hour)
	end := events[len(events)-1].Time.Truncate(time.Hour)
	n := int(end.Sub(start)/time.Hour) + 1
	if n > 24*31 { // garde-fou : au-delà d'un mois, on regroupe par jour
		return nil
	}
	buckets := make([]Bucket, n)
	for i := range buckets {
		buckets[i].Hour = start.Add(time.Duration(i) * time.Hour)
	}
	for _, e := range events {
		i := int(e.Time.Truncate(time.Hour).Sub(start) / time.Hour)
		buckets[i].Total++
		if attackers[e.IP] != nil {
			buckets[i].Malicious++
		}
	}
	return buckets
}
