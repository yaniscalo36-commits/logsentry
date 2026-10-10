package main

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

//go:embed templates/dashboard.html
var templateFS embed.FS

var dashboardTmpl = template.Must(template.New("dashboard.html").Funcs(template.FuncMap{
	"sevClass": func(s Severity) string {
		return map[Severity]string{Low: "low", Medium: "medium", High: "high", Critical: "critical"}[s]
	},
	"fmtTime":  func(t time.Time) string { return t.Format("02/01/2006 15:04:05") },
	"fmtHour":  func(t time.Time) string { return t.Format("15:04:05") },
	"same":     func(a, b time.Time) bool { return a.Equal(b) },
	"join":     strings.Join,
	"dedupe":   dedupe,
	"now":      func() string { return time.Now().Format("02/01/2006 15:04") },
	"timeline": timelineSVG,
	"sev": func(name string) Severity {
		s, _ := ParseSeverity(name)
		return s
	},
}).ParseFS(templateFS, "templates/dashboard.html"))

// writeHTML génère un tableau de bord HTML autonome (un seul fichier, sans JavaScript).
func writeHTML(path string, r *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return dashboardTmpl.Execute(f, r)
}

// timelineSVG dessine un histogramme horaire : trafic total en gris, trafic des IP malveillantes en rouge.
// Le SVG ne contient que des nombres et des heures formatées par le programme, jamais de données des logs.
func timelineSVG(buckets []Bucket) template.HTML {
	if len(buckets) == 0 {
		return ""
	}
	const w, h, pad, labelH = 860.0, 180.0, 4.0, 22.0
	max := 1
	for _, b := range buckets {
		if b.Total > max {
			max = b.Total
		}
	}
	barW := w / float64(len(buckets))
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg viewBox="0 0 %.0f %.0f" class="timeline" role="img" aria-label="Événements par heure">`, w, h+labelH)
	for i, b := range buckets {
		x := float64(i)*barW + pad/2
		bw := barW - pad
		th := float64(b.Total) / float64(max) * h
		mh := float64(b.Malicious) / float64(max) * h
		if b.Malicious > 0 && mh < 3 {
			mh = 3
		}
		fmt.Fprintf(&sb, `<rect class="t-total" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3"><title>%s : %d événements</title></rect>`,
			x, h-th, bw, th, b.Hour.Format("15h"), b.Total)
		if b.Malicious > 0 {
			fmt.Fprintf(&sb, `<rect class="t-bad" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3"><title>%s : %d événements malveillants</title></rect>`,
				x, h-mh, bw, mh, b.Hour.Format("15h"), b.Malicious)
		}
		if len(buckets) <= 24 || i%2 == 0 {
			fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" text-anchor="middle">%s</text>`, x+bw/2, h+16, b.Hour.Format("15h"))
		}
	}
	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}
