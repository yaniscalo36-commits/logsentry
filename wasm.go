//go:build js && wasm

// Point d'entrée WebAssembly : logsentry tourne directement dans le navigateur.
// Les logs sont analysés sur la machine du visiteur et ne sont jamais envoyés à un serveur.
//
// Compilation : GOOS=js GOARCH=wasm go build -o web/logsentry.wasm .
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"syscall/js"
	"time"
)

const maxInputBytes = 50 << 20 // 50 Mo au total

func main() {
	js.Global().Set("logsentryAnalyze", js.FuncOf(analyzeJS))
	js.Global().Call("dispatchEvent", js.Global().Get("Event").New("logsentry-ready"))
	select {} // garde le programme Go en vie pour répondre aux appels JavaScript
}

// analyzeJS attend un tableau [{name, text}, ...] et renvoie {html, json, summary} ou {error}.
func analyzeJS(_ js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return fail("argument invalide")
	}
	files := args[0]
	var sources []Source
	total := 0
	for i := 0; i < files.Length(); i++ {
		f := files.Index(i)
		text := f.Get("text").String()
		total += len(text)
		if total > maxInputBytes {
			return fail("fichiers trop volumineux (50 Mo maximum au total)")
		}
		sources = append(sources, Source{Name: f.Get("name").String(), Reader: strings.NewReader(text)})
	}

	events, st, err := ReadSources(sources, time.Now())
	if err != nil {
		return fail(err.Error())
	}
	r := Analyze(events, st, DefaultConfig)

	var html bytes.Buffer
	if err := dashboardTmpl.Execute(&html, r); err != nil {
		return fail(err.Error())
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fail(err.Error())
	}

	return map[string]any{
		"html": html.String(),
		"json": string(raw),
		"summary": map[string]any{
			"lines":    st.Lines,
			"events":   st.Events,
			"alerts":   len(r.Alerts),
			"critical": r.Count(Critical),
			"high":     r.Count(High),
			"medium":   r.Count(Medium),
			"low":      r.Count(Low),
		},
	}
}

func fail(msg string) any {
	return map[string]any{"error": msg}
}
