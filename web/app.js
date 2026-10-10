// Interface de la démo en direct : charge le moteur Go (WebAssembly) et lui passe les logs.
// Rien n'est envoyé sur le réseau : les fichiers sont lus localement avec l'API File.

const MAX_BYTES = 50 * 1024 * 1024;

const $ = id => document.getElementById(id);
const els = {
  drop: $("drop"), input: $("file-input"), files: $("files"), paste: $("paste"),
  analyze: $("analyze"), sample: $("sample"), status: $("status"),
  results: $("results"), summary: $("summary"), report: $("report"),
  dlHtml: $("dl-html"), dlJson: $("dl-json"),
};

let selected = [];   // [{name, size, file?, text?}]
let ready = false;
let urls = [];

// ---------- Chargement du moteur ----------

window.addEventListener("logsentry-ready", () => {
  ready = true;
  els.sample.disabled = false;
  setStatus("Prêt. Choisissez des fichiers ou essayez la démo.");
  refresh();
}, { once: true });

(async () => {
  try {
    const go = new Go();
    const res = fetch("logsentry.wasm");
    let instance;
    try {
      ({ instance } = await WebAssembly.instantiateStreaming(res, go.importObject));
    } catch {
      // Si le serveur ne renvoie pas le bon type MIME, on retombe sur un chargement classique.
      const buf = await (await fetch("logsentry.wasm")).arrayBuffer();
      ({ instance } = await WebAssembly.instantiate(buf, go.importObject));
    }
    go.run(instance);
  } catch (err) {
    setStatus("Impossible de charger le moteur d'analyse : " + err.message, true);
  }
})();

// ---------- Sélection des fichiers ----------

function addFiles(list) {
  for (const f of list) {
    if (!selected.some(s => s.name === f.name && s.size === f.size)) {
      selected.push({ name: f.name, size: f.size, file: f });
    }
  }
  refresh();
}

els.input.addEventListener("change", () => {
  addFiles(els.input.files);
  els.input.value = "";
});

["dragenter", "dragover"].forEach(t => els.drop.addEventListener(t, e => {
  e.preventDefault();
  els.drop.classList.add("over");
}));
["dragleave", "drop"].forEach(t => els.drop.addEventListener(t, e => {
  e.preventDefault();
  els.drop.classList.remove("over");
}));
els.drop.addEventListener("drop", e => addFiles(e.dataTransfer.files));

els.paste.addEventListener("input", refresh);

function totalSize() {
  return selected.reduce((n, s) => n + s.size, 0) + els.paste.value.length;
}

function refresh() {
  els.files.replaceChildren(...selected.map((s, i) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = s.name;
    const size = document.createElement("span");
    size.className = "size";
    size.textContent = formatSize(s.size);
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "✕";
    rm.setAttribute("aria-label", "Retirer " + s.name);
    rm.addEventListener("click", () => { selected.splice(i, 1); refresh(); });
    li.append(name, size, rm);
    return li;
  }));
  const hasInput = selected.length > 0 || els.paste.value.trim() !== "";
  els.analyze.disabled = !ready || !hasInput;
}

// ---------- Analyse ----------

els.analyze.addEventListener("click", run);

els.sample.addEventListener("click", async () => {
  setStatus("Chargement des logs de démo…");
  try {
    const names = ["auth.log", "access.log"];
    const texts = await Promise.all(names.map(n => fetch("samples/" + n).then(r => {
      if (!r.ok) throw new Error(n + " introuvable");
      return r.text();
    })));
    selected = names.map((n, i) => ({ name: "demo-" + n, size: texts[i].length, text: texts[i] }));
    els.paste.value = "";
    refresh();
    await run();
  } catch (err) {
    setStatus("Erreur : " + err.message, true);
  }
});

async function run() {
  if (!ready) return;
  if (totalSize() > MAX_BYTES) {
    setStatus("Fichiers trop volumineux : 50 Mo maximum au total.", true);
    return;
  }
  els.analyze.disabled = true;
  setStatus("Analyse en cours…");

  try {
    const inputs = await Promise.all(selected.map(async s => ({ name: s.name, text: s.text ?? await s.file.text() })));
    if (els.paste.value.trim()) inputs.push({ name: "collé", text: els.paste.value });

    // Laisse le navigateur afficher « Analyse en cours… » avant le calcul.
    await new Promise(r => setTimeout(r, 30));
    const t0 = performance.now();
    const out = window.logsentryAnalyze(inputs);
    const ms = Math.round(performance.now() - t0);

    if (out.error) {
      setStatus("Erreur : " + out.error, true);
      return;
    }
    show(out, ms);
  } catch (err) {
    setStatus("Erreur : " + err.message, true);
  } finally {
    refresh();
  }
}

function show(out, ms) {
  const s = out.summary;
  if (s.events === 0) {
    els.results.hidden = true;
    setStatus(`Aucune ligne reconnue sur ${s.lines}. Formats pris en charge : auth.log (sshd) et access.log au format « combined ».`, true);
    return;
  }

  setStatus(`${s.events} événements analysés en ${ms} ms.`);
  const chips = [
    [s.critical, "critique", "critical"], [s.high, "haute", "high"],
    [s.medium, "moyenne", "medium"], [s.low, "faible", "low"],
  ];
  els.summary.replaceChildren(
    chip(`${s.lines} lignes`, ""),
    ...chips.map(([n, label, cls]) => chip(`${n} ${label}${n > 1 ? "s" : ""}`, n ? cls : "")),
  );
  if (s.alerts === 0) els.summary.append(chip("✔ aucune activité suspecte", "ok"));

  urls.forEach(URL.revokeObjectURL);
  urls = [
    URL.createObjectURL(new Blob([out.html], { type: "text/html" })),
    URL.createObjectURL(new Blob([out.json], { type: "application/json" })),
  ];
  els.dlHtml.href = urls[0];
  els.dlJson.href = urls[1];

  // Le rapport s'affiche dans une iframe isolée (sandbox sans scripts).
  els.report.srcdoc = out.html;
  els.results.hidden = false;
  els.results.scrollIntoView({ behavior: "smooth", block: "start" });
}

els.report.addEventListener("load", () => {
  try {
    els.report.style.height = els.report.contentDocument.documentElement.scrollHeight + 20 + "px";
  } catch { /* hauteur par défaut */ }
});

// ---------- Utilitaires ----------

function chip(text, cls) {
  const span = document.createElement("span");
  span.className = "chip " + cls;
  span.textContent = text;
  return span;
}

function setStatus(msg, error = false) {
  els.status.textContent = msg;
  els.status.classList.toggle("error", error);
}

function formatSize(n) {
  if (n < 1024) return n + " o";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " Ko";
  return (n / 1024 / 1024).toFixed(1) + " Mo";
}
