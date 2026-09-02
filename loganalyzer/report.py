"""Generazione del report HTML.

Un solo file, autoconsistente a livello di dati: i cubi prodotti da
`aggregate` finiscono in un blocco JSON dentro la pagina, e tutto il
filtraggio avviene nel browser senza altre richieste.

**Il filtraggio incrociato ha limiti strutturali, e la pagina li dichiara.**
Con dati pre-aggregati un filtro agisce su un widget solo se la dimensione
filtrata è un asse del cubo che lo alimenta, o un attributo di uno dei suoi
assi. Alcune combinazioni non sono rappresentabili — "quanti hit ha preso
l'URL X il 12 marzo" richiederebbe un cubo URL × giorno da milioni di celle —
e ogni widget dichiara cosa sa fare: se un filtro attivo non lo riguarda,
compare un avviso con l'elenco dei filtri ignorati. Mostrare numeri non
filtrati senza dirlo sarebbe l'unica scelta davvero sbagliata.

**Le misure di unicità non si sommano.** URL unici e IP unici esistono solo ai
roll-up precalcolati; sotto un filtro arbitrario il front-end le disabilita
invece di produrre un numero sbagliato per eccesso.

Palette e regole grafiche seguono la guida di visualizzazione: otto tinte
categoriali in ordine fisso mai ciclato, colori di stato riservati alla
verifica degli IP e sempre accompagnati da icona ed etichetta, una sola scala
per asse, legenda sempre presente sopra le due serie.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
from datetime import date
from pathlib import Path

import requests

from .aggregate import Payload
from .config import PATHS, SiteConfig

log = logging.getLogger(__name__)

# Versioni fissate, con gli hash SRI calcolati sui file effettivi.
LIBS = {
    "echarts_js": (
        "https://cdn.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js",
        "sha384-Mx5lkUEQPM1pOJCwFtUICyX45KNojXbkWdYhkKUKsbv391mavbfoAmONbzkgYPzR",
    ),
    "tabulator_js": (
        "https://cdn.jsdelivr.net/npm/tabulator-tables@6.3.1/dist/js/tabulator.min.js",
        "sha384-SKSq3cuuVWdfrjtLz9wNlqE0bMc903yMS5zGnFtwvfddplgxa1hywtiLyw1CbSHO",
    ),
    "tabulator_css": (
        "https://cdn.jsdelivr.net/npm/tabulator-tables@6.3.1/dist/css/tabulator.min.css",
        "sha384-p6hY5g6BjbrEVoCLwj4gZMkotMaHdQrPkd4S0vRpErDxL9/kvjyaUIq/S9RAPQfL",
    ),
}


def _css() -> str:
    return """
:root {
  color-scheme: light;
  --plane:#f9f9f7; --surface:#fcfcfb; --surface-2:#f3f2ee;
  --ink:#0b0b0b; --ink-2:#52514e; --ink-muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --hairline:rgba(11,11,11,.10);
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100;
  --s5:#e87ba4; --s6:#008300; --s7:#4a3aa7; --s8:#e34948;
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
  --seq-100:#cde2fb; --seq-250:#86b6ef; --seq-300:#6da7ec;
  --seq-450:#2a78d6; --seq-550:#1c5cab; --seq-700:#0d366b;
  --rail:268px;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --plane:#0d0d0d; --surface:#1a1a19; --surface-2:#232322;
    --ink:#fff; --ink-2:#c3c2b7; --ink-muted:#898781;
    --grid:#2c2c2a; --axis:#383835; --hairline:rgba(255,255,255,.10);
    --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500;
    --s5:#d55181; --s6:#008300; --s7:#9085e9; --s8:#e66767;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --plane:#0d0d0d; --surface:#1a1a19; --surface-2:#232322;
  --ink:#fff; --ink-2:#c3c2b7; --ink-muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --hairline:rgba(255,255,255,.10);
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500;
  --s5:#d55181; --s6:#008300; --s7:#9085e9; --s8:#e66767;
}

* { box-sizing:border-box; }
body {
  margin:0; background:var(--plane); color:var(--ink);
  font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
}
.wrap { max-width:1720px; margin:0 auto; padding:0 24px 60px; }

header.masthead { padding:24px 0 20px; border-bottom:1px solid var(--hairline); margin-bottom:4px; }
.eyebrow { font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:var(--ink-muted); font-weight:600; }
h1 { font-size:30px; line-height:1.2; margin:6px 0 4px; font-weight:650; letter-spacing:-.01em; }
.sub { color:var(--ink-2); font-size:14px; }

.notes { margin:20px 0 8px; display:grid; gap:8px; }
.note {
  display:flex; gap:10px; align-items:flex-start; padding:11px 14px;
  border:1px solid var(--hairline); border-left:3px solid var(--ink-muted);
  border-radius:6px; background:var(--surface); font-size:13px; color:var(--ink-2);
}
.note.warn { border-left-color:var(--warning); }
.note.bad { border-left-color:var(--critical); background:color-mix(in srgb, var(--critical) 8%, var(--surface)); }
.note.info { border-left-color:var(--s1); }
.note b { color:var(--ink); font-weight:600; }
.note .ico { font-size:14px; line-height:1.4; flex:none; }

.kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(168px,1fr)); gap:12px; margin:20px 0 8px; }
.kpi { background:var(--surface); border:1px solid var(--hairline); border-radius:8px; padding:14px 16px; }
.kpi .lab { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-muted); font-weight:600; }
.kpi .val { font-size:26px; font-weight:650; letter-spacing:-.02em; margin-top:3px; font-variant-numeric:tabular-nums; }
.kpi .hint { font-size:12px; color:var(--ink-2); margin-top:2px; }

nav.toc { position:sticky; top:0; z-index:30; background:var(--plane); border-bottom:1px solid var(--hairline);
  padding:10px 0; margin-bottom:4px; display:flex; gap:6px; flex-wrap:wrap; }
nav.toc a { font-size:12px; color:var(--ink-2); text-decoration:none; padding:5px 10px; border-radius:99px; border:1px solid transparent; }
nav.toc a:hover { background:var(--surface-2); color:var(--ink); }

/* ---- impianto a due colonne ------------------------------------------- */
/* Il filtro sta a sinistra e scorre per conto suo: in testa alla pagina i
   controlli mangiavano l'altezza utile, che su 16:9 e la risorsa scarsa. */
.shell { display:grid; grid-template-columns:var(--rail) minmax(0,1fr); gap:26px; align-items:start; }
.railcol { position:sticky; top:0; height:100vh; display:flex; flex-direction:column;
  padding:24px 0 16px; }

.filters { background:var(--surface); border:1px solid var(--hairline); border-radius:8px;
  display:flex; flex-direction:column; min-height:0; overflow:hidden; }
.fhead { display:flex; align-items:center; justify-content:space-between; gap:8px;
  padding:10px 12px; border-bottom:1px solid var(--hairline); background:var(--surface-2); flex:none; }
.fbody { overflow-y:auto; overflow-x:hidden; padding:4px 12px 12px; display:grid; gap:2px; min-height:0; }
.fgroup { padding:8px 0; border-bottom:1px solid var(--hairline); }
.fgroup:last-child { border-bottom:0; }
.flab { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-muted);
  font-weight:600; margin-bottom:5px; display:flex; align-items:baseline; gap:6px; }
.fcount { font-size:10px; font-weight:700; color:var(--s1); text-transform:none; letter-spacing:0; }
.fcount:empty { display:none; }
.frange { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.f { display:flex; flex-direction:column; gap:4px; }
.f label { font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-muted); font-weight:600; }
.filters select, .filters input {
  font:13px system-ui,-apple-system,"Segoe UI",sans-serif; padding:5px 7px; width:100%; min-width:0;
  border:1px solid var(--axis); border-radius:6px; background:var(--surface); color:var(--ink);
}
.filters select[multiple] { padding:2px; }
.filters select[multiple] option { padding:2px 6px; border-radius:3px; }

/* Sotto i 1180px la colonna non ci sta: il filtro torna in testa, ma
   richiudibile, cosi non ruba comunque l'altezza. */
@media (max-width:1180px) {
  .shell { grid-template-columns:minmax(0,1fr); gap:0; }
  .railcol { position:static; height:auto; padding:0 0 16px; }
  .fbody { grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); display:grid;
    max-height:min(44vh,360px); align-content:start; }
  .fgroup { border-bottom:0; }
  .filters { position:sticky; top:0; z-index:25; }
}

button.btn {
  font:13px system-ui,-apple-system,"Segoe UI",sans-serif; padding:7px 13px; cursor:pointer;
  border:1px solid var(--axis); border-radius:6px; background:var(--surface); color:var(--ink);
}
button.btn:hover { background:var(--surface-2); }
button.btn.primary { background:var(--s1); border-color:var(--s1); color:#fff; }
#activeCount { font-size:12px; color:var(--ink-2); font-variant-numeric:tabular-nums; }

section { margin:36px 0 0; scroll-margin-top:120px; }
section > h2 { font-size:19px; font-weight:650; margin:0 0 3px; letter-spacing:-.01em; }
section > .desc { color:var(--ink-2); font-size:13px; margin:0 0 14px; max-width:78ch; }

.card { background:var(--surface); border:1px solid var(--hairline); border-radius:8px; padding:16px; margin-bottom:16px; }
.card > h3 { font-size:14px; font-weight:640; margin:0 0 2px; }
.card > .cap { font-size:12px; color:var(--ink-muted); margin:0 0 12px; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
@media (max-width:1000px){ .grid2 { grid-template-columns:1fr; } }

.chart { width:100%; height:320px; }
.chart.tall { height:400px; }
.chart.short { height:230px; }

.badge { display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:600;
  padding:3px 8px; border-radius:99px; border:1px solid var(--hairline); color:var(--ink-2); background:var(--surface-2); }
.badge.partial { border-color:var(--warning); color:var(--ink); }
.badge.na { border-color:var(--axis); }
.wstate { min-height:20px; margin-bottom:8px; }
.wstate:empty { display:none; }

.tbl { width:100%; }
.tabulator { border:1px solid var(--hairline); border-radius:6px; background:var(--surface); font-size:13px; }
.tabulator .tabulator-header { background:var(--surface-2); border-bottom:1px solid var(--hairline); }
.tabulator .tabulator-header .tabulator-col { background:transparent; border-right:1px solid var(--hairline); color:var(--ink-2); font-weight:600; }
.tabulator .tabulator-row { background:var(--surface); border-bottom:1px solid var(--grid); color:var(--ink); }
.tabulator .tabulator-row.tabulator-row-even { background:var(--surface); }
.tabulator .tabulator-row:hover { background:var(--surface-2) !important; }
.tabulator .tabulator-row .tabulator-cell { border-right:1px solid transparent; }
.tabulator .tabulator-footer { background:var(--surface-2); border-top:1px solid var(--hairline); color:var(--ink-2); }
.tabulator .tabulator-calcs-holder { background:var(--surface-2) !important; }
.num { font-variant-numeric:tabular-nums; text-align:right; display:block; }
.pathcell { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }

.st { display:inline-flex; align-items:center; gap:5px; font-weight:600; font-size:12px; }
.st .dot { width:8px; height:8px; border-radius:50%; flex:none; }
.st-VERIFIED   .dot { background:var(--good); }
.st-SPOOFED    .dot { background:var(--critical); }
.st-DNS_ERROR  .dot { background:var(--warning); }
.st-UNVERIFIABLE .dot { background:var(--ink-muted); }
.st-NOT_APPLICABLE .dot { background:var(--axis); }

.legend { display:flex; gap:14px; flex-wrap:wrap; margin:4px 0 10px; font-size:12px; color:var(--ink-2); }
.legend span { display:inline-flex; align-items:center; gap:6px; cursor:pointer; }
.legend i { width:10px; height:10px; border-radius:2px; display:inline-block; }
.legend .off { opacity:.35; }

footer { margin-top:56px; padding-top:20px; border-top:1px solid var(--hairline); color:var(--ink-muted); font-size:12px; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; background:var(--surface-2); padding:1px 5px; border-radius:4px; }
.empty { color:var(--ink-muted); font-size:13px; padding:22px; text-align:center; }
"""


def _js() -> str:
    return r"""
// ===========================================================================
// Payload e dizionari
// ===========================================================================
const D = window.__LOGAN__;
const DIM = D.dim, CU = D.cubes, META = D.meta, TOPS = D.tops;

// Dove l'IP del client non arriva nei log nessun bot puo risultare verificato.
// Le colonne su Googlebot allora contano l'agente DICHIARATO: il numero si
// vede lo stesso, con l'etichetta che dice cosa vale e cosa no.
const IPTRUST = META.client_ip_trusted !== false;
const GB_TAG = '<span class="st st-UNVERIFIABLE"><span class="dot"></span>NON VERIFICATO</span>';
const GB_WHY = 'Su questo sito l\'IP del client non arriva nei log (proxy): nessun agente puo '
  + 'essere verificato, quindi si conta Googlebot DICHIARATO dallo user agent. '
  + 'Il numero comprende anche chi si spaccia per Googlebot.';
const GB_WHAT = IPTRUST ? 'Googlebot verificato' : 'Googlebot dichiarato';

const PALETTE = ['--s1','--s2','--s3','--s4','--s5','--s6','--s7','--s8']
  .map(v => getComputedStyle(document.documentElement).getPropertyValue(v).trim());
const CSSVAR = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

// Il colore segue l'entita, mai la sua posizione in classifica: l'indice del
// dizionario e stabile, quindi un filtro che riduce le serie non ridipinge
// quelle rimaste.
const catColor = i => PALETTE[i % PALETTE.length];
const VER_COLOR = {
  VERIFIED: '--good', SPOOFED: '--critical', DNS_ERROR: '--warning',
  UNVERIFIABLE: '--ink-muted', NOT_APPLICABLE: '--axis'
};
const VER_ICON = { VERIFIED:'✓', SPOOFED:'✕', DNS_ERROR:'!', UNVERIFIABLE:'?', NOT_APPLICABLE:'–' };

const nf = new Intl.NumberFormat('it-IT');
const fmt = v => (v == null ? '' : nf.format(Math.round(v)));
const pct = (a, b) => b ? (100 * a / b).toFixed(1).replace('.', ',') + '%' : '–';
const bytesFmt = v => {
  if (!v) return '0';
  const u = ['B','KB','MB','GB','TB']; let i = 0; let n = v;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(n < 10 && i > 0 ? 1 : 0).replace('.', ',') + ' ' + u[i];
};
// Aritmetica di calendario, mai di fuso. `new Date('2025-08-03T00:00:00')` e
// mezzanotte LOCALE, ma `toISOString()` la riporta in UTC: a est di Greenwich
// il giorno stampato e quello prima. Sbagliava ogni etichetta di ogni asse
// temporale; e siccome `initControls` inizializza il campo «Al» con
// dayLabel(n-1), il campo nasceva sul penultimo giorno e l'ultimo giorno del
// periodo usciva dal filtro appena si toccava una delle due date. Qui le date
// si costruiscono e si formattano sempre dai componenti locali.
const [SY, SM, SD] = DIM.date.start.split('-').map(Number);
const START = new Date(SY, SM - 1, SD);
const isoDay = x => x.getFullYear() + '-' + String(x.getMonth() + 1).padStart(2, '0')
                  + '-' + String(x.getDate()).padStart(2, '0');
const dayLabel = d => isoDay(new Date(SY, SM - 1, SD + d));
// L'asse temporale dei cubi per URL e mensile, con la stessa origine.
const monthLabel = mo => {
  const x = new Date(SY, SM - 1 + mo, 1);
  return x.getFullYear() + '-' + String(x.getMonth() + 1).padStart(2, '0');
};
// L'inversa di dayLabel. Il round assorbe l'ora guadagnata o persa quando
// l'intervallo attraversa un cambio di ora legale.
const dayIndex = s => {
  const [y, m, d] = s.split('-').map(Number);
  return Math.round((new Date(y, m - 1, d) - START) / 86400000);
};

// Le colonne dei cubi diventano TypedArray una volta sola: da qui in poi ogni
// query e una scansione lineare su memoria contigua.
//
// Le MISURE restano a 64 bit. La somma dei byte di un singolo giorno per un
// singolo bot supera i 2,1 miliardi, e in un intero a 32 bit andrebbe in
// overflow silenzioso — il totale mostrato sarebbe semplicemente sbagliato,
// senza nessun errore in console. Gli INDICI no: sono limitati dalla
// cardinalita del proprio dizionario, e su 860.000 celle dimensionarli per
// davvero e la differenza fra ~10 e ~45 MB di heap nel browser.
function toTyped(col, values) {
  if (col === 'h' || col === 'by' || col.charCodeAt(0) === 126) {
    return Float64Array.from(values);          // misure, '~' incluso
  }
  let max = 0;
  for (let i = 0; i < values.length; i++) if (values[i] > max) max = values[i];
  return max < 256 ? Uint8Array.from(values)
       : max < 65536 ? Uint16Array.from(values)
       : Int32Array.from(values);
}
function decodeCube(cube) {
  for (const col in cube) {
    if (Array.isArray(cube[col])) cube[col] = toTyped(col, cube[col]);
  }
  return cube;
}
for (const k in CU) decodeCube(CU[k]);
for (const kind of ['ua', 'ip', 'referer']) if (TOPS[kind]) decodeCube(TOPS[kind].cube);

const cubeLen = cube => { for (const c in cube) if (cube[c].length !== undefined) return cube[c].length; return 0; };

// Indice di offset sulla colonna di testa, che e ordinata. Trasforma il filtro
// su quell'asse in uno slice contiguo invece di una scansione con branch: e il
// gesto piu frequente della pagina — trascinare l'intervallo di date — e senza
// questo costerebbe la scansione dell'intero cubo a ogni fotogramma.
function offsetsOf(cube, col, n) {
  const a = cube[col], len = a.length, off = new Int32Array(n + 1);
  let i = 0;
  for (let v = 0; v < n; v++) { off[v] = i; while (i < len && a[i] === v) i++; }
  off[n] = i;
  return off;
}
const nDay = DIM.date.n, nMonth = DIM.date.months;
const nBot = DIM.bot.name.length, nCat = DIM.cat.length, nVer = DIM.ver.length;
const nStatus = DIM.status.code.length, nSec = DIM.section.length, nRt = DIM.restype.length;
const nUrl = DIM.url.p.length, nProbe = DIM.probe.length;
CU.main.__off = offsetsOf(CU.main, 'd', nDay);
CU.url.__off = offsetsOf(CU.url, 'u', nUrl);
CU.attack.__off = offsetsOf(CU.attack, 'd', nDay);
CU.day_bot.__off = offsetsOf(CU.day_bot, 'd', nDay);

// Il mese di ogni giorno, con la stessa formula usata in aggregate.py. Serve a
// tradurre l'intervallo di date nell'asse mensile dei cubi per URL.
const MONTH_OF = (() => {
  const a = new Int16Array(nDay);
  for (let d = 0; d < nDay; d++) {
    const x = new Date(SY, SM - 1, SD + d);
    a[d] = (x.getFullYear() - SY) * 12 + x.getMonth() - (SM - 1);
  }
  return a;
})();

// Gli URL «veri»: le due righe di raccolta non sono URL e non vanno contate
// dove si contano URL distinti.
const URL_IS_AGG = Uint8Array.from(DIM.url.ag || new Array(nUrl).fill(0));

// ===========================================================================
// Store dei filtri
// ===========================================================================
const FS = {
  state: { d0:0, d1:DIM.date.n-1, bot:null, cat:null, ver:null, scls:null, sec:null, rt:null, probe:'exclude' },
  widgets: [],
  raf: null,
  slow: null,
  register(w) { this.widgets.push(w); return w; },
  set(k, v) { this.state[k] = v; this.schedule(); },
  activeDims() {
    const s = this.state, a = [];
    if (s.d0 > 0 || s.d1 < DIM.date.n - 1) a.push('date');
    if (s.bot) a.push('bot');
    if (s.cat) a.push('cat');
    if (s.ver) a.push('ver');
    if (s.scls) a.push('status');
    if (s.sec) a.push('sec');
    if (s.rt) a.push('rt');
    if (s.probe !== 'all') a.push('probe');
    return a;
  },
  schedule() {
    // I grafici seguono il fotogramma, le tabelle no: ricostruire 12.000 righe
    // di Tabulator costa piu di tutte le riduzioni messe insieme, e mentre si
    // trascina uno slider non serve a nessuno. I grafici restano fluidi, le
    // tabelle si assestano quando ci si ferma.
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = requestAnimationFrame(() => this.flush(false));
    clearTimeout(this.slow);
    this.slow = setTimeout(() => this.flush(true), 140);
  },
  flush(withTables) {
    const t0 = performance.now();
    const m = buildMasks(this.state);
    const R = reduce(m);
    const t1 = performance.now();
    const active = this.activeDims();
    document.getElementById('activeCount').textContent =
      active.length === 0 ? 'nessun filtro attivo'
      : active.length === 1 ? '1 filtro attivo' : active.length + ' filtri attivi';
    updateFilterCounts(this.state);
    for (const w of this.widgets) {
      if (w.table && !withTables) continue;
      renderState(w, m, active);
      try { w.render(R, m, this.state); } catch (e) { console.error(w.id, e); }
    }
    console.debug('flush' + (withTables ? '+tabelle' : ''),
      'riduzione ' + (t1 - t0).toFixed(1) + ' ms',
      'render ' + (performance.now() - t1).toFixed(1) + ' ms');
  }
};

// Con la barra in colonna un gruppo puo finire fuori dalla parte visibile
// mentre e attivo: il contatore accanto all'etichetta dice cosa e selezionato
// senza dover risalire con lo scorrimento.
function updateFilterCounts(s) {
  const put = (group, text) => {
    const el = document.querySelector('.fgroup[data-group="' + group + '"] .fcount');
    if (el) el.textContent = text;
  };
  const n = list => (list && list.length) ? '· ' + list.length : '';
  const giorni = s.d1 - s.d0 + 1;
  put('Periodo', (s.d0 > 0 || s.d1 < DIM.date.n - 1) ? '· ' + giorni + ' gg' : '');
  put('Sonde', s.probe === 'all' ? '' : (s.probe === 'only' ? '· solo sonde' : '· escluse'));
  put('Categoria agente', n(s.cat));
  put('User agent', n(s.bot));
  put('Verifica IP', n(s.ver));
  put('Classe di status', n(s.scls));
  put('Sezione', n(s.sec));
  put('Tipo risorsa', n(s.rt));
}

// Il badge non e piu scritto a mano nei widget: ogni widget dichiara il cubo
// che lo alimenta e gli assi arrivano dal payload. Se una leva di budget
// togliesse un asse a un cubo, l'avviso ricomparirebbe da solo — che e
// l'unico modo per cui «numeri non filtrati senza avviso» resti impossibile.
function axesOf(w) { return META.axes[w.cube] || { dims: [] }; }

function renderState(w, m, active) {
  const el = document.getElementById('st-' + w.id);
  if (!el) return;
  const ax = axesOf(w), fixed = w.fixed || [];
  const names = { date:'intervallo di date', bot:'user agent', cat:'categoria', ver:'verifica IP',
                  status:'status code', sec:'sezione', rt:'tipo risorsa', probe:'sonde' };
  const ignored = active.filter(d => ax.dims.indexOf(d) < 0 && fixed.indexOf(d) < 0);
  const out = [];
  if (ignored.length) {
    out.push('<span class="badge partial" title="Questo widget e alimentato da un cubo che non ha '
      + 'queste dimensioni: i dati sono pre-aggregati, non riga per riga.">'
      + '⚠ filtri non applicati qui: ' + ignored.map(d => names[d] || d).join(', ') + '</span>');
  }
  // Arrotondamento dichiarato: e una cosa diversa da «non applicato», e va
  // detta in modo diverso.
  if (ax.coarse && ax.coarse.date && active.indexOf('date') >= 0 && m.dateCoarse) {
    out.push('<span class="badge" title="A livello di singolo URL l\'asse temporale e mensile: '
      + 'il giorno costerebbe piu del doppio dell\'intero payload.">'
      + 'intervallo arrotondato al ' + ax.coarse.date + '</span>');
  }
  if (w.scope) out.push('<span class="badge">' + w.scope + '</span>');
  el.innerHTML = out.join(' ');
}

// ===========================================================================
// Maschere
// ===========================================================================
// Ogni maschera e sempre un Uint8Array, mai null: il ciclo interno costa un
// accesso invece di un ramo su oggetto nullable, ripetuto ~460.000 volte per
// fotogramma.
function maskAll(n) { const a = new Uint8Array(n); a.fill(1); return a; }
function maskOf(n, list) {
  if (!list || !list.length) return maskAll(n);
  const a = new Uint8Array(n);
  for (const i of list) a[i] = 1;
  return a;
}

function buildMasks(s) {
  const m = { d0: s.d0, d1: s.d1, probe: s.probe, state: s };

  // Categoria e sottoinsieme del bot: le due selezioni si intersecano una
  // volta sola qui, invece di due test per cella.
  const bot = maskOf(nBot, s.bot);
  if (s.cat && s.cat.length) {
    const cat = maskOf(nCat, s.cat);
    for (let b = 0; b < nBot; b++) if (!cat[DIM.bot.cat[b]]) bot[b] = 0;
  }
  m.bot = bot;
  m.cat = maskOf(nCat, s.cat);
  m.ver = maskOf(nVer, s.ver);
  m.sec = maskOf(nSec, s.sec);
  m.rt = maskOf(nRt, s.rt);

  // Dalla classe di status al codice, e alla classe stessa: i cubi per URL e
  // per ora portano la classe, quello principale il codice.
  m.status = maskAll(nStatus);
  m.scls = maskAll(10);
  if (s.scls && s.scls.length) {
    const want = new Set(s.scls);
    for (let i = 0; i < nStatus; i++) m.status[i] = want.has(DIM.status.cls[i]) ? 1 : 0;
    m.scls = new Uint8Array(10);
    for (const c of s.scls) m.scls[c] = 1;
  }

  // Le sonde sono un asse vero di ogni cubo, non un trucco sulla sezione.
  m.p = new Uint8Array(2);
  if (s.probe === 'all') { m.p[0] = 1; m.p[1] = 1; }
  else if (s.probe === 'only') m.p[1] = 1;
  else m.p[0] = 1;

  // L'intervallo di date sull'asse mensile dei cubi per URL. Un mese entra se
  // l'intervallo lo tocca; se lo tocca solo in parte, il widget lo dichiara.
  m.mo = new Uint8Array(nMonth);
  for (let d = m.d0; d <= m.d1; d++) m.mo[MONTH_OF[d]] = 1;
  m.dateCoarse = (m.d0 > 0 && MONTH_OF[m.d0 - 1] === MONTH_OF[m.d0])
              || (m.d1 < nDay - 1 && MONTH_OF[m.d1 + 1] === MONTH_OF[m.d1]);

  // Vero quando il filtro cambia il PERIMETRO delle misure, non solo quali
  // righe si vedono. Sezione e tipo scelgono le righe ma non toccano i valori
  // per URL; tutto il resto si. Le misure non additive si spengono qui.
  m.filtered = !!(s.bot || s.cat || s.ver || s.scls || s.probe !== 'all'
                  || s.d0 > 0 || s.d1 < nDay - 1);

  // Il cubo degli IP unici ha solo data, bot e sonda: sotto un filtro su
  // verifica, status, sezione o tipo il suo massimo giornaliero descrive un
  // perimetro piu largo di quello selezionato. Meglio un trattino di un numero
  // che sembra risposta e non lo e.
  m.ipExact = !(s.ver || s.scls || s.sec || s.rt);
  return m;
}

// ===========================================================================
// Riduzione: una passata per CUBO, non per widget
// ===========================================================================
// Prima ogni widget riscansionava il proprio cubo per conto suo, e cinque di
// loro rileggevano lo stesso cubo con la stessa identica predicazione. Oltre a
// costare cinque volte tanto, era il modo in cui due widget alimentati dagli
// stessi dati potevano divergere. Ora la passata e una e gli accumulatori sono
// condivisi: se due numeri della pagina devono coincidere, coincidono perche
// vengono dalla stessa somma.

function reduce(m) {
  return {
    main: reduceMain(m),
    url: reduceUrl(m),
    attack: reduceAttack(m),
    hour: reduceHour(m),
    ips: reduceIps(m),
    tops: reduceTops(m)
  };
}

function reduceMain(m) {
  const c = CU.main, off = c.__off;
  const verIx = DIM.ver.indexOf('VERIFIED');
  const r = {
    total: 0, totalBytes: 0,
    byBot: new Float64Array(nBot), byBotBytes: new Float64Array(nBot),
    byVer: new Float64Array(nVer), byVerBytes: new Float64Array(nVer),
    byStatus: new Float64Array(nStatus), byStatusBytes: new Float64Array(nStatus),
    byCat: new Float64Array(nCat), byCatBytes: new Float64Array(nCat),
    byDayCat: Array.from({ length: nCat }, () => new Float64Array(nDay)),
    byBotVer: Array.from({ length: nVer }, () => new Float64Array(nBot)),
    byBotSclsVer: new Float64Array(nBot * 6),
    byStatusDay: Array.from({ length: nStatus }, () => new Float64Array(nDay)),
    // Sonde dentro il perimetro selezionato ma IGNORANDO il filtro sonde: con
    // le sonde escluse — che e la vista di default — la loro quota calcolata
    // sul filtro sarebbe sempre zero, cioe un KPI che non dice mai niente.
    probeHitsAll: 0, totalAll: 0,
    probeHits: 0
  };
  const end = off[m.d1 + 1];
  for (let i = off[m.d0]; i < end; i++) {
    const b = c.b[i]; if (!m.bot[b]) continue;
    const v = c.v[i]; if (!m.ver[v]) continue;
    const s = c.s[i]; if (!m.status[s]) continue;
    if (!m.sec[c.sec[i]]) continue;
    if (!m.rt[c.rt[i]]) continue;
    const p = c.p[i];
    const h = c.h[i], by = c.by[i], d = c.d[i];
    r.totalAll += h; if (p) r.probeHitsAll += h;
    if (!m.p[p]) continue;
    r.total += h; r.totalBytes += by;
    if (p) r.probeHits += h;
    r.byBot[b] += h; r.byBotBytes[b] += by;
    r.byVer[v] += h; r.byVerBytes[v] += by;
    r.byStatus[s] += h; r.byStatusBytes[s] += by;
    r.byDayCat[DIM.bot.cat[b]][d] += h;
    r.byBotVer[v][b] += h;
    r.byStatusDay[s][d] += h;
    if (v === verIx) r.byBotSclsVer[b * 6 + DIM.status.cls[s]] += h;
  }
  // La categoria e un attributo del bot: si deriva dopo, invece di costare due
  // scritture per cella.
  for (let b = 0; b < nBot; b++) {
    const k = DIM.bot.cat[b];
    r.byCat[k] += r.byBot[b]; r.byCatBytes[k] += r.byBotBytes[b];
  }
  return r;
}

function reduceUrl(m) {
  const c = CU.url;
  const r = {
    hits: new Float64Array(nUrl), bytes: new Float64Array(nUrl),
    botHits: new Float64Array(nBot), botUrls: new Float64Array(nBot),
    total: 0, totalBytes: 0, distinct: 0
  };
  const n = cubeLen(c);
  // Il cubo e ordinato per (u, b): le celle della stessa coppia sono
  // consecutive, quindi gli URL distinti si contano confrontando con l'ultima
  // coppia accettata. Sommare le celle — come faceva il widget AI — gonfiava
  // il conteggio appena il cubo acquisiva piu di un asse per URL.
  let lu = -1, lb = -1, lastU = -1;
  for (let i = 0; i < n; i++) {
    const b = c.b[i]; if (!m.bot[b]) continue;
    if (!m.ver[c.v[i]]) continue;
    if (!m.scls[c.sc[i]]) continue;
    if (!m.p[c.p[i]]) continue;
    if (!m.mo[c.mo[i]]) continue;
    const u = c.u[i];
    if (!m.sec[DIM.url.sec[u]]) continue;
    if (!m.rt[DIM.url.rt[u]]) continue;
    const h = c.h[i], by = c.by[i];
    r.hits[u] += h; r.bytes[u] += by;
    r.botHits[b] += h;
    r.total += h; r.totalBytes += by;
    if (u !== lu || b !== lb) {
      if (!URL_IS_AGG[u]) r.botUrls[b] += 1;
      lu = u; lb = b;
    }
    if (u !== lastU) { if (!URL_IS_AGG[u]) r.distinct += 1; lastU = u; }
  }
  return r;
}

function reduceAttack(m) {
  const c = CU.attack, off = c.__off;
  const r = { byFamily: new Float64Array(nProbe), total: 0,
              byDayFamily: Array.from({ length: nProbe }, () => new Float64Array(nDay)) };
  const end = off[m.d1 + 1];
  for (let i = off[m.d0]; i < end; i++) {
    const b = c.b[i]; if (!m.bot[b]) continue;
    if (!m.ver[c.v[i]]) continue;
    if (!m.scls[c.sc[i]]) continue;
    if (!m.sec[c.sec[i]]) continue;
    if (!m.rt[c.rt[i]]) continue;
    const pf = c.pf[i], h = c.h[i];
    r.byFamily[pf] += h; r.total += h;
    r.byDayFamily[pf][c.d[i]] += h;
  }
  return r;
}

function reduceHour(m) {
  const c = CU.hour_dow, n = cubeLen(c);
  const grid = Array.from({ length: 7 }, () => new Float64Array(24));
  for (let i = 0; i < n; i++) {
    const b = c.b[i]; if (!m.bot[b]) continue;
    if (!m.ver[c.v[i]]) continue;
    if (!m.scls[c.sc[i]]) continue;
    if (!m.p[c.p[i]]) continue;
    if (!m.sec[c.sec[i]]) continue;
    if (!m.rt[c.rt[i]]) continue;
    grid[c.dw[i] - 1][c.hh[i]] += c.h[i];
  }
  return { grid };
}

function reduceIps(m) {
  // `~ui` non e additivo: il massimo giornaliero e l'unica riduzione lecita.
  // Sommarlo sovrastimerebbe di 2-5 volte, ed e l'errore piu facile da fare in
  // tutto il progetto. Questo cubo ha solo data, bot e sonda: sotto un filtro
  // su verifica, status, sezione o tipo il risultato descriverebbe un
  // perimetro piu largo, e `m.ipExact` dice ai widget di non mostrarlo.
  const c = CU.day_bot, off = c.__off;
  const r = { maxByBot: new Float64Array(nBot), max: 0 };
  const end = off[m.d1 + 1];
  const perDay = new Float64Array(nDay);
  for (let i = off[m.d0]; i < end; i++) {
    const b = c.b[i]; if (!m.bot[b]) continue;
    if (!m.p[c.p[i]]) continue;
    const ui = c['~ui'][i];
    if (ui > r.maxByBot[b]) r.maxByBot[b] = ui;
    perDay[c.d[i]] += ui;              // stesso giorno, bot diversi: additivo
  }
  for (let d = m.d0; d <= m.d1; d++) if (perDay[d] > r.max) r.max = perDay[d];
  return r;
}

function reduceTops(m) {
  const out = {};
  // Solo la classifica visibile: le altre due costerebbero 40.000 celle per
  // fotogramma senza che nessuno le guardi.
  const el = document.getElementById('topKind');
  const want = el ? el.value : 'ua';
  for (const kind of ['ua', 'ip', 'referer']) {
    const t = TOPS[kind];
    if (!t || kind !== want) continue;
    const c = t.cube, n = cubeLen(c), nk = t.k.length;
    const hits = new Float64Array(nk);
    const series = Array.from({ length: nk }, () => new Float64Array(nDay));
    for (let i = 0; i < n; i++) {
      const d = c.d[i]; if (d < m.d0 || d > m.d1) continue;
      if (!m.cat[c.c[i]]) continue;
      if (!m.ver[c.v[i]]) continue;
      if (!m.scls[c.sc[i]]) continue;
      if (!m.p[c.p[i]]) continue;
      const k = c.k[i];
      // Per gli user agent il bot e un attributo della chiave, non un asse:
      // cosi il filtro «user agent» vale anche su questa classifica senza
      // moltiplicare le celle del cubo.
      if (t.b && !m.bot[t.b[k]]) continue;
      hits[k] += c.h[i];
      series[k][d] += c.h[i];
    }
    out[kind] = { hits, series };
  }
  return out;
}

// ===========================================================================
// Grafici
// ===========================================================================
const charts = [];
function mkChart(elId) {
  const c = echarts.init(document.getElementById(elId), null, { renderer:'canvas' });
  charts.push(c);
  return c;
}
window.addEventListener('resize', () => charts.forEach(c => c.resize()));

function baseOption(extra) {
  return Object.assign({
    animation: false,
    backgroundColor: 'transparent',
    textStyle: { fontFamily: 'system-ui,-apple-system,"Segoe UI",sans-serif', color: CSSVAR('--ink-2') },
    grid: { left: 58, right: 18, top: 30, bottom: 40, containLabel: false },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line', lineStyle: { color: CSSVAR('--axis') } },
      backgroundColor: CSSVAR('--surface'),
      borderColor: CSSVAR('--hairline'),
      textStyle: { color: CSSVAR('--ink'), fontSize: 12 },
      extraCssText: 'box-shadow:0 2px 12px rgba(0,0,0,.12); border-radius:6px;'
    },
    legend: { top: 0, type: 'scroll', itemWidth: 10, itemHeight: 10, icon: 'roundRect',
              textStyle: { color: CSSVAR('--ink-2'), fontSize: 11 } }
  }, extra);
}
// Il formatter dei numeri sta QUI, non nei singoli assi.
//
// I call site combinano questo oggetto con le proprieta specifiche via
// Object.assign, e Object.assign non fonde in profondita: un `axisLabel`
// definito da entrambe le parti fa vincere l'ultima, e basta invertire i due
// argomenti per perdere il formatter senza accorgersene. Mettendolo qui il
// risultato non dipende piu dall'ordine. Le etichette di categoria sono
// stringhe e passano invariate.
const axisCommon = {
  axisLine: { lineStyle: { color: CSSVAR('--axis') } },
  axisTick: { show: false },
  axisLabel: {
    color: CSSVAR('--ink-muted'),
    fontSize: 11,
    formatter: v => (typeof v === 'number' ? nf.format(v) : v)
  },
  splitLine: { lineStyle: { color: CSSVAR('--grid'), width: 1 } }
};

// ===========================================================================
// Widget: crawl budget nel tempo, per categoria
// ===========================================================================
// Widget: KPI di testa
// ===========================================================================
// Erano stampati lato server e non reagivano a niente: i numeri piu in vista
// della pagina erano anche gli unici che restavano fermi mentre tutto il resto
// si filtrava.
function widgetKpi() {
  const set = (id, value, hint) => {
    const el = document.getElementById('kpi-' + id);
    if (!el) return;
    el.querySelector('.val').innerHTML = value;
    if (hint != null) el.querySelector('.hint').innerHTML = hint;
  };
  return FS.register({
    id: 'kpi', cube: 'main',
    render(R, m) {
      const days = m.d1 - m.d0 + 1;
      set('hits', fmt(R.main.total), days + (days === 1 ? ' giorno' : ' giorni'));
      set('bytes', bytesFmt(R.main.totalBytes), 'trasferiti');
      // IP unici nel periodo: non e una misura additiva e nessun cubo la porta
      // sotto filtro arbitrario. Il massimo giornaliero e l'unica riduzione
      // lecita, e va detto che e quello.
      set('ips',
          !m.filtered ? fmt(META.unique_ips)
          : m.ipExact ? fmt(R.ips.max)
          : '–',
          !m.filtered ? 'nel periodo'
          : m.ipExact ? 'massimo giornaliero, non sommabile'
          : 'non ricavabile con i filtri su verifica, status, sezione o tipo');
      // Stesso trattamento degli IP unici, per la stessa ragione: il cubo per
      // URL ne porta solo quelli rappresentati singolarmente, e con una coda
      // lunga il dizionario ne tiene una frazione. Senza filtri il numero vero
      // e nel meta, e dirlo e meglio che stampare la taglia del dizionario.
      set('urls',
          !m.filtered ? fmt(META.unique_urls) : fmt(R.url.distinct),
          !m.filtered ? 'path distinti nel periodo'
          : 'fra i path rappresentati singolarmente');
      set('probe', pct(R.main.probeHitsAll, R.main.totalAll),
          'quota nel perimetro selezionato, sonde incluse');
      set('anomaly', pct(META.ua_anomaly_hits, META.rows),
          'non filtrabile: e una proprieta della stringa UA');
    }
  });
}

// ===========================================================================
// Widget: crawl budget nel tempo, per categoria
// ===========================================================================
function widgetTimeline() {
  const ch = mkChart('c-timeline');
  return FS.register({
    id: 'timeline', cube: 'main',
    render(R, m) {
      const days = []; for (let d = m.d0; d <= m.d1; d++) days.push(dayLabel(d));
      const used = [];
      DIM.cat.forEach((name, i) => {
        const arr = Array.from(R.main.byDayCat[i].slice(m.d0, m.d1 + 1));
        if (arr.some(v => v > 0)) used.push({ name, i, arr });
      });
      ch.setOption(baseOption({
        xAxis: Object.assign({ type: 'category', data: days, boundaryGap: false }, axisCommon,
                             { splitLine: { show: false } }),
        yAxis: Object.assign({ type: 'value', name: 'richieste', nameTextStyle: { color: CSSVAR('--ink-muted'), fontSize: 11 },
                               axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11, formatter: v => nf.format(v) } }, axisCommon),
        dataZoom: [{ type: 'inside' }, { type: 'slider', height: 18, bottom: 6,
                    borderColor: CSSVAR('--hairline'), fillerColor: 'rgba(42,120,214,.12)',
                    handleStyle: { color: CSSVAR('--s1') }, textStyle: { color: CSSVAR('--ink-muted'), fontSize: 10 } }],
        series: used.map(s => ({
          name: s.name, type: 'line', stack: 'total', areaStyle: { opacity: .82 },
          lineStyle: { width: 0 }, symbol: 'none', itemStyle: { color: catColor(s.i) }, data: s.arr
        }))
      }), true);
    }
  });
}

// ===========================================================================
// Widget: verifica degli IP per bot
// ===========================================================================
function widgetVerify() {
  const ch = mkChart('c-verify');
  const naIx = DIM.ver.indexOf('NOT_APPLICABLE');
  const stack = DIM.ver.filter(v => v !== 'NOT_APPLICABLE');
  const stackIx = stack.map(v => DIM.ver.indexOf(v));
  return FS.register({
    id: 'verify', cube: 'main',
    render(R) {
      const grid = R.main.byBotVer, tot = R.main.byBot;
      // Solo i bot per cui la verifica ha senso: escludere NOT_APPLICABLE
      // toglie di mezzo i browser, dove la domanda non si pone.
      const order = [];
      for (let b = 0; b < nBot; b++) {
        const verifiable = tot[b] - grid[naIx][b];
        if (verifiable > 0) order.push([b, verifiable]);
      }
      order.sort((a, b) => b[1] - a[1]);
      const top = order.slice(0, 14).reverse();
      ch.setOption(baseOption({
        grid: { left: 150, right: 24, top: 30, bottom: 30 },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                   backgroundColor: CSSVAR('--surface'), borderColor: CSSVAR('--hairline'),
                   textStyle: { color: CSSVAR('--ink'), fontSize: 12 } },
        xAxis: Object.assign({ type: 'value', axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11, formatter: v => nf.format(v) } }, axisCommon),
        yAxis: Object.assign({ type: 'category', data: top.map(([b]) => DIM.bot.name[b]) }, axisCommon, { splitLine: { show: false } }),
        series: stack.map((v, k) => ({
          name: VER_ICON[v] + ' ' + v, type: 'bar', stack: 'v', barMaxWidth: 16,
          itemStyle: { color: CSSVAR(VER_COLOR[v]), borderColor: CSSVAR('--surface'), borderWidth: 2,
                       borderRadius: 2 },
          data: top.map(([b]) => grid[stackIx[k]][b])
        }))
      }), true);
    }
  });
}

// ===========================================================================
// Widget: tabella pivot + grafico collegato
// ===========================================================================
function widgetPivot() {
  const ch = mkChart('c-pivot');
  let table = null;
  const dimOf = () => document.getElementById('pivotDim').value;

  return FS.register({
    id: 'pivot', cube: 'main', table: true,
    render(R, m) {
      const dim = dimOf();
      const src = dim === 'bot' ? [DIM.bot.name, R.main.byBot, R.main.byBotBytes]
                : dim === 'cat' ? [DIM.cat, R.main.byCat, R.main.byCatBytes]
                : dim === 'ver' ? [DIM.ver, R.main.byVer, R.main.byVerBytes]
                : [DIM.status.code.map(String), R.main.byStatus, R.main.byStatusBytes];
      const [labels, hits, bytes] = src;
      const total = R.main.total;
      const rows = [];
      for (let i = 0; i < labels.length; i++) {
        if (!hits[i]) continue;
        rows.push({
          k: labels[i], h: hits[i], by: bytes[i],
          share: total ? hits[i] / total : 0,
          // Gli IP unici sono esatti solo per bot: il massimo giornaliero di
          // una categoria non e il massimo dei massimi dei suoi bot, e
          // spacciarlo per tale sarebbe un numero inventato.
          ui: (dim === 'bot' && m.ipExact) ? R.ips.maxByBot[i] : null
        });
      }
      rows.sort((a, b) => b.h - a.h);

      document.getElementById('pivotUniqueNote').innerHTML =
        dim !== 'bot'
          ? '<span class="badge na">IP unici disponibili solo per user agent: su altre dimensioni non sono ricavabili senza sommarli</span>'
        : !m.ipExact
          ? '<span class="badge na">IP unici non ricavabili con i filtri su verifica, status, sezione o tipo attivi</span>'
        : '<span class="badge">IP unici: massimo giornaliero, non sommabile nel periodo</span>';

      if (!table) {
        table = new Tabulator('#t-pivot', {
          data: rows, layout: 'fitColumns', height: '340px',
          placeholder: 'Nessun dato con questi filtri',
          columns: [
            { title: 'Voce', field: 'k', widthGrow: 3, headerFilter: 'input' },
            { title: 'Richieste', field: 'h', hozAlign: 'right', width: 120, sorter: 'number',
              bottomCalc: 'sum', bottomCalcFormatter: c => fmt(c.getValue()),
              formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
            { title: 'Quota', field: 'share', hozAlign: 'right', width: 90, sorter: 'number',
              formatter: c => '<span class="num">' + (100 * c.getValue()).toFixed(1).replace('.', ',') + '%</span>' },
            { title: 'Byte', field: 'by', hozAlign: 'right', width: 110, sorter: 'number',
              formatter: c => '<span class="num">' + (c.getValue() == null ? '–' : bytesFmt(c.getValue())) + '</span>' },
            { title: 'IP unici (max/gg)', field: 'ui', hozAlign: 'right', width: 140, sorter: 'number',
              formatter: c => '<span class="num">' + (c.getValue() == null ? '–' : fmt(c.getValue())) + '</span>' }
          ],
          initialSort: [{ column: 'h', dir: 'desc' }]
        });
      } else {
        table.replaceData(rows);
      }

      const top = rows.slice(0, 12).reverse();
      ch.setOption(baseOption({
        legend: { show: false },
        grid: { left: 160, right: 60, top: 12, bottom: 26 },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                   backgroundColor: CSSVAR('--surface'), borderColor: CSSVAR('--hairline'),
                   textStyle: { color: CSSVAR('--ink'), fontSize: 12 },
                   formatter: p => p[0].name + '<br><b>' + fmt(p[0].value) + '</b> richieste' },
        xAxis: Object.assign({ type: 'value', axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11, formatter: v => nf.format(v) } }, axisCommon),
        yAxis: Object.assign({ type: 'category', data: top.map(r => r.k) }, axisCommon, { splitLine: { show: false } }),
        series: [{
          type: 'bar', barMaxWidth: 14, data: top.map(r => r.h),
          itemStyle: { color: CSSVAR('--s1'), borderRadius: [0, 4, 4, 0] },
          label: { show: true, position: 'right', color: CSSVAR('--ink-2'), fontSize: 11,
                   formatter: p => fmt(p.value) }
        }]
      }), true);
    }
  });
}

// ===========================================================================
// Widget: distribuzione oraria (ora x giorno della settimana)
// ===========================================================================
function widgetHeat() {
  const ch = mkChart('c-heat');
  const DOW = ['lun','mar','mer','gio','ven','sab','dom'];
  return FS.register({
    id: 'heat', cube: 'hour_dow',
    render(R) {
      const grid = R.hour.grid;
      const data = []; let max = 0;
      for (let d = 0; d < 7; d++) for (let h = 0; h < 24; h++) {
        data.push([h, d, grid[d][h]]);
        if (grid[d][h] > max) max = grid[d][h];
      }
      ch.setOption({
        animation: false, backgroundColor: 'transparent',
        tooltip: { position: 'top', backgroundColor: CSSVAR('--surface'), borderColor: CSSVAR('--hairline'),
                   textStyle: { color: CSSVAR('--ink'), fontSize: 12 },
                   formatter: p => DOW[p.value[1]] + ' ore ' + String(p.value[0]).padStart(2, '0') + '<br><b>' + fmt(p.value[2]) + '</b> richieste' },
        grid: { left: 44, right: 20, top: 14, bottom: 56 },
        xAxis: { type: 'category', data: Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0')),
                 splitArea: { show: false }, axisLine: { lineStyle: { color: CSSVAR('--axis') } },
                 axisTick: { show: false }, axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 10 } },
        yAxis: { type: 'category', data: DOW, axisLine: { lineStyle: { color: CSSVAR('--axis') } },
                 axisTick: { show: false }, axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11 } },
        visualMap: { min: 0, max: max || 1, calculable: false, orient: 'horizontal', left: 'center', bottom: 6,
                     itemWidth: 12, itemHeight: 90, textStyle: { color: CSSVAR('--ink-muted'), fontSize: 10 },
                     inRange: { color: [CSSVAR('--seq-100'), CSSVAR('--seq-250'), CSSVAR('--seq-450'), CSSVAR('--seq-700')] } },
        series: [{ type: 'heatmap', data, itemStyle: { borderColor: CSSVAR('--surface'), borderWidth: 2 } }]
      }, true);
    }
  });
}

// ===========================================================================
// Widget: tabella URL
// ===========================================================================
function widgetUrls() {
  let table = null;
  const U = DIM.url;
  // Le righe si allocano una volta sola e si mutano in loco: ricrearne 12.000
  // a ogni fotogramma costerebbe piu di tutte le riduzioni messe insieme.
  const rows = U.p.map((p, i) => ({
    i, p,
    sec: DIM.section[U.sec[i]],
    rt: DIM.restype[U.rt[i]],
    neverLogged: U.h[i] === 0,
    aggregate: U.ag[i] === 1,
    probe: !!U.pb[i],
    h: 0, by: 0, ui: null,
    fs: U.fs[i] >= 0 ? dayLabel(U.fs[i]) : null,
    ls: U.ls[i] >= 0 ? dayLabel(U.ls[i]) : null,
    // -2 = riga di raccolta, -1 = mai preso da Googlebot: sono cose diverse.
    gAge: U.gls[i] >= 0 ? (DIM.date.n - 1 - U.gls[i]) : (U.gls[i] === -1 ? -1 : null),
    gc: U.gc[i], gi: U.gi[i], sm: !!U.sm[i]
  }));
  return FS.register({
    id: 'urls', cube: 'url', table: true,
    render(R, m) {
      const hits = R.url.hits, bytes = R.url.bytes;
      const filtered = [];
      for (const r of rows) {
        // Sezione e tipo sono attributi dell'URL: le maschere sono sempre
        // definite, perche gli attributi ignoti hanno una voce di dizionario
        // vera invece dell'indice -1.
        if (!m.sec[U.sec[r.i]] || !m.rt[U.rt[r.i]]) continue;
        r.h = hits[r.i]; r.by = bytes[r.i];
        // Gli IP unici per URL sono un totale di periodo e non sono additivi:
        // sotto un filtro che cambia il perimetro, un trattino invece di un
        // numero verosimile ma falso.
        r.ui = m.filtered ? null : (U['~ui'][r.i] >= 0 ? U['~ui'][r.i] : null);
        // Un URL senza richieste nel perimetro selezionato esce, tranne
        // quando non c'e nessun filtro: li gli URL noti a Google ma mai
        // comparsi nei log sono l'informazione, non il rumore.
        if (r.h === 0 && m.filtered) continue;
        filtered.push(r);
      }
      if (!table) {
        table = new Tabulator('#t-urls', {
          data: filtered, layout: 'fitColumns', height: '520px', pagination: true,
          paginationSize: 60, paginationCounter: 'rows',
          placeholder: 'Nessun URL con questi filtri',
          columns: [
            { title: 'URL', field: 'p', widthGrow: 4, headerFilter: 'input',
              formatter: c => '<span class="pathcell">' + escapeHtml(c.getValue()) + '</span>' },
            { title: 'Sezione', field: 'sec', width: 120, headerFilter: 'list',
              headerFilterParams: { values: DIM.section, clearable: true },
              formatter: c => escapeHtml(c.getValue()) },
            { title: 'Tipo', field: 'rt', width: 100, headerFilter: 'list',
              headerFilterParams: { values: DIM.restype, clearable: true },
              formatter: c => escapeHtml(c.getValue()) },
            { title: 'Richieste', field: 'h', hozAlign: 'right', width: 110, sorter: 'number',
              bottomCalc: 'sum', bottomCalcFormatter: c => fmt(c.getValue()),
              formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
            { title: 'Byte', field: 'by', hozAlign: 'right', width: 100, sorter: 'number',
              formatter: c => '<span class="num">' + bytesFmt(c.getValue()) + '</span>' },
            { title: 'IP unici', field: 'ui', hozAlign: 'right', width: 95, sorter: 'number',
              headerTooltip: 'Totale di periodo. Non e sommabile, quindi sotto filtro mostra un trattino.',
              formatter: c => '<span class="num">' + (c.getValue() == null ? '–' : fmt(c.getValue())) + '</span>' },
            { title: 'Click GSC', field: 'gc', hozAlign: 'right', width: 100, sorter: 'number',
              bottomCalc: 'sum', bottomCalcFormatter: c => fmt(c.getValue()),
              formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
            { title: 'Impression GSC', field: 'gi', hozAlign: 'right', width: 130, sorter: 'number',
              bottomCalc: 'sum', bottomCalcFormatter: c => fmt(c.getValue()),
              formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
            { title: 'Primo hit', field: 'fs', width: 105, formatter: c => c.getValue() || '–' },
            { title: 'Ultimo hit', field: 'ls', width: 105, formatter: c => c.getValue() || '–' },
            { title: 'Ultimo Googlebot (gg)' + (IPTRUST ? '' : ' *'),
              field: 'gAge', hozAlign: 'right', width: IPTRUST ? 175 : 195, sorter: 'number',
              headerTooltip: 'Giorni trascorsi dall\'ultima richiesta di Googlebot, contati dall\'ultimo '
                + 'giorno del periodo analizzato (' + dayLabel(DIM.date.n - 1) + '), non da oggi. '
                + (IPTRUST ? 'Conta solo Googlebot con IP VERIFICATO.' : '* ' + GB_WHY)
                + ' Non segue i filtri della pagina: e un '
                + 'totale di periodo. Non comprende Googlebot-Image, Googlebot-News, GoogleOther, '
                + 'AdsBot-Google e Google-InspectionTool, che sono agenti distinti.',
              formatter: c => {
                const v = c.getValue();
                if (v == null) return '<span class="num">–</span>';
                if (v < 0) return '<span class="st st-SPOOFED"><span class="dot"></span>mai preso</span>';
                return '<span class="num">' + v + '</span>';
              } }
          ],
          initialSort: [{ column: 'h', dir: 'desc' }]
        });
      } else {
        table.replaceData(filtered);
      }
      document.getElementById('urlCount').innerHTML =
        fmt(filtered.length) + ' URL mostrati su ' + fmt(META.coverage.urls_total) +
        ' osservati (copertura ' + String(META.coverage.hits_covered_pct).replace('.', ',') + '% degli hit)'
        + (IPTRUST ? '' : '<br>' + GB_TAG + ' <span style="opacity:.8">La colonna '
            + '«Ultimo Googlebot&nbsp;*» conta l\'agente dichiarato dallo user agent: '
            + 'su questo sito l\'IP arriva da un proxy e nessuna identita e dimostrabile.</span>');
    }
  });
}

// ===========================================================================
// Widget: copertura dei bot AI per URL
// ===========================================================================
function widgetAi() {
  const ch = mkChart('c-ai');
  // L'elenco arriva dalle categorie dichiarate in configurazione, non da una
  // regex nel front-end: quella ne intercettava 7 su 20.
  const AI = new Set(DIM.cat_ai || []);
  const AI_BOTS = [];
  for (let b = 0; b < nBot; b++) if (AI.has(DIM.bot.cat[b])) AI_BOTS.push(b);
  const SUB = { 'training': 'crawler di training', 'answer-index': 'indice di risposta',
                'on-demand': 'fetch su richiesta' };
  return FS.register({
    id: 'ai', cube: 'url',
    render(R) {
      const rows = AI_BOTS
        .map(b => ({ b, urls: R.url.botUrls[b], hits: R.url.botHits[b] }))
        .filter(r => r.urls > 0)
        .sort((a, b) => b.urls - a.urls)
        .slice(0, 16);
      ch.setOption(baseOption({
        legend: { top: 0, itemWidth: 10, itemHeight: 10, icon: 'roundRect',
                  textStyle: { color: CSSVAR('--ink-2'), fontSize: 11 }, data: ['URL distinti raggiunti'] },
        grid: { left: 170, right: 80, top: 30, bottom: 26 },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                   backgroundColor: CSSVAR('--surface'), borderColor: CSSVAR('--hairline'),
                   textStyle: { color: CSSVAR('--ink'), fontSize: 12 },
                   formatter: p => {
                     const r = rows[rows.length - 1 - p[0].dataIndex];
                     const sub = DIM.bot.sub[r.b] >= 0 ? DIM.sub[DIM.bot.sub[r.b]] : null;
                     return DIM.bot.name[r.b] + (sub ? '<br><i>' + (SUB[sub] || sub) + '</i>' : '')
                       + '<br><b>' + fmt(r.urls) + '</b> URL distinti<br>' + fmt(r.hits) + ' richieste';
                   } },
        xAxis: Object.assign({ type: 'value', axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11 } }, axisCommon),
        yAxis: Object.assign({ type: 'category', data: rows.map(r => DIM.bot.name[r.b]).reverse() }, axisCommon, { splitLine: { show: false } }),
        series: [{
          name: 'URL distinti raggiunti', type: 'bar', barMaxWidth: 14,
          data: rows.map(r => r.urls).reverse(),
          itemStyle: { color: CSSVAR('--s3'), borderRadius: [0, 4, 4, 0] },
          label: { show: true, position: 'right', color: CSSVAR('--ink-2'), fontSize: 11, formatter: p => fmt(p.value) }
        }]
      }), true);
    }
  });
}

// ===========================================================================
// Widget: sonde e attacchi nel tempo
// ===========================================================================
function widgetAttack() {
  const ch = mkChart('c-attack');
  return FS.register({
    id: 'attack', cube: 'attack',
    // Questo widget guarda per definizione solo le sonde: il filtro relativo
    // non lo riguarda, e va detto come perimetro, non come avviso.
    fixed: ['probe'],
    scope: 'perimetro fisso: solo traffico marcato come sonda',
    render(R, m) {
      const tot = R.attack.byFamily;
      const order = [...tot.keys()].filter(i => tot[i] > 0)
                                   .sort((a, b) => tot[b] - tot[a]).slice(0, 8);
      const days = []; for (let d = m.d0; d <= m.d1; d++) days.push(dayLabel(d));
      ch.setOption(baseOption({
        xAxis: Object.assign({ type: 'category', data: days, boundaryGap: false }, axisCommon, { splitLine: { show: false } }),
        yAxis: Object.assign({ type: 'value', axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11, formatter: v => nf.format(v) } }, axisCommon),
        dataZoom: [{ type: 'inside' }, { type: 'slider', height: 16, bottom: 6, borderColor: CSSVAR('--hairline'),
                    fillerColor: 'rgba(42,120,214,.12)', textStyle: { color: CSSVAR('--ink-muted'), fontSize: 10 } }],
        series: order.map((p, k) => ({
          name: DIM.probe[p], type: 'line', stack: 'a', areaStyle: { opacity: .8 },
          lineStyle: { width: 0 }, symbol: 'none', itemStyle: { color: catColor(k) },
          data: Array.from(R.attack.byDayFamily[p].slice(m.d0, m.d1 + 1))
        }))
      }), true);
    }
  });
}

// ===========================================================================
// Widget: classifiche
// ===========================================================================
// Prima questo widget non era nemmeno registrato nello store: mostrava sempre
// numeri sull'intero periodo, senza filtri e — non avendo il div di stato —
// senza dirlo. URI e status non hanno piu bisogno di un roll-up dedicato: si
// ricalcolano dai cubi, quindi ordinano l'intero dizionario invece di
// venticinque voci congelate.
function widgetTops() {
  const ch = mkChart('c-top');
  let table = null;
  let picked = null;
  const kindOf = () => document.getElementById('topKind').value;
  const CUBE_OF = { uri:'url', status:'main', ua:'top_ua', ip:'top_ip', referer:'top_referer' };

  function collect(R, m) {
    const kind = kindOf(), n = META.top_n;
    if (kind === 'uri') {
      const hits = R.url.hits, out = [];
      for (let u = 0; u < nUrl; u++) if (hits[u] > 0) out.push({ i: u, k: DIM.url.p[u], h: hits[u], ui: null });
      out.sort((a, b) => b.h - a.h);
      return out.slice(0, n);
    }
    if (kind === 'status') {
      const out = [];
      for (let i = 0; i < nStatus; i++) if (R.main.byStatus[i] > 0)
        out.push({ i, k: String(DIM.status.code[i]), h: R.main.byStatus[i], ui: null });
      out.sort((a, b) => b.h - a.h);
      return out.slice(0, n);
    }
    const t = TOPS[kind], red = R.tops[kind];
    if (!t || !red) return [];
    const out = [];
    for (let i = 0; i < t.k.length; i++) if (red.hits[i] > 0)
      out.push({ i, k: t.k[i], h: red.hits[i], ui: m.filtered ? null : t['~ui'][i] });
    out.sort((a, b) => b.h - a.h);
    return out.slice(0, n);
  }

  // La serie temporale della voce selezionata. Per gli URL l'asse e mensile,
  // come il cubo che li porta: e la stessa grana dichiarata dal badge.
  function series(R, m, kind, row) {
    if (!row) return { x: [], y: [] };
    if (kind === 'uri') {
      const c = CU.url, off = c.__off, arr = new Float64Array(nMonth);
      for (let i = off[row.i]; i < off[row.i + 1]; i++) {
        if (!m.bot[c.b[i]] || !m.ver[c.v[i]] || !m.scls[c.sc[i]] || !m.p[c.p[i]] || !m.mo[c.mo[i]]) continue;
        arr[c.mo[i]] += c.h[i];
      }
      const x = [], y = [];
      for (let mo = 0; mo < nMonth; mo++) if (m.mo[mo]) { x.push(monthLabel(mo)); y.push(arr[mo]); }
      return { x, y };
    }
    const src = kind === 'status' ? R.main.byStatusDay[row.i] : R.tops[kind].series[row.i];
    const x = [], y = [];
    for (let d = m.d0; d <= m.d1; d++) { x.push(dayLabel(d)); y.push(src[d]); }
    return { x, y };
  }

  function paint(R, m, rows) {
    const kind = kindOf();
    if (!rows.some(r => r.k === picked)) picked = rows.length ? rows[0].k : null;
    const row = rows.find(r => r.k === picked) || null;
    document.getElementById('topPick').textContent = picked == null ? '—' : String(picked);
    const s = series(R, m, kind, row);
    ch.setOption(baseOption({
      legend: { show: false },
      grid: { left: 58, right: 18, top: 16, bottom: 30 },
      xAxis: Object.assign({ type: 'category', data: s.x, boundaryGap: false }, axisCommon, { splitLine: { show: false } }),
      yAxis: Object.assign({ type: 'value', axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11, formatter: v => nf.format(v) } }, axisCommon),
      series: [{ type: 'line', symbol: 'none', lineStyle: { width: 2, color: CSSVAR('--s1') },
                 areaStyle: { color: 'rgba(42,120,214,.10)' }, data: s.y }]
    }), true);
  }

  const w = FS.register({
    id: 'tops', table: true,
    get cube() { return CUBE_OF[kindOf()]; },
    render(R, m) {
      const kind = kindOf();
      const rows = collect(R, m);
      const cols = [
        { title: kind === 'uri' ? 'URL' : kind === 'ua' ? 'User agent' : kind === 'ip' ? 'Indirizzo IP'
               : kind === 'referer' ? 'Referer' : 'Status', field: 'k', widthGrow: 4,
          formatter: c => '<span class="pathcell">' + escapeHtml(String(c.getValue())) + '</span>' },
        { title: 'Richieste', field: 'h', hozAlign: 'right', width: 120, sorter: 'number',
          formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
        { title: 'IP unici', field: 'ui', hozAlign: 'right', width: 110, sorter: 'number',
          headerTooltip: 'Totale di periodo: non essendo sommabile, sotto filtro mostra un trattino.',
          formatter: c => '<span class="num">' + (c.getValue() == null ? '–' : fmt(c.getValue())) + '</span>' }
      ];
      const opts = {
        data: rows, layout: 'fitColumns', height: '330px', columns: cols,
        placeholder: 'Nessuna voce con questi filtri',
        initialSort: [{ column: 'h', dir: 'desc' }],
        rowClick: (e, r) => { picked = r.getData().k; paint(R, m, rows); }
      };
      if (!table) table = new Tabulator('#t-top', opts);
      else { table.setColumns(cols); table.replaceData(rows); }
      // Il pool e un limite reale e va detto dov'e: una chiave fuori dalle
      // prime `top_pool` globali non puo risalire in classifica sotto filtro.
      document.getElementById('topScope').innerHTML =
        (kind === 'uri' || kind === 'status')
          ? '<span class="badge">classifica ricalcolata su tutte le voci</span>'
          : '<span class="badge">ri-ordinata entro le prime ' + fmt(META.top_pool)
            + ' voci del periodo: sotto filtri stretti una voce fuori da quel pool non risale</span>';
      paint(R, m, rows);
    }
  });
  document.getElementById('topKind').addEventListener('change', () => { picked = null; FS.schedule(); });
  return w;
}

// ===========================================================================
// Widget: crawl waste e stato dei bot verificati
// ===========================================================================
function widgetWaste() {
  const ch = mkChart('c-waste');
  const classes = [[2, '2xx'], [3, '3xx'], [4, '4xx'], [5, '5xx']];
  const COL = { 2: '--good', 3: '--s1', 4: '--warning', 5: '--critical' };
  return FS.register({
    id: 'waste', cube: 'main',
    fixed: ['ver'],
    scope: 'perimetro fisso: solo richieste con IP verificato',
    render(R) {
      const g = R.main.byBotSclsVer;
      const order = [];
      for (let b = 0; b < nBot; b++) {
        let s = 0; for (let c = 0; c < 6; c++) s += g[b * 6 + c];
        if (s > 0) order.push([b, s]);
      }
      order.sort((a, b) => b[1] - a[1]);
      const bots = order.slice(0, 10).reverse();
      ch.setOption(baseOption({
        grid: { left: 150, right: 24, top: 30, bottom: 30 },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                   backgroundColor: CSSVAR('--surface'), borderColor: CSSVAR('--hairline'),
                   textStyle: { color: CSSVAR('--ink'), fontSize: 12 } },
        xAxis: Object.assign({ type: 'value', axisLabel: { color: CSSVAR('--ink-muted'), fontSize: 11, formatter: v => nf.format(v) } }, axisCommon),
        yAxis: Object.assign({ type: 'category', data: bots.map(([b]) => DIM.bot.name[b]) }, axisCommon, { splitLine: { show: false } }),
        series: classes.map(([cl, name]) => ({
          name, type: 'bar', stack: 's', barMaxWidth: 16,
          itemStyle: { color: CSSVAR(COL[cl]), borderColor: CSSVAR('--surface'), borderWidth: 2, borderRadius: 2 },
          data: bots.map(([b]) => g[b * 6 + cl])
        }))
      }), true);
    }
  });
}

// ===========================================================================
// L'universo non sono tutti gli URL osservati: sui log di un sito pubblico la
// stragrande maggioranza dei percorsi e inventata dagli scanner, e Googlebot
// non ha nessuna ragione di chiederli. Qui contano gli URL che Google CONOSCE:
// quelli in sitemap, se una sitemap e stata fornita, piu quelli che hanno
// ricevuto impression in Search Console.
function widgetStale() {
  const ch = mkChart('c-stale');
  let table = null;
  const U = DIM.url;
  const lastDay = DIM.date.n - 1;

  const all = [];
  for (let i = 0; i < U.p.length; i++) {
    if (U.ag[i] === 1) continue;                            // righe di raccolta
    const known = U.sm[i] === 1 || U.gi[i] > 0;
    if (!known) continue;
    all.push({
      i, p: U.p[i],
      sec: DIM.section[U.sec[i]],
      gAge: U.gls[i] >= 0 ? lastDay - U.gls[i] : null,      // null = mai preso
      gi: U.gi[i], gc: U.gc[i], h: U.h[i],
      neverLogged: U.h[i] === 0,
      sm: U.sm[i] === 1
    });
  }
  // Sezione e tipo risorsa scelgono quali URL guardare; tutto il resto no,
  // perche «ultima visita di Googlebot verificato» e un totale di periodo su
  // un agente fisso, e restringerlo per bot o per data non vorrebbe dire
  // niente. Il badge lo dichiara invece di far finta.
  let universe = all;

  const BUCKETS = [
    { lab: 'mai preso',   step: '--seq-700', test: r => r.gAge === null },
    { lab: 'oltre 90 gg', step: '--seq-550', test: r => r.gAge > 90 },
    { lab: '61-90 gg',    step: '--seq-450', test: r => r.gAge > 60 && r.gAge <= 90 },
    { lab: '31-60 gg',    step: '--seq-300', test: r => r.gAge > 30 && r.gAge <= 60 },
    { lab: 'entro 30 gg', step: '--seq-250', test: r => r.gAge !== null && r.gAge <= 30 }
  ];

  function draw(m) {
    if (m) universe = all.filter(r => m.sec[U.sec[r.i]] && m.rt[U.rt[r.i]]);
    const days = Number(document.getElementById('staleDays').value);
    const stale = universe.filter(r => r.gAge === null || r.gAge > days)
                          .sort((a, b) => b.gi - a.gi);
    const impStale = stale.reduce((a, r) => a + r.gi, 0);
    const never = universe.filter(r => r.gAge === null).length;
    const neverLogged = universe.filter(r => r.neverLogged).length;

    document.getElementById('staleSummary').innerHTML = universe.length === 0
      ? '<span class="badge na">Serve una sitemap in <code>input/</code>, oppure i dati di Search Console, per stabilire quali URL Google conosce.</span>'
      : '<b>' + fmt(stale.length) + '</b> URL su ' + fmt(universe.length)
        + ' (' + pct(stale.length, universe.length) + ') non ricevono una visita di ' + GB_WHAT + ' da oltre '
        + days + ' giorni, o non l&rsquo;hanno mai ricevuta. Valgono <b>' + fmt(impStale)
        + '</b> impression. Di questi, <b>' + fmt(never) + '</b> non sono mai stati presi nel periodo'
        + (neverLogged ? ', e <b>' + fmt(neverLogged) + '</b> non compaiono affatto nei log del server' : '')
        + '.'
        + (IPTRUST ? '' : '<br>' + GB_TAG + ' <span style="opacity:.8">' + GB_WHY + '</span>');

    const data = BUCKETS.map(b => {
      const rows = universe.filter(b.test);
      return { lab: b.lab, step: b.step, urls: rows.length, imp: rows.reduce((a, r) => a + r.gi, 0) };
    }).reverse();

    ch.setOption(baseOption({
      legend: { show: false },
      grid: { left: 110, right: 170, top: 14, bottom: 34 },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                 backgroundColor: CSSVAR('--surface'), borderColor: CSSVAR('--hairline'),
                 textStyle: { color: CSSVAR('--ink'), fontSize: 12 },
                 formatter: p => {
                   const d = data[p[0].dataIndex];
                   return d.lab + '<br><b>' + fmt(d.imp) + '</b> impression<br>' + fmt(d.urls) + ' URL';
                 } },
      // La barra misura il NUMERO DI URL, non le impression. Con le impression
      // la fascia "entro 30 gg" ne vale oltre quattro milioni e schiaccia a
      // zero tutte le altre, cioe proprio quelle che questa sezione deve far
      // vedere. Le impression restano come etichetta diretta su ogni barra e
      // nel riepilogo qui sopra, dove un numero singolo sta meglio comunque.
      xAxis: Object.assign({}, axisCommon, { type: 'value', name: 'URL',
                             nameTextStyle: { color: CSSVAR('--ink-muted'), fontSize: 11 } }),
      yAxis: Object.assign({}, axisCommon, { type: 'category', data: data.map(d => d.lab),
                             splitLine: { show: false } }),
      series: [{
        type: 'bar', barMaxWidth: 18,
        data: data.map(d => ({ value: d.urls, itemStyle: { color: CSSVAR(d.step), borderRadius: [0, 4, 4, 0] } })),
        label: { show: true, position: 'right', color: CSSVAR('--ink-2'), fontSize: 11,
                 formatter: p => fmt(data[p.dataIndex].imp) + ' impression' }
      }]
    }), true);

    const cols = [
      { title: 'URL', field: 'p', widthGrow: 4, headerFilter: 'input',
        formatter: c => '<span class="pathcell">' + escapeHtml(c.getValue()) + '</span>' },
      { title: 'Sezione', field: 'sec', width: 130,
        formatter: c => c.getValue() == null ? '<span style="opacity:.5">mai nei log</span>' : escapeHtml(c.getValue()) },
      { title: 'Ultimo Googlebot (gg)' + (IPTRUST ? '' : ' *'),
        field: 'gAge', hozAlign: 'right', width: IPTRUST ? 175 : 195, sorter: 'number',
        headerTooltip: IPTRUST ? 'Conta solo Googlebot con IP VERIFICATO.' : '* ' + GB_WHY,
        formatter: c => c.getValue() == null
          ? '<span class="st st-SPOOFED"><span class="dot"></span>mai preso</span>'
          : '<span class="num">' + c.getValue() + '</span>' },
      { title: 'Impression', field: 'gi', hozAlign: 'right', width: 120, sorter: 'number',
        bottomCalc: 'sum', bottomCalcFormatter: c => fmt(c.getValue()),
        formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
      { title: 'Click', field: 'gc', hozAlign: 'right', width: 90, sorter: 'number',
        bottomCalc: 'sum', bottomCalcFormatter: c => fmt(c.getValue()),
        formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' },
      { title: 'Richieste totali', field: 'h', hozAlign: 'right', width: 145, sorter: 'number',
        headerTooltip: 'Richieste da qualunque agente, non solo da Googlebot.',
        formatter: c => '<span class="num">' + fmt(c.getValue()) + '</span>' }
    ];
    if (!table) {
      table = new Tabulator('#t-stale', {
        data: stale, layout: 'fitColumns', height: '420px', columns: cols,
        pagination: true, paginationSize: 40, paginationCounter: 'rows',
        placeholder: 'Nessun URL in ritardo con questa soglia',
        initialSort: [{ column: 'gi', dir: 'desc' }]
      });
    } else {
      table.replaceData(stale);
    }
  }

  // La soglia di partenza viene dalla configurazione (report.googlebot_stale_days),
  // non e cablata nella pagina.
  const sel = document.getElementById('staleDays');
  const configured = String(META.googlebot_stale_days || 30);
  if ([...sel.options].some(o => o.value === configured)) sel.value = configured;

  sel.addEventListener('change', () => draw(null));
  return FS.register({
    id: 'stale', cube: 'stale', table: true,
    fixed: ['bot', 'ver', 'probe'],
    scope: 'perimetro fisso: URL noti a Google, ultima visita di ' + GB_WHAT + ' sul periodo intero',
    render(R, m) { draw(m); }
  });
}

// ===========================================================================
// Controlli
// ===========================================================================
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
function multiValues(el) {
  const v = [...el.selectedOptions].map(o => Number(o.value));
  return v.length ? v : null;
}

function initControls() {
  const fill = (id, values) => {
    const el = document.getElementById(id);
    values.forEach((v, i) => {
      const o = document.createElement('option');
      o.value = i; o.textContent = v; el.appendChild(o);
    });
  };
  fill('fCat', DIM.cat);
  fill('fVer', DIM.ver);
  fill('fSec', DIM.section);
  fill('fRt', DIM.restype);
  // I bot in ordine di traffico: la prima voce dell'elenco e quella che conta.
  const botEl = document.getElementById('fBot');
  DIM.bot.name.forEach((v, i) => {
    const o = document.createElement('option'); o.value = i; o.textContent = v; botEl.appendChild(o);
  });

  document.getElementById('fCat').addEventListener('change', e => FS.set('cat', multiValues(e.target)));
  document.getElementById('fBot').addEventListener('change', e => FS.set('bot', multiValues(e.target)));
  document.getElementById('fVer').addEventListener('change', e => FS.set('ver', multiValues(e.target)));
  document.getElementById('fSec').addEventListener('change', e => FS.set('sec', multiValues(e.target)));
  document.getElementById('fRt').addEventListener('change', e => FS.set('rt', multiValues(e.target)));
  document.getElementById('fStatus').addEventListener('change', e => FS.set('scls', multiValues(e.target)));
  document.getElementById('fProbe').addEventListener('change', e => FS.set('probe', e.target.value));
  document.getElementById('pivotDim').addEventListener('change', () => FS.schedule());

  const d0 = document.getElementById('fFrom'), d1 = document.getElementById('fTo');
  d0.min = d1.min = DIM.date.start; d0.max = d1.max = dayLabel(DIM.date.n - 1);
  d0.value = DIM.date.start; d1.value = dayLabel(DIM.date.n - 1);
  const onDate = () => {
    const a = Math.max(0, dayIndex(d0.value));
    const b = Math.min(DIM.date.n - 1, dayIndex(d1.value));
    FS.state.d0 = Math.min(a, b); FS.state.d1 = Math.max(a, b); FS.schedule();
  };
  d0.addEventListener('change', onDate); d1.addEventListener('change', onDate);

  document.getElementById('btnReset').addEventListener('click', () => {
    document.querySelectorAll('.filters select').forEach(s => {
      if (s.multiple) [...s.options].forEach(o => o.selected = false);
    });
    document.getElementById('fProbe').value = 'exclude';
    d0.value = DIM.date.start; d1.value = dayLabel(DIM.date.n - 1);
    Object.assign(FS.state, { d0:0, d1:DIM.date.n-1, bot:null, cat:null, ver:null, scls:null, sec:null, rt:null, probe:'exclude' });
    FS.schedule();
  });
}

// ===========================================================================
// Controllo incrociato Polars <-> JavaScript
// ===========================================================================
// `meta.selftest` porta una manciata di stati di filtro con i totali calcolati
// in Polars sul frame riga per riga. Qui li facciamo girare nel riduttore del
// front-end e li confrontiamo. E l'unico controllo che attraversa il confine
// fra i due linguaggi: tutti gli altri ne verificano un lato solo, e un errore
// di codifica degli assi passerebbe inosservato proprio perche ogni lato e
// coerente con se stesso. Se un numero non torna la pagina lo dice, invece di
// mostrare in silenzio un totale sbagliato.
function selftest() {
  const cases = META.selftest || [];
  const bad = [];
  for (const c of cases) {
    const st = Object.assign(
      { d0: 0, d1: DIM.date.n - 1, bot: null, cat: null, ver: null,
        scls: null, sec: null, rt: null, probe: 'all' }, c.f);
    const r = reduceMain(buildMasks(st));
    if (r.total !== c.h || r.totalBytes !== c.by) {
      bad.push({ filtro: JSON.stringify(c.f), attesi: c.h + ' hit / ' + c.by + ' byte',
                 ottenuti: r.total + ' hit / ' + r.totalBytes + ' byte' });
    }
  }
  const el = document.getElementById('selftest');
  if (!el) return;
  if (bad.length) {
    el.innerHTML = '<div class="note bad"><b>Controllo interno fallito su ' + bad.length
      + ' casi su ' + cases.length + '.</b> I totali calcolati nella pagina non coincidono con '
      + 'quelli calcolati in fase di aggregazione: i numeri qui sotto non sono affidabili. '
      + 'Il dettaglio e in console.</div>';
    console.error('selftest', bad);
  } else {
    console.debug('selftest: ' + cases.length + ' casi, tutti coerenti con i totali di Polars');
  }
}

// ===========================================================================
// Avvio
// ===========================================================================
initControls();
widgetTimeline(); widgetVerify(); widgetPivot(); widgetWaste();
widgetHeat(); widgetAi(); widgetAttack(); widgetUrls(); widgetStale(); widgetTops();
widgetKpi();
FS.flush(true);
selftest();
"""


# --------------------------------------------------------------------------
# assemblaggio
# --------------------------------------------------------------------------


def _kpis(meta: dict) -> str:
    """Lo scheletro. I valori li scrive `widgetKpi` a ogni cambio di filtro.

    Prima erano stampati qui e restavano fermi: erano i numeri più in vista
    della pagina, ed erano anche gli unici che non seguivano il filtro.
    """
    cards = [
        ("hits", "Richieste", f"{meta['days']} giorni"),
        ("bytes", "Byte", "trasferiti"),
        ("ips", "IP unici", "nel periodo"),
        ("urls", "URL unici", "path distinti"),
        ("probe", "Sonde e attacchi", "&nbsp;"),
        ("anomaly", "UA anomali", "browser dichiarati, comportamento da automa"),
    ]
    return "\n".join(
        f'<div class="kpi" id="kpi-{key}"><div class="lab">{label}</div>'
        f'<div class="val">–</div><div class="hint">{hint}</div></div>'
        for key, label, hint in cards
    )


def _notes(meta: dict) -> str:
    notes: list[tuple[str, str, str]] = []

    if not meta.get("assets_logged", True):
        notes.append((
            "info", "ℹ",
            "<b>Gli asset non sono nei log.</b> Nel vhost di questo sito css, js, font e immagini "
            "hanno <code>access_log off</code>: il rapporto fra HTML e asset non è calcolabile, e "
            "il tipo di risorsa descrive solo ciò che viene effettivamente registrato.",
        ))
    if not meta.get("client_ip_trusted", True):
        notes.append((
            "warn", "⚠",
            "<b>L'identità degli indirizzi IP non è verificabile su questo sito.</b> Le richieste "
            "arrivano da un proxy che non propaga l'indirizzo di origine: <code>remote_addr</code> è "
            "il nodo di bordo del proxy, non il client. Confrontarlo con i range pubblicati dai "
            "proprietari dei crawler darebbe <i>spoofed</i> per ogni bot legittimo, quindi la verifica "
            "non viene eseguita e ogni bot dichiarato resta <i>non verificabile</i>: la categoria qui "
            "è quella che lo user agent <i>dichiara</i>, non una identità provata. Per lo stesso "
            "motivo il conteggio degli IP unici e le classifiche per indirizzo descrivono i nodi del "
            "proxy, non i visitatori.",
        ))
    for path in meta.get("excluded_from_log") or []:
        notes.append((
            "info", "ℹ",
            f"<b>{path}</b> è escluso dal log dalla configurazione di nginx: il traffico su quel "
            "percorso non compare in nessuna cifra di questo report.",
        ))
    if meta.get("has_gsc"):
        notes.append((
            "info", "ℹ",
            "<b>Le impression sono aggregate per pagina.</b> Sono circa il 9% più alte del totale "
            "di proprietà che l'interfaccia di Search Console mostra: quando due URL dello stesso "
            f"sito compaiono nella stessa pagina di risultati, la proprietà conta un'impression e le "
            f"pagine ne contano due. Gli ultimi {meta.get('gsc_delay_days', 3)} giorni non sono "
            "consolidati e vanno letti come incompleti, non come un calo.",
        ))
    if meta.get("ua_anomaly_hits"):
        share = 100 * meta["ua_anomaly_hits"] / max(meta["rows"], 1)
        notes.append((
            "warn", "⚠",
            f"<b>Il {share:.1f}% delle richieste arriva da user agent che si dichiarano browser ma "
            "si comportano da automa</b>, con centinaia di richieste per singolo indirizzo. Sono "
            "conteggiate nella categoria Browser: tienine conto prima di leggere qualunque rapporto "
            "fra traffico umano e traffico automatico.".replace(".", ",", 1),
        ))
    for line in meta.get("degradation") or []:
        notes.append((
            "warn", "⚠",
            f"<b>Granularità ridotta.</b> {line}. I totali restano esatti: ciò che non è "
            "rappresentato singolarmente confluisce in righe di raccolta, tenute separate "
            "fra traffico normale e sonde così che restino esatti anche sotto filtro.",
        ))
    if meta.get("rows_unparsed"):
        notes.append((
            "info", "ℹ",
            f"<b>{meta['rows_unparsed']} righe su {_it(meta['rows_parsed_total'])} non sono "
            f"state interpretate</b> ({str(meta['unparsed_pct']).replace('.', ',')}%). Sono "
            "conservate in <code>errors/</code>, non scartate.",
        ))

    return "\n".join(
        f'<div class="note {kind}"><span class="ico">{icon}</span><div>{text}</div></div>'
        for kind, icon, text in notes
    )


def _sections(meta: dict) -> str:
    def card(title: str, caption: str, body: str, widget: str | None = None) -> str:
        state = f'<div class="wstate" id="st-{widget}"></div>' if widget else ""
        return (
            f'<div class="card"><h3>{title}</h3><p class="cap">{caption}</p>{state}{body}</div>'
        )

    # Le due sezioni su Googlebot cambiano di senso, non solo di parola, dove
    # l'identità non è verificabile: il testo lo deve dire dove sta il numero.
    ip_trusted = meta.get("client_ip_trusted", True)
    gb_what = "Googlebot verificato" if ip_trusted else "Googlebot dichiarato"
    gb_counts = (
        "Conta solo Googlebot con IP verificato, e non"
        if ip_trusted
        else "Su questo sito l'IP del client arriva da un proxy e nessuna identità è "
        "dimostrabile: si conta <b>Googlebot dichiarato</b> dallo user agent, quindi anche "
        "chi si spaccia per lui. Non"
    )

    return f"""
<section id="s-traffico">
  <h2>Traffico nel tempo</h2>
  <p class="desc">Richieste al giorno per categoria di agente. Trascina sull'asse per restringere il
     periodo: la selezione si propaga a tutti i widget che hanno la dimensione temporale.</p>
  {card("Crawl budget per categoria", "Aree impilate, una per categoria di agente.",
        '<div class="chart tall" id="c-timeline"></div>', "timeline")}
</section>

<section id="s-verifica">
  <h2>Identità dichiarata e identità verificata</h2>
  <p class="desc">Uno user agent è una stringa che il client sceglie. Qui l'identità è confrontata
     con gli IP range ufficiali e con il reverse DNS forward-confirmed. In caso di discordanza fra i
     due metodi prevale l'esito negativo.</p>
  {card("Esito della verifica per bot", "Solo i bot per cui la verifica è pertinente: i browser sono esclusi.",
        '<div class="chart tall" id="c-verify"></div>', "verify")}
</section>

<section id="s-pivot">
  <h2>Tabella pivot</h2>
  <p class="desc">La stessa selezione, letta lungo la dimensione che scegli. Il grafico segue la tabella.</p>
  <div class="card">
    <div class="row" style="display:flex;gap:12px;align-items:flex-end;margin-bottom:12px">
      <div class="f"><label for="pivotDim">Dimensione</label>
        <select id="pivotDim">
          <option value="bot">User agent</option>
          <option value="cat">Categoria</option>
          <option value="ver">Stato di verifica IP</option>
          <option value="status">Status code</option>
        </select></div>
      <div id="pivotUniqueNote" style="padding-bottom:6px"></div>
    </div>
    <div class="wstate" id="st-pivot"></div>
    <div class="grid2">
      <div id="t-pivot" class="tbl"></div>
      <div class="chart" id="c-pivot"></div>
    </div>
  </div>
</section>

<section id="s-status">
  <h2>Status code dei bot verificati</h2>
  <p class="desc">Che cosa ricevono davvero i crawler la cui identità è confermata. I 4xx e i 5xx qui
     sono crawl budget buttato via.</p>
  {card("Classi di status per bot verificato", "Solo le righe con esito VERIFIED.",
        '<div class="chart" id="c-waste"></div>', "waste")}
</section>

<section id="s-url">
  <h2>URL</h2>
  <p class="desc">Primo e ultimo hit, ultima visita di {gb_what}, click e impression da
     Search Console. Filtrabile per sezione e tipo di risorsa direttamente sulle intestazioni.</p>
  <div class="card">
    <h3>Tabella URL</h3>
    <p class="cap" id="urlCount"></p>
    <div class="wstate" id="st-urls"></div>
    <div id="t-urls" class="tbl"></div>
  </div>
</section>

<section id="s-fresh">
  <h2>Freschezza del crawl di Googlebot</h2>
  <p class="desc">Da quanto tempo Googlebot non passa sugli URL che contano. L'insieme di
     riferimento non sono tutti i percorsi visti nei log — la maggior parte se li inventano gli
     scanner, e Googlebot non ha ragione di chiederli — ma gli URL che <b>Google conosce</b>:
     quelli in sitemap, se ne è stata fornita una in <code>input/</code>, più quelli che hanno
     ricevuto impression in Search Console. {gb_counts}
     comprende Googlebot-Image, GoogleOther o AdsBot, che sono agenti distinti.</p>
  <div class="card">
    <div class="row" style="display:flex;gap:12px;align-items:flex-end;margin-bottom:12px">
      <div class="f"><label for="staleDays">Soglia</label>
        <select id="staleDays">
          <option value="14">14 giorni</option>
          <option value="30">30 giorni</option>
          <option value="60">60 giorni</option>
          <option value="90">90 giorni</option>
        </select></div>
    </div>
    <div class="wstate" id="st-stale"></div>
    <p class="cap" id="staleSummary" style="font-size:13px;line-height:1.6"></p>
    <div class="chart short" id="c-stale"></div>
  </div>
  <div class="card">
    <h3>URL in ritardo, ordinati per impression perse di vista</h3>
    <p class="cap">Più impression ha un URL, più costa che Googlebot non ci torni.</p>
    <div id="t-stale" class="tbl"></div>
  </div>
</section>

<section id="s-ai">
  <h2>Copertura dei bot AI</h2>
  <p class="desc">Quanti URL distinti raggiunge ciascun agente AI. La distinzione che conta è fra
     crawler di training, crawler per indice di risposta e fetcher innescati da un utente: sono tre
     comportamenti economicamente diversi.</p>
  {card("URL distinti raggiunti per agente AI", "Conteggio di URL, non di richieste.",
        '<div class="chart" id="c-ai"></div>', "ai")}
</section>

<section id="s-orario">
  <h2>Distribuzione oraria</h2>
  <p class="desc">Ora locale del sito, per giorno della settimana.</p>
  {card("Ora × giorno della settimana", "Intensità proporzionale alle richieste.",
        '<div class="chart" id="c-heat"></div>', "heat")}
</section>

<section id="s-sonde">
  <h2>Sonde di scanner e attacchi</h2>
  <p class="desc">Questo traffico è taggato riga per riga ed escluso di default da tutte le viste
     sopra. Qui invece è l'oggetto dell'analisi: usa il filtro «Sonde» in testa alla pagina per
     rimetterlo nel resto del report.</p>
  {card("Famiglie di sonda nel tempo", "Le otto famiglie più frequenti nel periodo selezionato.",
        '<div class="chart tall" id="c-attack"></div>', "attack")}
</section>

<section id="s-top">
  <h2>Classifiche</h2>
  <p class="desc">Clicca una riga per vederne l'andamento nel tempo.</p>
  <div class="card">
    <div class="row" style="display:flex;gap:12px;align-items:flex-end;margin-bottom:12px">
      <div class="f"><label for="topKind">Classifica</label>
        <select id="topKind">
          <option value="uri">Top URI</option>
          <option value="ua">Top user agent</option>
          <option value="ip">Top IP</option>
          <option value="referer">Top referer</option>
          <option value="status">Status code</option>
        </select></div>
      <div id="topScope" style="padding-bottom:6px"></div>
    </div>
    <div class="wstate" id="st-tops"></div>
    <div class="grid2">
      <div id="t-top" class="tbl"></div>
      <div>
        <p class="cap">Andamento di <b id="topPick"></b></p>
        <div class="chart" id="c-top"></div>
      </div>
    </div>
  </div>
</section>
"""


def _filters_bar() -> str:
    """Il filtro globale, in colonna.

    In testa alla pagina i controlli stavano su una riga sola e su uno schermo
    16:9 mangiavano l'altezza utile proprio dove servono i grafici. In colonna
    restano tutti visibili insieme, la barra ha il suo scorrimento e il
    contenuto guadagna l'altezza che prima perdeva.
    """
    groups = [
        ("Periodo", """
      <div class="frange">
        <div class="f"><label for="fFrom">Dal</label><input type="date" id="fFrom"></div>
        <div class="f"><label for="fTo">Al</label><input type="date" id="fTo"></div>
      </div>"""),
        ("Sonde", """
      <div class="f"><select id="fProbe">
        <option value="exclude" selected>escluse</option>
        <option value="all">incluse</option>
        <option value="only">solo sonde</option>
      </select></div>"""),
        ("Categoria agente", '\n      <select id="fCat" multiple size="4"></select>'),
        ("User agent", '\n      <select id="fBot" multiple size="5"></select>'),
        ("Verifica IP", '\n      <select id="fVer" multiple size="5"></select>'),
        ("Classe di status", """
      <select id="fStatus" multiple size="4">
        <option value="2">2xx</option><option value="3">3xx</option>
        <option value="4">4xx</option><option value="5">5xx</option>
      </select>"""),
        ("Sezione", '\n      <select id="fSec" multiple size="5"></select>'),
        ("Tipo risorsa", '\n      <select id="fRt" multiple size="4"></select>'),
    ]
    blocks = "\n".join(
        f'''    <div class="fgroup" data-group="{title}">
      <div class="flab">{title}<span class="fcount"></span></div>{body}
    </div>'''
        for title, body in groups
    )
    return f"""
<div class="filters">
  <div class="fhead">
    <span id="activeCount"></span>
    <button class="btn" id="btnReset">Azzera</button>
  </div>
  <div class="fbody">
{blocks}
  </div>
</div>
"""


def _fetch(url: str) -> str:
    log.info("  scarico per l'incorporamento: %s", url.rsplit("/", 1)[-1])
    response = requests.get(url, timeout=120)
    response.raise_for_status()
    return response.text


def render(
    cfg: SiteConfig,
    payload: Payload,
    *,
    inline_libs: bool = False,
    compress: bool = False,
) -> Path:
    meta = payload.data["meta"]
    start, end = meta["period"]
    filename = (
        f"log_analysis_{cfg.domain.replace('.', '_')}_"
        f"{start.replace('-', '')}-{end.replace('-', '')}.html"
    )
    out_path = PATHS.output / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Il payload viene prima, la definizione del codice dopo, e solo alla fine
    # l'avvio: il codice legge `window.__LOGAN__` alle prime righe, quindi
    # l'ordine dei tre blocchi non è indifferente.
    raw = json.dumps(payload.data, separators=(",", ":"), ensure_ascii=False)
    if compress:
        blob = base64.b64encode(gzip.compress(raw.encode("utf-8"), 9)).decode("ascii")
        data_block = f'<script id="payload" type="application/octet-stream">{blob}</script>'
        start_block = (
            "<script>\n"
            "(async () => {\n"
            "  const b64 = document.getElementById('payload').textContent;\n"
            "  const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));\n"
            "  const ds = new DecompressionStream('gzip');\n"
            "  window.__LOGAN__ = JSON.parse(\n"
            "    await new Response(new Blob([bin]).stream().pipeThrough(ds)).text());\n"
            "  __loganStart();\n"
            "})();\n"
            "</script>"
        )
        log.info(
            "  payload compresso: %.2f MB → %.2f MB in base64",
            len(raw) / 1_048_576, len(blob) / 1_048_576,
        )
    else:
        data_block = (
            '<script id="payload" type="application/json">'
            + raw.replace("</", "<\\/")
            + "</script>"
        )
        start_block = (
            "<script>window.__LOGAN__ = JSON.parse("
            "document.getElementById('payload').textContent); __loganStart();</script>"
        )

    if inline_libs:
        head_libs = (
            f"<style>{_fetch(LIBS['tabulator_css'][0])}</style>\n"
            f"<script>{_fetch(LIBS['echarts_js'][0])}</script>\n"
            f"<script>{_fetch(LIBS['tabulator_js'][0])}</script>"
        )
    else:
        head_libs = "\n".join(
            [
                f'<link rel="stylesheet" href="{LIBS["tabulator_css"][0]}" '
                f'integrity="{LIBS["tabulator_css"][1]}" crossorigin="anonymous">',
                f'<script src="{LIBS["echarts_js"][0]}" '
                f'integrity="{LIBS["echarts_js"][1]}" crossorigin="anonymous"></script>',
                f'<script src="{LIBS["tabulator_js"][0]}" '
                f'integrity="{LIBS["tabulator_js"][1]}" crossorigin="anonymous"></script>',
            ]
        )

    html = f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Analisi log {cfg.domain} · {start} → {end}</title>
{head_libs}
<style>{_css()}</style>
</head>
<body>
<div class="wrap">
  <div class="shell">
    <aside class="railcol">
      {_filters_bar()}
    </aside>

    <main>
      <header class="masthead">
        <div class="eyebrow">Analisi degli access log nginx</div>
        <h1>{cfg.domain}</h1>
        <div class="sub">
          {start} → {end} · {meta['days']} giorni · {_it(meta['rows'])} richieste ·
          ora locale {meta['tz']} · generato il {meta['generated_at'][:16].replace('T', ' ')}
        </div>
      </header>

      <nav class="toc">
        <a href="#s-traffico">Traffico</a>
        <a href="#s-verifica">Verifica identità</a>
        <a href="#s-pivot">Pivot</a>
        <a href="#s-status">Status dei bot verificati</a>
        <a href="#s-url">URL</a>
        <a href="#s-fresh">Freschezza Googlebot</a>
        <a href="#s-ai">Copertura AI</a>
        <a href="#s-orario">Distribuzione oraria</a>
        <a href="#s-sonde">Sonde e attacchi</a>
        <a href="#s-top">Classifiche</a>
      </nav>

      <div id="selftest"></div>
      <div class="wstate" id="st-kpi"></div>
      <div class="kpis">{_kpis(meta)}</div>
      <div class="notes">{_notes(meta)}</div>

      {_sections(meta)}

      <footer>
        Generato da logAnalyzer2 · payload {payload.size_bytes / 1_048_576:.2f} MB
        su un tetto di {meta['json_budget'] / 1_048_576:.0f} MB ·
        {_it(meta['unique_uas'])} user agent distinti.
      </footer>
    </main>
  </div>
</div>

{data_block}
<script>function __loganStart() {{
{_js()}
}}</script>
{start_block}
</body>
</html>
"""

    out_path.write_text(html, encoding="utf-8")
    log.info(
        "report: %s (%.2f MB)", out_path.name, out_path.stat().st_size / 1_048_576
    )
    return out_path


def _it(n: int) -> str:
    return f"{n:,}".replace(",", ".")
