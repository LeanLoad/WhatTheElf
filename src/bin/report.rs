//! `report` — render the case/crash catalog (and any `check` results) to a
//! self-contained HTML page, plus a machine-readable `crashes.json`.
//!
//! The Rust definitions (`cases::ALL`, `crashes::ALL`) are the single source of
//! truth; this just projects them. Usage: `report [OUT_DIR]` (default
//! `gh-pages`, the published-site worktree; see `deploy.sh`).
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::Path;

use whattheelf::crash::{Crash, Loader, Signal};
use whattheelf::{cases, crashes};

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::env::args().nth(1).unwrap_or_else(|| "gh-pages".to_string());
    let out = root.join(out);
    fs::create_dir_all(&out)?;

    let results = read_results(&root.join("results").join("summary.tsv"));
    let html = render_html(root, &results);
    fs::write(out.join("index.html"), html)?;
    fs::write(out.join("crashes.json"), crashes_json(root))?;
    println!("wrote {}/index.html", out.display());
    println!("wrote {}/crashes.json", out.display());

    // Every unexpected backend×case outcome (crash/hang/error), if check has run.
    if !results.is_empty() {
        fs::write(out.join("findings.json"), findings_json(&results))?;
        println!("wrote {}/findings.json", out.display());
        // Copy the raw captured stdout/stderr into the site so the matrix can
        // fetch the exact file for a clicked cell.
        let copied = copy_streams(root, &out, &results)?;
        println!("copied {copied} output streams to {}/results/", out.display());
    }
    Ok(())
}

// ---- results matrix ------------------------------------------------------

/// One backend×case outcome from results/summary.tsv.
#[derive(Default)]
struct Cell {
    category: String,
    status: String,
    finding: String,
}

/// (backend, case) -> outcome, parsed from results/summary.tsv if present.
/// Columns: backend, case, category, status, json, note, finding.
type Results = BTreeMap<(String, String), Cell>;

fn read_results(path: &Path) -> Results {
    let mut map = Results::new();
    let Ok(text) = fs::read_to_string(path) else {
        return map;
    };
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() >= 3 {
            let finding = f.get(6).filter(|s| !s.is_empty()).or_else(|| f.get(5));
            map.insert(
                (f[0].to_string(), f[1].to_string()),
                Cell {
                    category: f[2].to_string(),
                    status: f.get(3).unwrap_or(&"").to_string(),
                    finding: finding.unwrap_or(&"").to_string(),
                },
            );
        }
    }
    map
}

// ---- JSON export ---------------------------------------------------------

fn crashes_json(root: &Path) -> String {
    let arr: Vec<_> = crashes::ALL
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "loader": c.loader.name(),
                "signal": c.signal.name(),
                "site": c.site,
                "repro": c.repro.name(),
                "details": c.details,
                "bytes": fixture_len(root, c.id),
            })
        })
        .collect();
    serde_json::to_string_pretty(&arr).unwrap_or_default()
}

fn findings_json(results: &Results) -> String {
    let arr: Vec<_> = results
        .iter()
        .filter(|(_, cell)| is_unexpected(&cell.category))
        .map(|((backend, case), cell)| {
            serde_json::json!({
                "backend": backend,
                "case": case,
                "category": cell.category,
                "status": cell.status,
                "finding": cell.finding,
            })
        })
        .collect();
    serde_json::to_string_pretty(&arr).unwrap_or_default()
}

/// Copy each cell's captured `results/<backend>/<case>.{stdout,stderr}` into
/// `<out>/results/...` so the matrix can fetch the exact file on click. Returns
/// the number of stream files copied.
fn copy_streams(root: &Path, out: &Path, results: &Results) -> Result<usize, Box<dyn Error>> {
    // Mirror cleanly: drop any stale streams (e.g. a renamed/removed backend).
    let _ = fs::remove_dir_all(out.join("results"));
    let mut n = 0;
    for (backend, case) in results.keys() {
        let dst_dir = out.join("results").join(backend);
        fs::create_dir_all(&dst_dir)?;
        for ext in ["stdout", "stderr"] {
            let name = format!("{case}.{ext}");
            let src = root.join("results").join(backend).join(&name);
            if src.is_file() {
                fs::copy(&src, dst_dir.join(&name))?;
                n += 1;
            }
        }
    }
    Ok(n)
}

fn fixture_len(root: &Path, id: &str) -> u64 {
    fs::metadata(root.join("fixtures").join(id))
        .map(|m| m.len())
        .unwrap_or(0)
}

// ---- HTML ----------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn render_html(root: &Path, results: &Results) -> String {
    let mut h = String::new();
    let glibc = crashes::ALL.iter().filter(|c| c.loader == Loader::Glibc).count();
    let musl = crashes::ALL.iter().filter(|c| c.loader == Loader::Musl).count();

    h.push_str("<!doctype html><html lang=en><head><meta charset=utf-8>");
    h.push_str("<meta name=viewport content=\"width=device-width,initial-scale=1\">");
    h.push_str("<title>WhatTheElf — loader fuzzing report</title>");
    h.push_str(STYLE);
    h.push_str("</head><body><main>");
    h.push_str("<h1>WhatTheElf — dynamic-loader fuzzing report</h1>");
    h.push_str(&summary(glibc, musl, results));

    // Crashes, grouped by loader.
    h.push_str("<h2>Loader crashes</h2>");
    for (loader, label) in [
        (Loader::Glibc, "glibc — ld.so --preload exitfirst.so (full load)"),
        (Loader::Musl, "musl — ld-musl --list"),
    ] {
        h.push_str(&format!("<h3>{}</h3>", esc(label)));
        h.push_str("<table class=crashes><thead><tr><th>id<th>signal<th>fault site<th>bytes<th>details</tr></thead><tbody>");
        for c in crashes::ALL.iter().filter(|c| c.loader == loader) {
            h.push_str(&crash_row(root, c));
        }
        h.push_str("</tbody></table>");
    }

    // Unexpected outcomes across all backends (from the results matrix).
    if !results.is_empty() {
        h.push_str(&render_findings(results));
    }

    // Backend results matrix (only if check has been run).
    if !results.is_empty() {
        h.push_str("<h2>Backend results</h2>");
        h.push_str(&results_table(results));
    } else {
        h.push_str("<h2>Backend results</h2><p class=muted>No <code>results/summary.tsv</code> \
                    yet — run <code>./check.sh</code> then regenerate.</p>");
    }

    // Structural cases.
    h.push_str("<h2>Structural cases</h2>");
    h.push_str("<table class=cases><thead><tr><th>id<th>tags<th>summary</tr></thead><tbody>");
    for case in cases::ALL {
        let tags: Vec<_> = case.tags.iter().map(|t| t.name()).collect();
        h.push_str(&format!(
            "<tr><td class=mono>{}</td><td class=tags>{}</td><td>{}</td></tr>",
            esc(case.id),
            esc(&tags.join(", ")),
            esc(case.summary),
        ));
    }
    h.push_str("</tbody></table>");

    h.push_str("<footer>Generated by <code>report</code> from <code>cases::ALL</code> / \
                <code>crashes::ALL</code>. Machine-readable: <code>crashes.json</code>.</footer>");
    h.push_str("</main></body></html>");
    h
}

/// The "Findings" abstract that opens the page: dynamic counts plus the
/// qualitative takeaways from the run.
fn summary(glibc: usize, musl: usize, results: &Results) -> String {
    let n_struct = cases::ALL.len();
    let n_crash = crashes::ALL.len();
    let crash_count = |b: &str| {
        results
            .iter()
            .filter(|((bk, _), c)| bk == b && c.category == "crash")
            .count()
    };
    let backends: BTreeSet<&str> = results.keys().map(|(b, _)| b.as_str()).collect();
    let unexpected: usize = results.values().filter(|c| is_unexpected(&c.category)).count();

    let mut h = String::from("<section class=abstract><h2>Findings</h2>");
    h.push_str(&format!(
        "<p>WhatTheElf feeds deliberately malformed ELF files to the <b>glibc</b> and \
         <b>musl</b> dynamic loaders — fuzzed with AFL++ — and through a panel of ELF tools, \
         looking for inputs that <em>crash</em> rather than cleanly accept or reject. \
         Alongside <b>{n_struct}</b> hand-written structural cases, <b>{n_crash}</b> are \
         fuzzer-found loader crashes (<b>{glibc}</b> glibc, <b>{musl}</b> musl), each reduced \
         to one representative per fault site and confirmed to reproduce on the stock system \
         loaders.</p>"
    ));
    h.push_str(
        "<p>The headline: cheap header validation turns these away — glibc's \
         <code>--verify</code> rejects them all cleanly — but <b>actually mapping and \
         relocating a hostile object, which is what any real load does, crashes both \
         loaders</b>. The crashes span the whole pipeline — segment mapping and \
         <code>.bss</code> zero-fill, symbol resolution, REL/RELA/RELR relocation, dependency \
         loading, and TLS setup. One input, <code>glibc_dyn_lsoname_oob</code> — a \
         <code>PT_DYNAMIC</code> whose entry walk runs off into unmapped memory — crashes \
         <b>glibc, musl, and llvm-objdump</b> alike.</p>",
    );
    if !results.is_empty() {
        h.push_str(&format!(
            "<p>Across all <b>{}</b> backends, <b>{unexpected}</b> backend×case runs ended in a \
             crash (everything else cleanly accepted or rejected). <b>qemu-user</b> is the least \
             hardened — its own pre-launch ELF loader crashes or asserts on <b>{}</b> inputs (a \
             GLib out-of-memory abort, a <code>pgb_dynamic</code> assertion); even \
             <code>llvm-objdump</code> segfaults on <b>{}</b>. The strict validators \
             (<code>eu-elflint</code>, kernel <code>execve</code>) and lenient scanners never \
             crash.</p>",
            backends.len(),
            crash_count("qemu-x86_64"),
            crash_count("llvm-objdump"),
        ));
    }
    h.push_str(
        "<p class=muted>The loaders are exercised <em>non-executing</em> — glibc \
         <code>ld.so --verify</code> / <code>--preload</code> (an exit-lib that stops after \
         relocation) and <code>ld-musl --list</code> — so we fuzz the loader, not the loaded \
         program. Crash catalogue, all unexpected outcomes, and the full backend×case matrix \
         (click any cell for its stdout/stderr) follow.</p>",
    );
    h.push_str("</section>");
    h
}

fn crash_row(root: &Path, c: &Crash) -> String {
    let sigcls = match c.signal {
        Signal::Segv => "sig-segv",
        Signal::Bus => "sig-bus",
    };
    format!(
        "<tr><td class=mono>{id}</td>\
         <td><span class=\"badge {sigcls}\">{sig}</span></td>\
         <td class=mono>{site}</td>\
         <td class=num>{bytes}</td>\
         <td class=details>{details}</td></tr>",
        id = esc(c.id),
        sig = c.signal.name(),
        site = esc(c.site),
        bytes = fixture_len(root, c.id),
        details = esc(c.details),
    )
}

/// Every backend×case where a backend did something *unexpected* — crashed,
/// hung, or errored out, as opposed to cleanly accepting or rejecting the input.
/// This documents the findings the matrix would otherwise bury, including ones
/// outside the curated `crashes::ALL` (e.g. tool crashes, or structural cases
/// that also crash a loader).
fn render_findings(results: &Results) -> String {
    let mut by_backend: BTreeMap<&str, Vec<(&str, &Cell)>> = BTreeMap::new();
    for ((b, case), cell) in results {
        if is_unexpected(&cell.category) {
            by_backend
                .entry(b.as_str())
                .or_default()
                .push((case.as_str(), cell));
        }
    }
    let mut h = String::from("<h2>Unexpected outcomes</h2>");
    if by_backend.is_empty() {
        h.push_str("<p class=muted>None — every backend cleanly accepted or rejected each input.</p>");
        return h;
    }
    let total: usize = by_backend.values().map(Vec::len).sum();
    h.push_str(&format!(
        "<p class=lede><b>{total}</b> backend×case outcomes where a backend crashed, hung, or \
         errored (everything else was a clean accept/reject). Loaders faulting are the headline; \
         tool crashes (e.g. <code>llvm-objdump</code>) and qemu-user dying in its own pre-launch \
         loader are surfaced here too. Red = crash.</p>"
    ));
    h.push_str("<table class=findings><thead><tr><th>backend<th>n<th>cases (hover for the finding)</tr></thead><tbody>");
    for (b, cases) in &by_backend {
        let mut cells = String::new();
        for (case, cell) in cases {
            cells.push_str(&format!(
                "<span class=\"badge {}\" title=\"{}\">{}</span> ",
                cat_class(&cell.category),
                attr(&format!("{} — {}", cell.status, cell.finding)),
                esc(case)
            ));
        }
        h.push_str(&format!(
            "<tr><td class=mono>{}</td><td class=num>{}</td><td class=findcell>{}</td></tr>",
            esc(b),
            cases.len(),
            cells
        ));
    }
    h.push_str("</tbody></table>");
    h
}

/// True for outcomes that are *not* a clean accept/reject.
fn is_unexpected(category: &str) -> bool {
    let c = category.to_ascii_lowercase();
    c.contains("crash") || c.contains("timeout") || c.contains("hang") || c.contains("tool-error")
}

/// Escape a string for use inside a double-quoted HTML attribute.
fn attr(s: &str) -> String {
    esc(s).replace('"', "&quot;")
}

fn results_table(results: &Results) -> String {
    let backends: BTreeSet<&str> = results.keys().map(|(b, _)| b.as_str()).collect();
    let cases: BTreeSet<&str> = results.keys().map(|(_, c)| c.as_str()).collect();

    // Sticky detail panel filled by clicking a cell.
    let mut h = String::from(
        "<p class=muted>Hover a cell for the backend's message; click it for the full finding below.</p>\
         <div id=detail class=detail><span class=muted>Click a cell to see backend · case · status · finding.</span></div>",
    );
    h.push_str("<div class=scroll><table class=matrix><thead><tr><th>case</th>");
    for b in &backends {
        h.push_str(&format!("<th>{}</th>", esc(b)));
    }
    h.push_str("</tr></thead><tbody>");
    for case in &cases {
        h.push_str(&format!("<tr><td class=mono>{}</td>", esc(case)));
        for b in &backends {
            match results.get(&(b.to_string(), case.to_string())) {
                Some(cell) => {
                    let tip = format!("{} — {}", cell.status, cell.finding);
                    h.push_str(&format!(
                        "<td class=\"cell {cls}\" title=\"{tip}\" \
                         data-b=\"{b}\" data-c=\"{c}\" data-cat=\"{cat}\" data-st=\"{st}\" data-f=\"{f}\">{cat}</td>",
                        cls = cat_class(&cell.category),
                        tip = attr(&tip),
                        b = attr(b),
                        c = attr(case),
                        cat = attr(&cell.category),
                        st = attr(&cell.status),
                        f = attr(&cell.finding),
                    ));
                }
                None => h.push_str("<td class=cell></td>"),
            }
        }
        h.push_str("</tr>");
    }
    h.push_str("</tbody></table></div>");
    h.push_str(MATRIX_JS);
    h
}

fn cat_class(cat: &str) -> &'static str {
    let c = cat.to_ascii_lowercase();
    if c.contains("crash") {
        "c-crash"
    } else if c.contains("hang") || c.contains("timeout") {
        "c-hang"
    } else if c.contains("error") || c.contains("reject") {
        "c-reject"
    } else if c.contains("accept") || c.contains("ok") || c.contains("clean") {
        "c-accept"
    } else {
        "c-other"
    }
}

const STYLE: &str = "<style>\
:root{color-scheme:light dark}\
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1a1a1a}\
main{max-width:1100px;margin:0 auto;padding:2rem 1.25rem}\
h1{font-size:1.6rem;margin:0 0 .3rem}h2{margin:2rem 0 .6rem;border-bottom:2px solid #ddd;padding-bottom:.2rem}\
h3{margin:1.2rem 0 .4rem;color:#444}\
.lede{color:#555;font-size:1.05rem}.muted{color:#888}\
.abstract{background:#fff;border:1px solid #e3e3e8;border-left:4px solid #36c;border-radius:6px;padding:.6rem 1.25rem 1rem;margin:1.25rem 0}\
.abstract h2{margin:.6rem 0 .4rem;border:0}.abstract p{margin:.55rem 0;font-size:1.02rem;line-height:1.55}\
table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.06);font-size:.92rem}\
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #eee;vertical-align:top}\
th{background:#fafafa;font-weight:600;font-size:.82rem;text-transform:uppercase;letter-spacing:.03em;color:#666}\
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86rem;white-space:nowrap}\
.details{color:#333;font-size:.88rem}.tags{color:#777;font-size:.85rem;white-space:nowrap}\
.num{text-align:right;font-variant-numeric:tabular-nums;color:#666}\
.badge{display:inline-block;padding:.05rem .45rem;border-radius:99px;font-size:.78rem;font-weight:600;white-space:nowrap}\
.sig-segv{background:#fde2e1;color:#a11}.sig-bus{background:#fff0d6;color:#a60}\
.findcell{line-height:2.1}.findings .badge{font-family:ui-monospace,monospace}\
.scroll{overflow-x:auto}.matrix td,.matrix th{white-space:nowrap}\
.cell{text-align:center;font-size:.78rem}\
.c-crash{background:#fde2e1;color:#a11;font-weight:600}.c-hang{background:#fff0d6;color:#a60}\
.c-reject{background:#dcefe0;color:#176}.c-accept{background:#dde7fb;color:#249}.c-other{color:#999}\
td.cell{cursor:pointer}td.cell.sel{outline:2px solid #36c;outline-offset:-2px}\
.detail{position:sticky;top:0;z-index:5;background:#fff;border:1px solid #ddd;border-radius:6px;padding:.6rem .8rem;margin:.5rem 0;box-shadow:0 2px 6px rgba(0,0,0,.08)}\
.detail pre{white-space:pre-wrap;word-break:break-word;margin:.4rem 0 0;font-size:.82rem;color:#333;max-height:240px;overflow:auto}\
.stream{margin-top:.5rem}.slabel{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#888;font-weight:600}\
.detail .stream pre{background:#0d1117;color:#c9d1d9;border-radius:5px;padding:.5rem .6rem;font-family:ui-monospace,Menlo,Consolas,monospace}\
footer{margin:2rem 0 1rem;color:#999;font-size:.85rem}\
code{background:#eef0f2;padding:.05rem .3rem;border-radius:4px;font-size:.85em}\
</style>";

/// Click-to-expand for matrix cells: show backend·case·status·finding, then
/// fetch the cell's raw results/<backend>/<case>.{stdout,stderr} and append them.
const MATRIX_JS: &str = "<script>\
(function(){\
var d=document.getElementById('detail');\
function e(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}\
function k(c){c=(c||'').toLowerCase();return c.indexOf('crash')>=0?'c-crash':(c.indexOf('hang')>=0||c.indexOf('timeout')>=0)?'c-hang':(c.indexOf('error')>=0||c.indexOf('reject')>=0)?'c-reject':c.indexOf('accept')>=0?'c-accept':'c-other';}\
function get(p){return fetch(p).then(function(r){return r.ok?r.text():'';}).catch(function(){return '';});}\
function block(label,path,v){return (v&&v.trim())?'<div class=stream><span class=slabel>'+label+' <a href=\"'+path+'\">raw</a></span><pre>'+e(v)+'</pre></div>':'';}\
document.querySelectorAll('td.cell[data-b]').forEach(function(td){\
td.addEventListener('click',function(){\
var s=td.dataset;var dir='results/'+encodeURIComponent(s.b)+'/'+encodeURIComponent(s.c);\
var head='<b>'+e(s.c)+'</b> &middot; <span class=mono>'+e(s.b)+'</span> &middot; <span class=\"badge '+k(s.cat)+'\">'+e(s.cat)+'</span> <span class=muted>'+e(s.st)+'</span><pre>'+e(s.f||'(no message captured)')+'</pre>';\
d.innerHTML=head+'<p class=muted>loading output…</p>';\
document.querySelectorAll('td.cell.sel').forEach(function(x){x.classList.remove('sel');});\
td.classList.add('sel');\
Promise.all([get(dir+'.stdout'),get(dir+'.stderr')]).then(function(r){\
var body=block('stdout',dir+'.stdout',r[0])+block('stderr',dir+'.stderr',r[1]);\
d.innerHTML=head+(body||'<p class=muted>(no captured output)</p>');\
});\
});\
});\
})();\
</script>";
