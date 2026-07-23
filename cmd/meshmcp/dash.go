package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/xrey167/meshmcp/policy"
)

// auditTailer serves live summaries of a growing audit file WITHOUT re-reading
// the whole file on every poll (S21): it remembers the byte offset of the last
// complete line it folded into a policy.Accumulator and, on each call, reads
// only the bytes appended since. The first call pays one full scan; steady
// state is O(new records) per poll instead of O(file) every 2 seconds.
//
// Rotation-aware (S51): whenever it (re)starts from scratch — first poll, or
// the active file shrank because RotatingFileSink sealed it and reopened a
// fresh one — it first folds every sealed archive (<path>.<UTC timestamp>, in
// name order = chronological) and only then tails the active segment. The
// summary therefore keeps whole-ledger totals and a chain verdict seeded from
// genesis; without this, a rescan of the active segment alone would start at a
// mid-chain seq and report a healthy ledger as tampered. Safe for concurrent
// polls.
type auditTailer struct {
	mu        sync.Mutex
	path      string
	recentCap int
	acc       *policy.Accumulator
	off       int64 // bytes of the ACTIVE file folded so far
	primed    bool  // archives folded for the current accumulator generation
}

func newAuditTailer(path string, recentCap int) *auditTailer {
	return &auditTailer{path: path, recentCap: recentCap, acc: policy.NewAccumulator(recentCap)}
}

// foldArchives folds every sealed rotation archive of t.path, oldest first,
// into the accumulator. Archives are complete (fsync+close before rename), so
// every line is folded — there is no partial tail to defer.
func (t *auditTailer) foldArchives() error {
	matches, err := filepath.Glob(t.path + ".*")
	if err != nil || len(matches) == 0 {
		return err
	}
	var archives []string
	for _, m := range matches {
		if auditArchivePattern.MatchString(m) {
			archives = append(archives, m)
		}
	}
	sort.Strings(archives) // timestamp names are lexicographically chronological
	for _, a := range archives {
		if err := t.foldWholeFile(a); err != nil {
			return err
		}
	}
	return nil
}

func (t *auditTailer) foldWholeFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			t.acc.AddLine(line)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// summary folds any newly appended complete lines and snapshots the rollups.
// A partially written trailing line (a record mid-write) is left for the next
// poll rather than being misread as corruption.
func (t *auditTailer) summary() (policy.Summary, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, err := os.Open(t.path)
	if err != nil {
		return policy.Summary{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return policy.Summary{}, err
	}
	if st.Size() < t.off {
		// Truncated or rotated underneath us: start over (one full rescan,
		// archives included, then back to incremental tailing).
		t.acc = policy.NewAccumulator(t.recentCap)
		t.off = 0
		t.primed = false
	}
	if !t.primed {
		if err := t.foldArchives(); err != nil {
			return policy.Summary{}, err
		}
		t.primed = true
	}
	if _, err := f.Seek(t.off, io.SeekStart); err != nil {
		return policy.Summary{}, err
	}
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadBytes('\n')
		if err == nil {
			t.acc.AddLine(line)
			t.off += int64(len(line))
			continue
		}
		if err == io.EOF {
			break // trailing partial line (if any) waits for the next poll
		}
		return policy.Summary{}, err
	}
	return t.acc.Summary(), nil
}

// cmdDash serves the mesh control dashboard: a live, identity-attributed view
// of the audit log — per-caller call graph, policy hits, and the tamper-chain
// verdict — over a self-contained HTML page. The trace is invisible until
// someone can see it; this is what makes it visible.
func cmdDash(args []string) error {
	fs := flag.NewFlagSet("dash", flag.ContinueOnError)
	auditPath := fs.String("audit", "", "audit log (JSONL) to visualize (required)")
	addr := fs.String("addr", "127.0.0.1:9800", "listen address for the dashboard")
	recent := fs.Int("recent", 200, "number of recent events to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("meshmcp dash: --audit <file> is required")
	}

	mux := http.NewServeMux()
	registerAgentOSAssets(mux)
	// Bounded tailing read (S21): fold only newly appended records per poll
	// instead of ReadAll-ing the whole ledger every 2 seconds.
	tail := newAuditTailer(*auditPath, *recent)
	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		sum, err := tail.summary()
		if err != nil {
			status := http.StatusInternalServerError
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sum)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashHTML))
	})

	fmt.Fprintf(os.Stderr, "meshmcp dashboard on http://%s (audit: %s)\n", *addr, *auditPath)
	// Guard the dashboard like the room: a DNS-rebinding / non-loopback Host is
	// rejected, so the audit summary (identities, tools, reasons) can't be read
	// by a rebound domain or a stray LAN client. Timeouts bound Slowloris.
	return serveGracefully(newLocalHTTPServer(*addr, guardLoopback(mux, *addr)), nil)
}

const dashHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>meshmcp — agent control plane</title>
<style>
:root{--bg:#0b0e14;--panel:#141a24;--line:#232c3b;--fg:#d7e0ef;--dim:#8b98ad;--ok:#37d67a;--deny:#ff5c5c;--cosign:#ffb020;--accent:#5b8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:16px 22px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;flex-wrap:wrap}
h1{font-size:16px;margin:0;letter-spacing:.5px}.sub{color:var(--dim)}
.chain{margin-left:auto;padding:6px 12px;border-radius:6px;font-weight:600}
.chain.ok{background:rgba(55,214,122,.12);color:var(--ok);border:1px solid rgba(55,214,122,.3)}
.chain.bad{background:rgba(255,92,92,.12);color:var(--deny);border:1px solid rgba(255,92,92,.35)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;padding:18px 22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow:auto}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);margin:0 0 10px}
.kpis{display:flex;gap:18px;flex-wrap:wrap}.kpi{display:flex;flex-direction:column}.kpi b{font-size:26px}
.kpi.allow b{color:var(--ok)}.kpi.deny b{color:var(--deny)}.kpi.cosign b{color:var(--cosign)}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px}
th{color:var(--dim);font-weight:500}
.tag{padding:1px 7px;border-radius:5px;font-size:11px;font-weight:600}
.tag.allow{background:rgba(55,214,122,.14);color:var(--ok)}.tag.deny{background:rgba(255,92,92,.14);color:var(--deny)}.tag.cosign{background:rgba(255,176,32,.14);color:var(--cosign)}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;margin-top:3px}.bar>i{display:block;height:100%;background:var(--deny)}
.full{grid-column:1/-1}.mono{color:var(--dim);font-size:12px}.arrow{color:var(--accent)}
footer{padding:12px 22px;color:var(--dim);border-top:1px solid var(--line)}
</style><link rel="stylesheet" href="/assets/agent-os.css"></head><body>
<header><h1>meshmcp</h1><span class="sub">agent-to-tool control plane</span>
<span id="chain" class="chain" role="status" aria-live="polite">…</span></header>
<main class="grid">
 <div class="card"><h2>Policy decisions</h2><div class="kpis">
  <div class="kpi"><span class="mono">calls</span><b id="k-total">0</b></div>
  <div class="kpi allow"><span class="mono">allowed</span><b id="k-allow">0</b></div>
  <div class="kpi deny"><span class="mono">denied</span><b id="k-deny">0</b></div>
  <div class="kpi cosign"><span class="mono">co-sign</span><b id="k-cosign">0</b></div>
 </div></div>
 <div class="card"><h2>Identities (callers)</h2><table><thead><tr><th>peer</th><th>calls</th><th>deny</th></tr></thead><tbody id="peers"></tbody></table></div>
 <div class="card"><h2>Tools</h2><table><thead><tr><th>tool</th><th>calls</th><th>deny</th></tr></thead><tbody id="tools"></tbody></table></div>
 <div class="card full"><h2>Call graph — identity → tool</h2><table><thead><tr><th>caller</th><th></th><th>tool</th><th>backend</th><th>calls</th><th>denied</th></tr></thead><tbody id="edges"></tbody></table></div>
 <div class="card full"><h2>Recent activity</h2><table><thead><tr><th>seq</th><th>time</th><th>peer</th><th>method / tool</th><th>backend</th><th>decision</th></tr></thead><tbody id="recent"></tbody></table></div>
</main>
<footer id="foot" role="status" aria-live="polite">loading…</footer>
<script>
const $=id=>document.getElementById(id), esc=s=>(s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function denybar(d,t){const p=t?Math.round(100*d/t):0;return '<div class="bar"><i style="width:'+p+'%"></i></div>';}
async function tick(){
 let s; try{s=await (await fetch('/api/summary')).json();}catch(e){$('foot').textContent='fetch error: '+e;return;}
 const c=$('chain'); if(s.chain&&s.chain.OK){c.className='chain ok';c.textContent='✓ chain intact · '+s.chain.Count+' records';}
 else{c.className='chain bad';c.textContent='⚠ TAMPERED at seq '+(s.chain?s.chain.BreakSeq:'?');}
 $('k-total').textContent=s.records||0;$('k-allow').textContent=s.allowed||0;$('k-deny').textContent=s.denied||0;$('k-cosign').textContent=s.cosign||0;
 $('peers').innerHTML=(s.peers||[]).slice(0,12).map(p=>'<tr><td title="'+esc(p.peer_key||'')+'">'+esc(p.peer||'(none)')+'</td><td>'+p.calls+'</td><td>'+p.denied+denybar(p.denied,p.calls)+'</td></tr>').join('');
 $('tools').innerHTML=(s.tools||[]).slice(0,12).map(t=>'<tr><td>'+esc(t.tool)+'</td><td>'+t.calls+'</td><td>'+t.denied+denybar(t.denied,t.calls)+'</td></tr>').join('');
 $('edges').innerHTML=(s.edges||[]).slice(0,25).map(e=>'<tr><td>'+esc(e.peer||'(none)')+'</td><td class="arrow">→</td><td>'+esc(e.tool)+'</td><td class="mono">'+esc(e.backend)+'</td><td>'+e.calls+'</td><td>'+e.denied+'</td></tr>').join('');
 $('recent').innerHTML=(s.recent||[]).map(r=>{const d=String(r.decision||'');const cls=/^(allow|deny|cosign)$/.test(d)?d:'';const tag=d?'<span class="tag '+cls+'">'+esc(d)+'</span>':'';return '<tr><td class="mono">'+r.seq+'</td><td class="mono">'+esc(r.time)+'</td><td>'+esc(r.peer||'(none)')+'</td><td>'+esc(r.tool||r.method)+'</td><td class="mono">'+esc(r.backend)+'</td><td>'+tag+(r.reason?' <span class="mono">'+esc(r.reason)+'</span>':'')+'</td></tr>';}).join('');
 $('foot').textContent='backends: '+((s.backends||[]).join(', ')||'none')+' · refreshed';
}
tick();setInterval(tick,2000);
</script></body></html>`
