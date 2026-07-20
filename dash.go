package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/xrey167/meshmcp/policy"
)

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
	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(*auditPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		sum, err := policy.Analyze(f, *recent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
	return newLocalHTTPServer(*addr, guardLoopback(mux, *addr)).ListenAndServe()
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
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow:hidden}
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
</style></head><body>
<header><h1>meshmcp</h1><span class="sub">agent-to-tool control plane</span>
<span id="chain" class="chain">…</span></header>
<section class="grid">
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
</section>
<footer id="foot">loading…</footer>
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
 $('recent').innerHTML=(s.recent||[]).map(r=>{const d=r.decision||'';const tag=d?'<span class="tag '+d+'">'+d+'</span>':'';return '<tr><td class="mono">'+r.seq+'</td><td class="mono">'+esc(r.time)+'</td><td>'+esc(r.peer||'(none)')+'</td><td>'+esc(r.tool||r.method)+'</td><td class="mono">'+esc(r.backend)+'</td><td>'+tag+(r.reason?' <span class="mono">'+esc(r.reason)+'</span>':'')+'</td></tr>';}).join('');
 $('foot').textContent='backends: '+((s.backends||[]).join(', ')||'none')+' · refreshed';
}
tick();setInterval(tick,2000);
</script></body></html>`
