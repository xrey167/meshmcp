package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"meshmcp/policy"
)

// cmdRoom serves the meshmcp Control Room: a live, identity-attributed web view
// of the whole fabric — server tiles, per-identity app activity, a streaming
// decision feed, and the tamper-chain verdict — over a running gateway's audit
// log. Where `dash` is a compact panel, the room is the operations surface you
// leave open on a screen while agents work.
func cmdRoom(args []string) error {
	fs := flag.NewFlagSet("room", flag.ContinueOnError)
	auditPath := fs.String("audit", "", "audit log (JSONL) the gateway writes (required)")
	addr := fs.String("addr", "127.0.0.1:9900", "listen address for the control room")
	recent := fs.Int("recent", 120, "live-feed events to keep")
	title := fs.String("title", "meshmcp control room", "page title / header")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("meshmcp room: --audit <file> is required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/room", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(*auditPath)
		if err != nil {
			// No log yet is normal before the first call — return an empty room.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(policy.Summary{})
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
	mux.HandleFunc("/api/title", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"title": *title})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(roomHTML))
	})

	fmt.Fprintf(os.Stderr, "meshmcp control room on http://%s (audit: %s)\n", *addr, *auditPath)
	return http.ListenAndServe(*addr, mux)
}

const roomHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>meshmcp — control room</title>
<style>
:root{--bg:#0a0d13;--panel:#12161f;--panel2:#171c27;--line:#232c3b;--fg:#dce4f2;--dim:#8a97ad;--faint:#67728a;
--accent:#5b8cff;--ok:#37d67a;--deny:#ff5c5c;--warn:#ffb020;--label:#c07bff}
@media(prefers-color-scheme:light){:root{--bg:#eef1f7;--panel:#fff;--panel2:#e7ecf5;--line:#d6ddea;--fg:#101725;
--dim:#586179;--faint:#8a93a8;--accent:#2f5fe0;--ok:#128a45;--deny:#cf3636;--warn:#a9700a;--label:#8536e6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,"SF Mono",Menlo,Consolas,monospace}
header{display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font-size:15px;margin:0;letter-spacing:-.01em;display:flex;align-items:center;gap:9px}
h1 .dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 22%,transparent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.chain{padding:5px 11px;border-radius:6px;font-size:12px;font-weight:600}
.chain.ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 12%,transparent);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.chain.bad{color:var(--deny);background:color-mix(in srgb,var(--deny) 12%,transparent);border:1px solid color-mix(in srgb,var(--deny) 35%,transparent)}
.spacer{margin-left:auto}
.kpis{display:flex;gap:22px}.kpi{display:flex;flex-direction:column;align-items:flex-end}
.kpi b{font-size:22px;font-variant-numeric:tabular-nums}.kpi span{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em}
.kpi.a b{color:var(--ok)}.kpi.d b{color:var(--deny)}.kpi.c b{color:var(--warn)}
main{display:grid;grid-template-columns:1.5fr 1fr;gap:14px;padding:16px 20px}
@media(max-width:900px){main{grid-template-columns:1fr}}
.col{display:flex;flex-direction:column;gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card h2{font-size:11px;text-transform:uppercase;letter-spacing:.13em;color:var(--dim);margin:0 0 12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}
.tile{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 12px;position:relative;overflow:hidden}
.tile.live::after{content:"";position:absolute;top:9px;right:9px;width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.tile .n{font-weight:600;font-size:13px;display:flex;justify-content:space-between;align-items:center;gap:6px}
.tile .meta{color:var(--faint);font-size:11px;margin-top:2px}
.tile .bar{height:5px;border-radius:3px;background:var(--line);overflow:hidden;margin-top:9px;display:flex}
.tile .bar i{display:block;height:100%}.tile .bar .ia{background:var(--ok)}.tile .bar .id{background:var(--deny)}.tile .bar .ic{background:var(--warn)}
.tile .tags{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.tg{font-size:9.5px;padding:1px 6px;border-radius:20px;border:1px solid transparent}
.tg.secret{color:var(--label);border-color:color-mix(in srgb,var(--label) 34%,transparent)}
.tg.cosign{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)}
.tg.taint{color:var(--deny);border-color:color-mix(in srgb,var(--deny) 38%,transparent)}
.tg.label{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 34%,transparent)}
.idlist{display:flex;flex-direction:column;gap:8px}
.id{display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--panel2);border:1px solid var(--line);border-radius:9px}
.id .av{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;font-size:12px;font-weight:700;color:#fff;flex:none}
.id .info{flex:1;min-width:0}.id .nm{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.id .sub{color:var(--faint);font-size:11px}
.id .cnt{text-align:right;font-size:11px;color:var(--dim);white-space:nowrap}
.id .cnt b{color:var(--fg);font-size:15px;display:block;font-variant-numeric:tabular-nums}
.feed{max-height:60vh;overflow-y:auto;display:flex;flex-direction:column;gap:0}
.ev{display:grid;grid-template-columns:56px 1fr auto;gap:10px;padding:7px 4px;border-top:1px solid var(--line);align-items:center;font-size:12.5px}
.ev:first-child{border-top:0}
.ev.new{animation:flash 1.2s ease-out}
@keyframes flash{0%{background:color-mix(in srgb,var(--accent) 16%,transparent)}100%{background:transparent}}
.ev .t{color:var(--faint);font-size:11px;font-variant-numeric:tabular-nums}
.ev .who{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev .who .pe{color:var(--fg)}.ev .who .to{color:var(--accent)}.ev .who .be{color:var(--faint);font-size:11px}
.ev .who .rs{color:var(--faint);font-size:11px}
.pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:20px;text-transform:uppercase;letter-spacing:.04em}
.pill.allow{color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent)}
.pill.deny{color:var(--deny);background:color-mix(in srgb,var(--deny) 14%,transparent)}
.pill.cosign{color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent)}
.empty{color:var(--faint);padding:20px;text-align:center}
.foot{padding:8px 20px;color:var(--faint);font-size:11px;border-top:1px solid var(--line)}
</style></head><body>
<header>
  <h1><span class="dot"></span> meshmcp <span style="color:var(--dim)">· control room</span></h1>
  <span id="chain" class="chain">…</span>
  <div class="spacer"></div>
  <div class="kpis">
    <div class="kpi"><b id="k-total">0</b><span>calls</span></div>
    <div class="kpi a"><b id="k-allow">0</b><span>allow</span></div>
    <div class="kpi d"><b id="k-deny">0</b><span>deny</span></div>
    <div class="kpi c"><b id="k-cosign">0</b><span>co-sign</span></div>
  </div>
</header>
<main>
  <div class="col">
    <div class="card"><h2>Servers · MCP backends on the mesh</h2><div class="tiles" id="tiles"></div></div>
    <div class="card"><h2>Live decision feed</h2><div class="feed" id="feed"><div class="empty">waiting for traffic…</div></div></div>
  </div>
  <div class="col">
    <div class="card"><h2>Identities · agent apps</h2><div class="idlist" id="ids"></div></div>
  </div>
</main>
<div class="foot" id="foot">connecting…</div>
<script>
var $=function(id){return document.getElementById(id)};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function hue(s){var h=0;for(var i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))%360;return h}
function ago(ts){if(!ts)return '';var d=(Date.now()-Date.parse(ts))/1000;if(isNaN(d))return '';
  if(d<2)return 'now';if(d<60)return Math.floor(d)+'s';if(d<3600)return Math.floor(d/60)+'m';return Math.floor(d/3600)+'h'}
function hhmmss(ts){var d=new Date(ts);if(isNaN(d))return '';return d.toTimeString().slice(0,8)}
// governance tags per backend, inferred from its recent events
function tags(be,recent){var t={};recent.forEach(function(r){if(r.backend!==be)return;
  if(r.method==='secrets/inject')t.secret=1;if(r.decision==='cosign')t.cosign=1;
  var rs=(r.reason||'');if(/tainted/.test(rs))t.taint=1;if(/label/.test(rs))t.label=1;});
  var out='';if(t.secret)out+='<span class="tg secret">🔑 secret</span>';if(t.cosign)out+='<span class="tg cosign">co-sign</span>';
  if(t.taint)out+='<span class="tg taint">taint</span>';if(t.label)out+='<span class="tg label">labels</span>';return out}
var seenSeq=0, firstLoad=true;
function tick(){
  fetch('/api/room').then(function(r){return r.json()}).then(function(s){
    var c=$('chain');
    if(!s.records){c.className='chain';c.textContent='no records yet';}
    else if(s.chain&&s.chain.OK){c.className='chain ok';c.textContent='✓ chain intact · '+s.chain.Count;}
    else{c.className='chain bad';c.textContent='⚠ TAMPERED @ seq '+(s.chain?s.chain.BreakSeq:'?');}
    $('k-total').textContent=s.records||0;$('k-allow').textContent=s.allowed||0;$('k-deny').textContent=s.denied||0;$('k-cosign').textContent=s.cosign||0;
    var recent=s.recent||[];
    // server tiles
    $('tiles').innerHTML=(s.backend_stats||[]).map(function(b){
      var live=b.last_seen&&(Date.now()-Date.parse(b.last_seen)<4000);
      var tot=b.calls||1;
      return '<div class="tile'+(live?' live':'')+'">'+
        '<div class="n">'+esc(b.backend)+'</div>'+
        '<div class="meta">'+b.calls+' calls · '+b.peers+' caller(s) · '+ago(b.last_seen)+'</div>'+
        '<div class="bar"><i class="ia" style="width:'+(100*b.allowed/tot)+'%"></i><i class="ic" style="width:'+(100*b.cosign/tot)+'%"></i><i class="id" style="width:'+(100*b.denied/tot)+'%"></i></div>'+
        '<div class="tags">'+tags(b.backend,recent)+'</div></div>';
    }).join('')||'<div class="empty">no servers seen yet</div>';
    // identities
    $('ids').innerHTML=(s.peers||[]).map(function(p){
      var nm=p.peer||p.peer_key||'(unknown)';var h=hue(nm);
      return '<div class="id"><div class="av" style="background:hsl('+h+',55%,45%)">'+esc((nm[0]||'?').toUpperCase())+'</div>'+
        '<div class="info"><div class="nm">'+esc(nm)+'</div><div class="sub">'+(p.last_tool?esc(p.last_tool)+' · ':'')+ago(p.last_seen)+' · '+p.denied+' denied</div></div>'+
        '<div class="cnt"><b>'+p.calls+'</b>calls</div></div>';
    }).join('')||'<div class="empty">no identities yet</div>';
    // live feed (recent is newest-first)
    if(recent.length){
      $('feed').innerHTML=recent.map(function(r){
        var isNew=!firstLoad&&r.seq>seenSeq;
        var who='<span class="pe">'+esc(r.peer||'(none)')+'</span> → <span class="to">'+esc(r.tool||r.method)+'</span> <span class="be">@'+esc(r.backend)+'</span>'+(r.reason?' <span class="rs">'+esc(r.reason)+'</span>':'');
        return '<div class="ev'+(isNew?' new':'')+'"><span class="t">'+hhmmss(r.time)+'</span><span class="who">'+who+'</span><span class="pill '+(r.decision||'')+'">'+(r.decision||'')+'</span></div>';
      }).join('');
      seenSeq=recent[0].seq;firstLoad=false;
    }
    var bes=(s.backends||[]).join(', ');
    $('foot').textContent='backends: '+(bes||'none')+' · '+((s.peers||[]).length)+' identities · live';
  }).catch(function(e){$('foot').textContent='fetch error: '+e});
}
fetch('/api/title').then(function(r){return r.json()}).then(function(t){if(t.title){document.title=t.title;}}).catch(function(){});
tick();setInterval(tick,1000);
</script></body></html>`
