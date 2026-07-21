package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// cmdApprovals serves the co-sign approver: a mesh service that lists held
// require_cosign calls and lets a human approve or deny them. It is the human
// side of the agent firewall — and the natural home for a phone. Run it over
// the mesh and the approver is resolved from the caller's WireGuard identity,
// so "who approved" is cryptographic and lands in the audit as that identity.
//
//	meshmcp approvals --store ./cosign            # served on the mesh (identity-aware)
//	meshmcp approvals --store ./cosign --addr :9700  # local, for testing
func cmdApprovals(args []string) error {
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	o := meshFlags(fs)
	store := fs.String("store", "", "co-sign store directory (matches the backend's cosign_store) (required)")
	port := fs.Int("port", 9700, "mesh port to serve on")
	addr := fs.String("addr", "", "bind a plain local address instead of the mesh (dev/testing)")
	ttlSec := fs.Int("ttl", 0, "drop pending requests older than this many seconds (0 = never)")
	var approvers stringList
	fs.Var(&approvers, "approver", "identity allowed to approve (FQDN glob or 'pubkey:<key>'); repeatable; REQUIRED in mesh mode")
	devices := fs.String("devices", "", "directory to persist push-wake device tokens (enables /v1/devices + notify on new pendings)")
	notifyWebhook := fs.String("notify-webhook", "", "POST push-wake notifications to this URL instead of logging them (needs --devices; the endpoint fans out to APNs/FCM with its own credentials)")
	approvalKey := fs.String("approval-key", "", "Ed25519 key file shared with the gateway; when set, /v1/approve mints signed, single-use, argument-bound approvals (must match the backend's approval_signing_key)")
	ttlApprovalSec := fs.Int("approval-ttl", 0, "TTL in seconds for a minted request-bound approval (0 = default 5m, capped at 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store == "" {
		return fmt.Errorf("meshmcp approvals: --store <dir> is required")
	}
	// Fail closed: on the mesh, a mandatory approver ACL identifies who may
	// approve/deny. An empty ACL must NOT mean "any mesh peer may approve" — that
	// would let a low-privilege agent self-authorize its own held call. Require
	// at least one --approver in mesh mode (the local --addr dev listener uses a
	// fixed operator identity and is not a mesh administrative endpoint).
	if *addr == "" && len(approvers) == 0 {
		return fmt.Errorf("meshmcp approvals: --approver is required in mesh mode (e.g. --approver 'pubkey:<key>' or an FQDN glob); refusing to start an approver that any mesh peer could use to self-authorize")
	}
	ps := &policy.FilePending{Dir: *store, TTL: time.Duration(*ttlSec) * time.Second}

	var opts []approvalsOption
	if *devices != "" {
		var notifier Notifier = logNotifier{w: os.Stderr}
		delivery := "logging to stderr"
		if *notifyWebhook != "" {
			notifier = newWebhookNotifier(*notifyWebhook)
			delivery = "POST to " + *notifyWebhook
		}
		opts = append(opts, withPushWake(&DeviceStore{Dir: *devices}, notifier))
		log.Printf("push-wake enabled: devices in %s (register via POST /v1/devices; delivery: %s)", *devices, delivery)
	} else if *notifyWebhook != "" {
		return fmt.Errorf("meshmcp approvals: --notify-webhook requires --devices")
	}
	// Request-bound approvals: load the shared signing key (fail closed — a
	// configured-but-unreadable key is a security-config error, not a fallback to
	// the weaker ambient grant).
	if *approvalKey != "" {
		signer, err := policy.LoadSigner(*approvalKey)
		if err != nil {
			return fmt.Errorf("meshmcp approvals: --approval-key %s: %w", *approvalKey, err)
		}
		reqStore := policy.NewFileApprovalStore(*store, time.Duration(*ttlApprovalSec)*time.Second, signer)
		opts = append(opts, withRequestBound(reqStore))
		log.Printf("request-bound approvals enabled (signer %s); /v1/approve mints single-use, argument-bound tokens", signer.PubKeyHex()[:16])
	}

	// Local/dev mode: no mesh, a fixed approver identity.
	if *addr != "" {
		h := approvalsHandler(ps, func(*http.Request) string { return "operator@local" }, nil, time.Now, opts...)
		log.Printf("approvals on http://%s (LOCAL — approver is 'operator@local')", *addr)
		return newLocalHTTPServer(*addr, h).ListenAndServe()
	}

	// Mesh mode: the approver is the caller's cryptographic mesh identity.
	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)
	approver := func(r *http.Request) string {
		_, fqdn := peerIdentityStr(client, r.RemoteAddr)
		if fqdn == "" {
			return "unknown-mesh-peer"
		}
		return fqdn
	}
	// Operator allowlist: when --approver entries are given, only those
	// identities may approve/deny — so a low-privilege agent on the mesh cannot
	// self-authorize its own held call. Empty = any mesh peer (prior behavior).
	var authorized func(*http.Request) bool
	if len(approvers) > 0 {
		allow := newACL(approvers)
		authorized = func(r *http.Request) bool {
			pub, fqdn := peerIdentityStr(client, r.RemoteAddr)
			return allow.allows(pub, fqdn)
		}
		log.Printf("approvals: operator allowlist active (%v)", []string(approvers))
	}
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	log.Printf("approvals on mesh port %d (open it from a phone on the mesh; approver = your mesh identity)", *port)
	srv := newLocalHTTPServer("", approvalsHandler(ps, approver, authorized, time.Now, opts...))
	return srv.Serve(ln)
}

// approvalsOpts are optional add-ons for approvalsHandler (push-wake).
type approvalsOpts struct {
	devices  *DeviceStore
	notifier Notifier
	reqStore *policy.FileApprovalStore // set: /v1/approve also mints a request-bound token
}

// approvalsOption configures approvalsHandler without breaking its callers.
type approvalsOption func(*approvalsOpts)

// withPushWake enables device registration (/v1/devices) and notifies the
// registered devices when a new approval request is recorded.
func withPushWake(d *DeviceStore, n Notifier) approvalsOption {
	return func(o *approvalsOpts) { o.devices, o.notifier = d, n }
}

// withRequestBound makes /v1/approve additionally mint a signed, single-use,
// argument-bound approval (consumed by the gateway's DecideToolCallBound) for
// the exact held call — the request-bound half of the co-sign flow.
func withRequestBound(store *policy.FileApprovalStore) approvalsOption {
	return func(o *approvalsOpts) { o.reqStore = store }
}

// approvalsHandler builds the approver HTTP surface. approver resolves the
// caller identity for a request; now supplies grant timestamps. Split out so it
// is unit-testable with a fixed approver via httptest.
func approvalsHandler(ps *policy.FilePending, approver func(*http.Request) string, authorized func(*http.Request) bool, now func() time.Time, options ...approvalsOption) http.Handler {
	var opt approvalsOpts
	for _, o := range options {
		o(&opt)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/pending", func(w http.ResponseWriter, r *http.Request) {
		// Enumerating every held request is approver-only state.
		if authorized != nil && !authorized(r) {
			http.Error(w, "forbidden: not an authorized approver", http.StatusForbidden)
			return
		}
		list, err := ps.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if list == nil {
			list = []policy.Pending{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"pending": list, "you": approver(r)})
	})

	decide := func(grant bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			if authorized != nil && !authorized(r) {
				http.Error(w, "forbidden: not an authorized approver", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // bound the request body
			var body struct{ Peer, Tool string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Peer == "" || body.Tool == "" {
				http.Error(w, "peer and tool are required", http.StatusBadRequest)
				return
			}
			who := approver(r)
			if grant {
				// Mint the request-bound approval BEFORE clearing the pending record
				// (it holds the argument + policy binding). A configured request-bound
				// store makes the grant argument-scoped and single-use; a failure here
				// must fail the approval rather than silently fall back to the weaker
				// ambient grant.
				if opt.reqStore != nil {
					p, ok := ps.Get(body.Peer, body.Tool)
					if !ok || p.ArgsHash == "" {
						http.Error(w, "no held request-bound call for this peer+tool", http.StatusConflict)
						return
					}
					if _, err := opt.reqStore.Grant(p.ApprovalRequest(), who, p.PolicyHash, now()); err != nil {
						http.Error(w, "request-bound grant failed: "+err.Error(), http.StatusInternalServerError)
						return
					}
				}
				if err := policy.Grant(ps.Dir, body.Peer, body.Tool, who, now()); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = policy.ClearDeny(ps.Dir, body.Peer, body.Tool)
			} else {
				_ = policy.Deny(ps.Dir, body.Peer, body.Tool, who, now())
				_ = policy.Revoke(ps.Dir, body.Peer, body.Tool) // no lingering grant
			}
			// Whether approved or denied, the request is no longer pending.
			_ = ps.Clear(body.Peer, body.Tool)
			verb := "denied"
			if grant {
				verb = "approved"
			}
			writeJSONResp(w, http.StatusOK, map[string]string{
				"status": verb, "peer": body.Peer, "tool": body.Tool, "by": who,
			})
		}
	}
	mux.HandleFunc("/v1/approve", decide(true))
	mux.HandleFunc("/v1/deny", decide(false))

	// /v1/request lets ANY agent framework (e.g. the OpenAI Agents SDK
	// ShellTool's on_approval) register a human-approval request over the mesh —
	// turning meshmcp's approver into a general "human in the loop" service.
	mux.HandleFunc("/v1/request", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var body struct{ Peer, Tool, Backend string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil || body.Peer == "" || body.Tool == "" {
			http.Error(w, "peer and tool are required", http.StatusBadRequest)
			return
		}
		// NOTE: /v1/request is the framework-facing "ask for approval" endpoint —
		// a proxy (e.g. the Air web-proxy) legitimately registers a request on
		// behalf of a named agent, so the body Peer is honored here. The security
		// controls are downstream: approve/deny are approver-ACL gated, and a
		// granted approval is request-bound and single-use.
		// Fresh request: clear any stale decision, then record it pending.
		_ = policy.Revoke(ps.Dir, body.Peer, body.Tool)
		_ = policy.ClearDeny(ps.Dir, body.Peer, body.Tool)
		if err := ps.Record(policy.Pending{Peer: body.Peer, Tool: body.Tool, Backend: body.Backend}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Push-wake: buzz the registered approver device(s) instead of polling.
		if opt.notifier != nil && opt.devices != nil {
			if devs, err := opt.devices.List(""); err == nil && len(devs) > 0 {
				_ = opt.notifier.Notify(devs, "approval needed", body.Peer+" wants "+body.Tool)
			}
		}
		writeJSONResp(w, http.StatusOK, map[string]string{"status": "pending", "peer": body.Peer, "tool": body.Tool})
	})

	// /v1/devices registers a phone's push token, owned by the caller's mesh
	// identity, so the gateway can wake it when an approval is pending.
	if opt.devices != nil {
		mux.HandleFunc("/v1/devices", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			var body struct{ Token, Platform string }
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil || body.Token == "" {
				http.Error(w, "token is required", http.StatusBadRequest)
				return
			}
			d := Device{Identity: approver(r), Token: body.Token, Platform: body.Platform}
			if err := opt.devices.Register(d); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSONResp(w, http.StatusOK, map[string]string{"status": "registered", "identity": d.Identity})
		})
	}

	// /v1/status?peer=&tool= lets the requester poll the human's decision.
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		peer, tool := r.URL.Query().Get("peer"), r.URL.Query().Get("tool")
		if peer == "" || tool == "" {
			http.Error(w, "peer and tool query params are required", http.StatusBadRequest)
			return
		}
		// A requester may poll only its OWN (peer, tool); an authorized approver
		// may poll any. This prevents a peer probing another peer's approvals.
		if authorized != nil && approver(r) != peer && !authorized(r) {
			http.Error(w, "forbidden: not the requester or an authorized approver", http.StatusForbidden)
			return
		}
		state := "unknown"
		switch {
		case (&policy.FileCosign{Dir: ps.Dir}).Approved(policy.CosignKey(peer, tool)):
			state = "approved"
		case policy.IsDenied(ps.Dir, peer, tool):
			state = "denied"
		case ps.Has(peer, tool):
			state = "pending"
		}
		writeJSONResp(w, http.StatusOK, map[string]string{"state": state, "peer": peer, "tool": tool})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(approvalsHTML))
	})
	return mux
}

func writeJSONResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// approvalsHTML is a phone-first approver: big tap targets, dark, auto-refresh.
const approvalsHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0a0d13"><title>meshmcp approvals</title>
<style>
:root{--bg:#0a0d13;--panel:#141a24;--line:#232c3b;--fg:#dce4f2;--dim:#8a97ad;--accent:#5b8cff;--ok:#37d67a;--deny:#ff5c5c;--warn:#ffb020}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 ui-monospace,"SF Mono",Menlo,monospace;-webkit-font-smoothing:antialiased;
padding:max(16px,env(safe-area-inset-top)) 16px calc(16px + env(safe-area-inset-bottom))}
header{display:flex;align-items:center;gap:9px;margin-bottom:6px}
header .dot{width:9px;height:9px;border-radius:50%;background:var(--warn);box-shadow:0 0 0 3px color-mix(in srgb,var(--warn) 22%,transparent)}
h1{font-size:16px;margin:0}.you{color:var(--dim);font-size:12px;margin:0 0 16px}
.empty{color:var(--dim);text-align:center;padding:48px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:14px}
.tool{font-size:19px;font-weight:600;color:var(--warn);word-break:break-all}
.meta{color:var(--dim);font-size:13px;margin:6px 0 14px;word-break:break-all}
.meta b{color:var(--fg)}
.row{display:flex;gap:10px}
button{flex:1;border:0;border-radius:12px;padding:15px;font:600 15px ui-monospace,Menlo,monospace;
color:#08110a;cursor:pointer;-webkit-tap-highlight-color:transparent}
.ok{background:var(--ok)}.no{background:var(--deny);color:#1a0808}
button:active{filter:brightness(.85)}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:10px 16px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none}
.toast.show{opacity:1}
</style></head><body>
<header><span class="dot"></span><h1>Pending approvals</h1></header>
<p class="you" id="you">…</p>
<div id="list"><div class="empty">loading…</div></div>
<div class="toast" id="toast"></div>
<script>
// All dynamic values (peer, tool, backend) are agent-controlled, so they are
// only ever written via textContent / DOM APIs — never string-concatenated into
// HTML or an inline handler — so a tool named  '),alert(1)//  cannot inject.
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show')},1800)}
function ago(ts){var d=(Date.now()-Date.parse(ts))/1000;if(isNaN(d))return '';if(d<60)return Math.floor(d)+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';return Math.floor(d/3600)+'h ago'}
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
function act(peer,tool,grant){
  fetch(grant?'/v1/approve':'/v1/deny',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({peer:peer,tool:tool})})
   .then(function(r){return r.json()}).then(function(){toast((grant?'✓ approved ':'✗ denied ')+tool);load()})
   .catch(function(e){toast('error: '+e)});
}
function load(){
  fetch('/v1/pending').then(function(r){return r.json()}).then(function(j){
    document.getElementById('you').textContent='signing as: '+(j.you||'');
    var list=j.pending||[], c=document.getElementById('list');
    c.textContent='';
    if(!list.length){c.appendChild(el('div','empty','✓ nothing waiting'));return}
    list.forEach(function(p){
      var card=el('div','card');
      card.appendChild(el('div','tool',p.tool));
      var meta=el('div','meta');
      meta.appendChild(el('b',null,p.peer));
      meta.appendChild(document.createTextNode(' · '+(p.backend||'')+' · '+ago(p.requested)));
      card.appendChild(meta);
      var row=el('div','row');
      var ok=el('button','ok','Approve'); ok.addEventListener('click',function(){act(p.peer,p.tool,true)});
      var no=el('button','no','Deny');    no.addEventListener('click',function(){act(p.peer,p.tool,false)});
      row.appendChild(ok); row.appendChild(no); card.appendChild(row);
      c.appendChild(card);
    });
  }).catch(function(e){var c=document.getElementById('list');c.textContent='';c.appendChild(el('div','empty','fetch error: '+e))});
}
load();setInterval(load,2000);
</script></body></html>`
