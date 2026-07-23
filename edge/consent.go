package edge

import (
	"html/template"
	"net/http"
)

// The consent page is fully self-contained: inline CSS, no external assets, a
// strict CSP, and a side-effect-free poll of the authorization status. No
// credential is ever collected here — approval happens out of band in the
// operator CLI, so there is nothing on this page to phish.

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {{.ClientName}}</title>
<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  background:#f6f8fc;color:#111827;display:flex;min-height:100vh;align-items:center;justify-content:center}
@media(prefers-color-scheme:dark){body{background:#090b10;color:#f7f8fc}}
.card{max-width:28rem;margin:1.5rem;padding:2rem;border-radius:18px;background:#fff;
  box-shadow:0 1px 3px rgba(0,0,0,.08),0 8px 24px rgba(0,0,0,.06)}
@media(prefers-color-scheme:dark){.card{background:#151820}}
h1{font-size:1.25rem;margin:0 0 .5rem}
.muted{color:#647084}
@media(prefers-color-scheme:dark){.muted{color:#a5adbd}}
.dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.4rem;vertical-align:middle}
.wait{background:#e86f16}.ok{background:#159b62}.bad{background:#d63c48}
.status{margin-top:1rem;padding:.75rem 1rem;border-radius:12px;background:rgba(72,86,110,.08)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}
</style>
</head><body>
<main class="card">
  <h1>Authorize {{.ClientName}}</h1>
  <p class="muted">This connector is asking to reach your mesh tools. An operator must approve this request before access is granted.</p>
  <div class="status" id="status" role="status" aria-live="polite">
    <span class="dot wait" id="dot"></span><span id="msg">Waiting for operator approval…</span>
  </div>
  <p class="muted" style="margin-top:1rem">Request <code>{{.RequestID}}</code></p>
</main>
<script>
(function(){
  var id={{.RequestID}};
  var dot=document.getElementById('dot'), msg=document.getElementById('msg');
  function set(cls,text){dot.className='dot '+cls;msg.textContent=text;}
  function poll(){
    fetch('authorize/status?request_id='+encodeURIComponent(id),{cache:'no-store'})
      .then(function(r){return r.json()})
      .then(function(d){
        if(d.status==='approved'&&d.redirect){set('ok','Approved — redirecting…');window.location=d.redirect;return;}
        if(d.status==='completed'){set('ok','Approved.');return;}
        if(d.status==='denied'){set('bad','Request denied.');return;}
        if(d.status==='expired'){set('bad','Request expired. Start again from the connector.');return;}
        setTimeout(poll,2000);
      })
      .catch(function(){setTimeout(poll,3000)});
  }
  poll();
})();
</script>
</body></html>`))

// renderConsentPage serves the self-contained consent/poll page for a pending
// authorization request.
func (s *Server) renderConsentPage(w http.ResponseWriter, authz authzRecord) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	_ = consentTmpl.Execute(w, authz)
}

// renderAuthzError serves a minimal error page for pre-redirect failures (an
// untrusted or unknown redirect_uri means we cannot bounce the error back).
func (s *Server) renderAuthzError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = authzErrorTmpl.Execute(w, map[string]string{"Msg": msg})
}

var authzErrorTmpl = template.Must(template.New("authzerr").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorization error</title>
<style>body{margin:0;font:16px/1.5 system-ui,sans-serif;background:#f6f8fc;color:#111827;
display:flex;min-height:100vh;align-items:center;justify-content:center}
@media(prefers-color-scheme:dark){body{background:#090b10;color:#f7f8fc}}
.card{max-width:28rem;margin:1.5rem;padding:2rem;border-radius:18px;background:#fff}
@media(prefers-color-scheme:dark){.card{background:#151820}}</style></head>
<body><main class="card"><h1>Authorization error</h1><p>{{.Msg}}</p></main></body></html>`))
