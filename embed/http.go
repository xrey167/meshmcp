package embed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"
)

// HTTP embeds text through an OpenAI-compatible embeddings endpoint
// (POST {url} with {"model","input"}), which covers OpenAI itself and the
// self-hosted servers speaking the same shape (Ollama, vLLM, LM Studio,
// llamafile). The operator supplies the endpoint and, optionally, the name of
// an environment variable holding the bearer token — no vendor credential is
// ever embedded, matching the secrets rules.
//
// Construction probes the endpoint once and fails closed, fixing the vector
// dimension from the provider's response. A runtime failure logs and returns
// the zero vector: it cosine-scores 0 against everything, so a degraded
// embedder can rank nothing spuriously high — results shrink, never lie.
type HTTP struct {
	url    string
	model  string
	key    string
	dim    int
	client *http.Client
	logf   func(string, ...any)
}

const (
	httpEmbedTimeout  = 30 * time.Second
	maxEmbedRespBytes = 8 << 20
)

// NewHTTP builds and probes an HTTP embedder. keyEnv, when non-empty, names an
// environment variable that MUST hold the bearer token (fail closed on an
// empty value — a typo'd variable name silently sending unauthenticated
// requests is the failure mode this refuses). logf may be nil.
func NewHTTP(url, model, keyEnv string, logf func(string, ...any)) (*HTTP, error) {
	if url == "" || model == "" {
		return nil, errors.New("embed: url and model are required")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	e := &HTTP{url: url, model: model, client: &http.Client{Timeout: httpEmbedTimeout}, logf: logf}
	if keyEnv != "" {
		e.key = os.Getenv(keyEnv)
		if e.key == "" {
			return nil, fmt.Errorf("embed: environment variable %s is empty (bearer token expected)", keyEnv)
		}
	}
	vec, err := e.doEmbed("meshmcp embedder probe")
	if err != nil {
		return nil, fmt.Errorf("embed: probe failed: %w", err)
	}
	if len(vec) == 0 {
		return nil, errors.New("embed: probe returned an empty vector")
	}
	e.dim = len(vec)
	return e, nil
}

func (e *HTTP) Dim() int { return e.dim }

// Embed implements Embedder. The interface has no error path, so a runtime
// provider failure degrades to the zero vector (see the type comment) and is
// logged — never silently mis-embedded.
func (e *HTTP) Embed(text string) []float32 {
	vec, err := e.doEmbed(text)
	if err != nil || len(vec) != e.dim {
		if err == nil {
			err = fmt.Errorf("provider returned %d dimensions, want %d", len(vec), e.dim)
		}
		e.logf("embed: %v (returning zero vector)", err)
		return make([]float32, e.dim)
	}
	return vec
}

func (e *HTTP) doEmbed(text string) ([]float32, error) {
	body, err := json.Marshal(map[string]any{"model": e.model, "input": []string{text}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.key != "" {
		req.Header.Set("Authorization", "Bearer "+e.key)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEmbedRespBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// Deliberately not echoing the body: an error page from a misconfigured
		// endpoint is untrusted text.
		return nil, fmt.Errorf("endpoint returned %s", resp.Status)
	}
	var out struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	if len(out.Data) == 0 || len(out.Data[0].Embedding) == 0 {
		return nil, errors.New("response carried no embedding")
	}
	return normalize(out.Data[0].Embedding), nil
}

// normalize L2-normalizes so the index's dot product is cosine similarity,
// matching the Hashing embedder's contract regardless of provider behavior.
func normalize(in []float64) []float32 {
	var norm float64
	for _, v := range in {
		norm += v * v
	}
	out := make([]float32, len(in))
	if norm == 0 {
		return out
	}
	inv := 1 / math.Sqrt(norm)
	for i, v := range in {
		out[i] = float32(v * inv)
	}
	return out
}
