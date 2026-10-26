package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgsInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	lvl := fs.String("level", "", "")
	// flag after the positional — plain flag.Parse would miss --level here.
	pos := parseArgs(fs, []string{"input.o", "--level", "seal"})
	if len(pos) != 1 || pos[0] != "input.o" {
		t.Fatalf("positionals = %v, want [input.o]", pos)
	}
	if *lvl != "seal" {
		t.Fatalf("level = %q, want seal", *lvl)
	}
}

func TestReceiptField(t *testing.T) {
	raw := json.RawMessage(`{"level":"seal","receipt_hash":"ab12…cd34","n":5}`)
	if got := receiptField(raw, "receipt_hash"); got != "ab12…cd34" {
		t.Fatalf("got %q", got)
	}
	if got := receiptField(raw, "missing"); got != "" {
		t.Fatalf("missing field should be empty, got %q", got)
	}
	if got := receiptField(raw, "n"); got != "" {
		t.Fatalf("non-string field should be empty, got %q", got)
	}
}

// fakeAPI returns a server that behaves like /api/protect: it seals by echoing a
// deterministic "artifact" and a receipt whose hash matches it.
func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good_key" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{"error": "bad key"})
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"error": "not multipart"})
			return
		}
		f, _, _ := r.FormFile("binary")
		in, _ := io.ReadAll(f)
		artifact := append([]byte("SEALED:"), in...)
		sum := fmt.Sprintf("%x", sha256.Sum256(artifact))
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"artifact_b64": base64.StdEncoding.EncodeToString(artifact),
			"receipt": map[string]any{
				"level":         r.FormValue("level"),
				"sealed_symbol": "check_license",
				"receipt_hash":  sum[:4] + "…" + sum[len(sum)-4:],
			},
			"quota": map[string]any{"used": 1, "limit": 500},
		})
	}))
}

func TestProtectWritesArtifactAndReceipt(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	in := filepath.Join(dir, "app.o")
	os.WriteFile(in, []byte("OBJECTBYTES"), 0o644)
	out := filepath.Join(dir, "app.sealed.o")
	rec := filepath.Join(dir, "receipt.json")

	t.Setenv("VEILCC_KEY", "good_key")
	t.Setenv("VEILCC_API_URL", srv.URL)
	if err := cmdProtect([]string{"--level", "seal", "-o", out, "--receipt", rec, in}); err != nil {
		t.Fatalf("protect: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output not written: %v", err)
	}
	if string(got) != "SEALED:OBJECTBYTES" {
		t.Fatalf("artifact = %q", got)
	}
	// Receipt must round-trip and the CLI's own verify must accept it.
	if err := cmdVerify([]string{rec, "--artifact", out}); err != nil {
		t.Fatalf("verify should pass on a fresh build: %v", err)
	}
}

func TestProtectBadKey(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	in := filepath.Join(dir, "app.o")
	os.WriteFile(in, []byte("x"), 0o644)
	t.Setenv("VEILCC_KEY", "wrong")
	t.Setenv("VEILCC_API_URL", srv.URL)
	err := cmdProtect([]string{"-o", filepath.Join(dir, "o"), in})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 error, got %v", err)
	}
}

func TestVerifyMismatch(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "a.o")
	os.WriteFile(art, []byte("hello"), 0o644)
	rec := filepath.Join(dir, "r.json")
	os.WriteFile(rec, []byte(`{"level":"seal","receipt_hash":"0000…0000"}`), 0o644)
	if err := cmdVerify([]string{rec, "--artifact", art}); err == nil || !strings.Contains(err.Error(), "MISMATCH") {
		t.Fatalf("want MISMATCH, got %v", err)
	}
}

func TestConfigRoundTripAndAuthPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VEILCC_KEY", "")
	t.Setenv("VEILCC_API_URL", "")
	if err := saveConfig(config{APIURL: "https://self.example", Token: "cfg_token", Email: "a@b.co", WS: "b"}); err != nil {
		t.Fatal(err)
	}
	// stored login is used when no flag/env override
	if k, base := resolveAuth("", ""); k != "cfg_token" || base != "https://self.example" {
		t.Fatalf("stored login not used: key=%q base=%q", k, base)
	}
	// env overrides the stored token
	t.Setenv("VEILCC_KEY", "env_key")
	if k, _ := resolveAuth("", ""); k != "env_key" {
		t.Fatalf("env should win: %q", k)
	}
	// explicit flag overrides env
	if k, base := resolveAuth("flag_key", "https://flag.example"); k != "flag_key" || base != "https://flag.example" {
		t.Fatalf("flag should win: key=%q base=%q", k, base)
	}
}
