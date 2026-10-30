package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostCompileCombinations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     []string
		seal, obf string
	}{
		{"standalone", []string{"--post-obfuscate"}, "", ""},
		{"seal", []string{"--seal", "--post-obfuscate"}, "1", ""},
		{"stacked", []string{"--obfuscate", "--seal", "--post-obfuscate"}, "1", "1"},
		{"legacy", []string{"--level", "seal", "--post-obfuscate"}, "1", ""},
		{"scoped", []string{"--obfuscate", "--seal", "--scope", "sealed", "--post-obfuscate"}, "1", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseMultipartForm(1 << 20); err != nil {
					t.Fatal(err)
				}
				for key, want := range map[string]string{"post_obfuscate": "1", "strip": "1", "seal": tc.seal, "obfuscate": tc.obf} {
					if got := r.FormValue(key); got != want {
						t.Errorf("%s=%q, want %q", key, got, want)
					}
				}
				if tc.name == "scoped" && r.FormValue("scope") != "sealed" {
					t.Error("scoped flag was not forwarded")
				}
				if tc.seal == "" && tc.obf == "" && r.FormValue("level") != "" {
					t.Error("standalone post mode must not default to legacy seal")
				}
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "artifact_b64": base64.StdEncoding.EncodeToString([]byte("artifact")), "receipt": map[string]string{"strip": "on", "post_obfuscate": "on", "function_scope": "check_license"}})
			}))
			defer srv.Close()
			dir := t.TempDir()
			in := filepath.Join(dir, "in.o")
			out := filepath.Join(dir, "out.o")
			os.WriteFile(in, []byte("object"), 0600)
			args := append(append([]string{}, tc.flags...), in, "-o", out, "--api-key", "test", "--api-url", srv.URL)
			if err := cmdProtect(args); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPostCompileRejectsOldRunner(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.o")
	out := filepath.Join(dir, "out.o")
	os.WriteFile(in, []byte("object"), 0600)
	err := cmdProtect([]string{"--seal", "--post-obfuscate", in, "-o", out, "--api-key", "good_key", "--api-url", srv.URL})
	if err == nil || !strings.Contains(err.Error(), "did not confirm post-compile hardening") {
		t.Fatalf("want unsupported stage error, got %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("must not write a partially protected artifact")
	}
}
