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

func TestStripCombinations(t *testing.T) {
	cases := []struct {
		name                    string
		flags                   []string
		obf, seal, strip, level string
	}{
		{"default-seal", nil, "", "1", "", "seal"},
		{"strip-only", []string{"--strip"}, "", "", "1", ""},
		{"seal-strip", []string{"--seal", "--strip"}, "", "1", "1", "seal"},
		{"stacked", []string{"--obfuscate", "--seal", "--strip"}, "1", "1", "1", "seal"},
		{"max-strip", []string{"--obfuscate-max", "--strip"}, "1", "", "1", "obfuscate"},
		{"legacy-strip", []string{"--level", "seal", "--strip"}, "", "1", "1", "seal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseMultipartForm(1 << 20); err != nil {
					t.Error(err)
				}
				for k, want := range map[string]string{"obfuscate": tc.obf, "seal": tc.seal, "strip": tc.strip, "level": tc.level} {
					if got := r.FormValue(k); got != want {
						t.Errorf("%s = %q, want %q", k, got, want)
					}
				}
				state := "off"
				if tc.strip == "1" {
					state = "on"
				}
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "artifact_b64": base64.StdEncoding.EncodeToString([]byte("artifact")), "receipt": map[string]string{"strip": state}})
			}))
			defer srv.Close()
			dir := t.TempDir()
			in := filepath.Join(dir, "input.o")
			os.WriteFile(in, []byte("input"), 0600)
			args := append(append([]string{}, tc.flags...), in, "-o", filepath.Join(dir, "out.o"), "--api-key", "test-key", "--api-url", srv.URL)
			if err := cmdProtect(args); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStripRejectsOlderServerWithoutWriting(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.o")
	os.WriteFile(in, []byte("input"), 0600)
	out := filepath.Join(dir, "out.o")
	err := cmdProtect([]string{"--seal", "--strip", in, "-o", out, "--api-key", "good_key", "--api-url", srv.URL})
	if err == nil || !strings.Contains(err.Error(), "did not confirm stripping") {
		t.Fatalf("want unsupported stripping error, got %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("must not write an unstripped artifact")
	}
}
