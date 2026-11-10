package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseProtectValidatesHashAndPreservesInput(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "app.cjs")
			output := filepath.Join(dir, "shielded.cjs")
			os.WriteFile(input, []byte("input"), 0755)
			artifact := []byte("protected artifact")
			hash := sha256.Sum256(artifact)
			digest := hex.EncodeToString(hash[:])
			if !valid {
				digest = strings.Repeat("0", 64)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/release" || r.Header.Get("Authorization") != "Bearer test" {
					t.Error("wrong release request")
				}
				if err := r.ParseMultipartForm(1024); err != nil {
					t.Error(err)
				}
				if r.FormValue("action") != "protect" {
					t.Error("wrong action")
				}
				fmt.Fprintf(w, `{"ok":true,"artifact_b64":%q,"receipt":{"artifact_sha256":%q}}`, base64.StdEncoding.EncodeToString(artifact), digest)
			}))
			defer server.Close()
			err := cmdRelease([]string{"protect", input, "-o", output, "--api-key", "test", "--api-url", server.URL})
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				b, _ := os.ReadFile(output)
				if string(b) != string(artifact) {
					t.Fatal("bad output")
				}
				info, _ := os.Stat(output)
				if info.Mode().Perm() != 0755 {
					t.Fatal("executable mode lost")
				}
				if e := cmdRelease([]string{"protect", input, "-o", output}); e == nil {
					t.Fatal("overwrote existing output")
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "SHA-256") {
					t.Fatalf("expected hash refusal, got %v", err)
				}
				if _, e := os.Stat(output); e == nil {
					t.Fatal("wrote mismatching artifact")
				}
			}
			b, _ := os.ReadFile(input)
			if string(b) != "input" {
				t.Fatal("modified input")
			}
		})
	}
}

func TestReleasePaywallHasUpgradeAction(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "app.cjs")
	os.WriteFile(input, []byte("test"), 0644)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"error":"Monthly allowance reached","code":"quota_exceeded","upgrade_url":"/upgrade","action_label":"Upgrade to Pro"}`)
	}))
	defer server.Close()
	err := cmdRelease([]string{"protect", input, "-o", filepath.Join(dir, "out.cjs"), "--api-key", "test", "--api-url", server.URL})
	if err == nil || !strings.Contains(err.Error(), "Upgrade to Pro: "+server.URL+"/upgrade") {
		t.Fatalf("missing actionable paywall: %v", err)
	}
}
