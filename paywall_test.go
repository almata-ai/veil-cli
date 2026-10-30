package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectionPaywalls(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   map[string]any
		wants  []string
	}{
		{"enterprise-feature", 403, map[string]any{"error": "Device-bound sealing requires the Enterprise plan.", "code": "plan_required", "upgrade_url": "https://cal.com/ameer-iblsq5", "action_label": "Contact sales"}, []string{"HTTP 403", "Enterprise", "Contact sales: https://cal.com/ameer-iblsq5"}},
		{"free-quota", 429, map[string]any{"error": "Monthly build allowance reached (1/1 on the free plan).", "code": "quota_exceeded", "upgrade_url": "/api/billing/checkout?plan=pro", "action_label": "Upgrade to Pro", "resets_at": "2026-11-01T00:00:00.000Z"}, []string{"HTTP 429", "Upgrade to Pro:", "/api/billing/checkout?plan=pro", "Allowance resets Nov 1, 2026"}},
		{"pro-quota", 429, map[string]any{"error": "Monthly build allowance reached (500/500 on the pro plan).", "upgrade_url": "https://cal.com/ameer-iblsq5", "action_label": "Contact sales"}, []string{"500/500", "Contact sales:"}},
		{"older-server", 429, map[string]any{"error": "monthly quota reached"}, []string{"monthly quota reached", "View plans and allowance:", "/#pricing"}},
		{"invalid-action-url", 403, map[string]any{"error": "plan required", "upgrade_url": "javascript:alert(1)"}, []string{"View plans and allowance:", "/#pricing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				json.NewEncoder(w).Encode(tc.body)
			}))
			defer srv.Close()
			dir := t.TempDir()
			in := filepath.Join(dir, "crown.o")
			out := filepath.Join(dir, "protected.o")
			receipt := filepath.Join(dir, "receipt.json")
			os.WriteFile(in, []byte("object"), 0600)
			err := cmdProtect([]string{"--seal", in, "-o", out, "--receipt", receipt, "--api-key", "test-key", "--api-url", srv.URL})
			if err == nil {
				t.Fatal("expected a paywall error")
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("want %q in %q", want, err)
				}
			}
			if strings.Contains(err.Error(), "javascript:") {
				t.Fatal("unsafe upgrade URL was printed")
			}
			for _, path := range []string{out, receipt} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal(fmt.Sprintf("paywall must not write %s", path))
				}
			}
		})
	}
}
