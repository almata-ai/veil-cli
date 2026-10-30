// Command veil is the open-source client for the VeilCC Protection API.
//
// The protection itself runs server-side (the algorithm never ships in your
// binary); this CLI uploads a compiled object or LLVM IR, passes your options,
// and writes back the protected artifact plus a build receipt. It is a thin,
// dependency-free HTTP client over the same API the console and GitHub Action use.
//
//	veil protect --seal app.o -o app.sealed.o
//	veil protect --obfuscate --seal module.ll -o module.o   # stack both (needs IR)
//	veil verify build-receipt.json --artifact app.sealed.o
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var version = "0.1.0" // overridden at release via -ldflags "-X main.version=…"

const defaultAPIURL = "https://veilcc.com"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "protect":
		err = cmdProtect(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "login":
		err = cmdLogin(os.Args[2:])
	case "logout":
		err = cmdLogout(os.Args[2:])
	case "whoami":
		err = cmdWhoami(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("veil %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "veil: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "veil: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `veil — protect binaries against AI reverse-engineering

usage:
  veil login                                   sign in from the browser, store a token
  veil logout                                  forget the stored token
  veil whoami                                  show the workspace the current token belongs to
  veil scan    <input>                         exposure scan (free, unmetered): what AI reads first
  veil protect [flags] <input.o | source | ir> seal and/or obfuscate, write the artifact
  veil verify  <receipt.json> --artifact <f>   check a build receipt against its artifact
  veil version

auth: veil uses the token from "veil login", or VEILCC_KEY, or --api-key.
run "veil protect -h" for the full flag list.
`)
}

// ── protect ──────────────────────────────────────────────────────────────────

type protectResponse struct {
	OK       bool            `json:"ok"`
	Artifact string          `json:"artifact_b64"`
	Receipt  json.RawMessage `json:"receipt"`
	Quota    *struct {
		Used  int `json:"used"`
		Limit int `json:"limit"`
	} `json:"quota"`
	Simulated   bool   `json:"simulated"`
	Note        string `json:"note"`
	Error       string `json:"error"`
	Code        string `json:"code"`
	UpgradeURL  string `json:"upgrade_url"`
	ActionLabel string `json:"action_label"`
	ResetsAt    string `json:"resets_at"`
}

func cmdProtect(args []string) error {
	fs := flag.NewFlagSet("protect", flag.ExitOnError)
	obfuscate := fs.Bool("obfuscate", false, "obfuscate (source/IR); default MBA + decoys, lighter")
	obfMax := fs.Bool("obfuscate-max", false, "obfuscate: whole-module max (adds control-flow flattening; heavier)")
	seal := fs.Bool("seal", false, "seal the annotated functions (encrypt at rest)")
	scope := fs.String("scope", "", "sealed: restrict optional IR obfuscation to the exact function selected for sealing")
	strip := fs.Bool("strip", false, "remove debug info and discardable local symbols after protection (also works alone on objects)")
	postObfuscate := fs.Bool("post-obfuscate", false, "post-compile metadata hardening: strip and anonymize retained locals, with code/data and ABI checks; objects only")
	sealKey := fs.String("seal-key", "embedded", "seal key mode: embedded | device-bound")
	level := fs.String("level", "", "legacy alias: obfuscate | seal | device-bound (maps to --obfuscate/--seal)")
	var protos multiFlag
	fs.Var(&protos, "proto", "sealed function C signature (repeatable), e.g. \"uint32_t check_license(const char*)\"")
	symbols := fs.String("symbols", "", "comma-separated symbols to protect when source has no annotation")
	target := fs.String("target", "auto-detect", "output triple (auto-detect | arm64-macos | x86_64-macos | x86_64-linux | aarch64-linux | x86_64-windows)")
	persistent := fs.Bool("persistent", false, "seal: cache the decrypted function (default scrubs per call)")
	antiDebug := fs.Bool("anti-debug", false, "seal: fold a debugger-present check into the key")
	keyProvider := fs.String("key-provider", "", "device-bound: runtime key-unwrap symbol")
	seed := fs.String("seed", "", "obfuscate/post-compile: fixed build seed (0x…) for reproducible transformations")
	out := fs.String("out", "", "output path for the protected artifact (required)")
	fs.StringVar(out, "o", "", "shorthand for --out")
	receiptOut := fs.String("receipt", "", "write the build receipt JSON here")
	apiKey := fs.String("api-key", "", "API key (or set VEILCC_KEY)")
	apiURL := fs.String("api-url", "", "Protection API base URL (or set VEILCC_API_URL)")
	pos := parseArgs(fs, args)
	if len(pos) != 1 {
		return errors.New("expected exactly one input file (an object .o to seal, or IR .ll to obfuscate)")
	}
	input := pos[0]
	if *out == "" {
		return errors.New("--out (-o) is required")
	}
	key, base := resolveAuth(*apiKey, *apiURL)
	if key == "" {
		return errors.New("not authenticated: run `veil login`, or set VEILCC_KEY, or pass --api-key")
	}

	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	// Protection is composable: obfuscate and/or seal, with device-bound a seal key-mode.
	// With no protection flags, fall back to legacy --level (default seal).
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	doObf, doSeal, sk := *obfuscate, *seal, *sealKey
	doPost, doStrip := *postObfuscate, *strip || *postObfuscate
	if *obfMax {
		doObf = true // --obfuscate-max implies --obfuscate
	}
	if !set["obfuscate"] && !set["seal"] && !*obfMax && (!doStrip || *level != "") {
		lv := *level
		if lv == "" {
			lv = "seal"
		}
		switch lv {
		case "obfuscate":
			doObf = true
		case "seal":
			doSeal = true
		case "device-bound":
			doSeal, sk = true, "device-bound"
		default:
			return fmt.Errorf("--level must be obfuscate | seal | device-bound")
		}
	}
	if !doObf && !doSeal && !doStrip {
		return errors.New("choose at least one of --obfuscate / --seal / --strip / --post-obfuscate")
	}
	if *scope != "" && (*scope != "sealed" || !doSeal) {
		return errors.New("--scope sealed requires --seal")
	}
	deviceBound := doSeal && sk == "device-bound"
	// A single-level label so an older gateway still understands the request.
	compatLevel := "seal"
	switch {
	case !doObf && !doSeal:
		compatLevel = "" // strip-only must not trigger legacy seal on the gateway
	case doObf && !doSeal:
		compatLevel = "obfuscate"
	case deviceBound:
		compatLevel = "device-bound"
	}
	modeLabel := ""
	if doObf {
		modeLabel = "obfuscate"
	}
	if doSeal {
		if modeLabel != "" {
			modeLabel += " + "
		}
		if deviceBound {
			modeLabel += "seal (device-bound)"
		} else {
			modeLabel += "seal"
		}
	}

	if doStrip {
		if modeLabel != "" {
			modeLabel += " + "
		}
		if doPost {
			modeLabel += "post-compile hardening"
		} else {
			modeLabel += "strip"
		}
	}

	// Build the multipart request the same way the console does.
	fields := map[string]string{"target": *target, "level": compatLevel}
	if *scope != "" {
		fields["scope"] = *scope
	}
	if doStrip {
		fields["strip"] = "1"
		if doPost {
			fields["post_obfuscate"] = "1"
		}
	}
	if doObf {
		fields["obfuscate"] = "1"
		if *obfMax {
			fields["obf_max"] = "1"
		}
	}
	if doSeal {
		fields["seal"] = "1"
		fields["seal_key"] = sk
	}
	if len(protos) > 0 {
		fields["proto"] = strings.Join(protos, "\n")
	}
	if *symbols != "" {
		fields["symbols"] = *symbols
	}
	if *persistent {
		fields["persistent"] = "1"
	}
	if *antiDebug {
		fields["anti_debug"] = "1"
	}
	if *keyProvider != "" {
		fields["key_provider"] = *keyProvider
	}
	if *seed != "" {
		fields["seed"] = *seed
	}

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	fw, err := mw.CreateFormFile("binary", baseName(input))
	if err != nil {
		return err
	}
	fw.Write(data)
	mw.Close()

	total := int64(body.Len())
	reqBody, cleanup := uploadBody(body, total, "protecting on the runner…")
	req, err := http.NewRequest("POST", strings.TrimRight(base, "/")+"/api/protect", reqBody)
	if err != nil {
		cleanup()
		return err
	}
	req.ContentLength = total
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	cleanup()
	if err != nil {
		return fmt.Errorf("Protection API unreachable at %s: %w", base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var pr protectResponse
	if err := json.Unmarshal(raw, &pr); err != nil {
		return fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, truncate(string(raw), 300))
	}
	if resp.StatusCode != 200 || !pr.OK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			message := pr.Error
			if message == "" {
				message = "Your workspace plan does not allow this build."
			}
			action, target := pr.ActionLabel, pr.UpgradeURL
			if action == "" {
				action = "View plans and allowance"
			}
			root, _ := url.Parse(strings.TrimRight(base, "/") + "/")
			link, err := url.Parse(target)
			if err != nil || target == "" {
				link, _ = url.Parse("/#pricing")
			}
			if root != nil {
				link = root.ResolveReference(link)
			}
			if link.Scheme != "http" && link.Scheme != "https" {
				link, _ = url.Parse(strings.TrimRight(base, "/") + "/#pricing")
			}
			reset := ""
			if when, err := time.Parse(time.RFC3339, pr.ResetsAt); err == nil {
				reset = "\nAllowance resets " + when.UTC().Format("Jan 2, 2006 15:04 MST") + "."
			}
			return fmt.Errorf("HTTP %d: %s%s\n%s: %s", resp.StatusCode, message, reset, action, link.String())
		}
		if pr.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, pr.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if *scope == "sealed" && receiptField(pr.Receipt, "function_scope") == "" && !pr.Simulated {
		return errors.New("server did not confirm selected-function scope; update the gateway and runner")
	}

	if doPost && receiptField(pr.Receipt, "post_obfuscate") != "on" && !pr.Simulated {
		return errors.New("server did not confirm post-compile hardening; update the gateway and runner to support --post-obfuscate")
	}

	if doStrip && receiptField(pr.Receipt, "strip") != "on" && !pr.Simulated {
		return errors.New("server did not confirm stripping; update the gateway and runner to support --strip")
	}

	if pr.Artifact == "" {
		// The server simulated (no runner configured). Don't write a fake object.
		return fmt.Errorf("server returned no artifact%s", note(pr.Note))
	}
	artifact, err := base64.StdEncoding.DecodeString(pr.Artifact)
	if err != nil {
		return fmt.Errorf("decoding artifact: %w", err)
	}
	if err := os.WriteFile(*out, artifact, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", *out, err)
	}

	if *receiptOut != "" && len(pr.Receipt) > 0 {
		pretty, _ := json.MarshalIndent(json.RawMessage(pr.Receipt), "", "  ")
		if err := os.WriteFile(*receiptOut, pretty, 0o644); err != nil {
			return fmt.Errorf("writing receipt %s: %w", *receiptOut, err)
		}
	}

	fmt.Printf("veilcc: protected %s → %s (%d bytes, %s)\n", baseName(input), *out, len(artifact), modeLabel)
	if pr.Quota != nil {
		fmt.Printf("        quota: %d of %d used this month\n", pr.Quota.Used, pr.Quota.Limit)
	}
	if h := receiptField(pr.Receipt, "receipt_hash"); h != "" {
		fmt.Printf("        receipt: %s\n", h)
	}
	// Expose the artifact path to a GitHub Action step, if present.
	if gh := os.Getenv("GITHUB_OUTPUT"); gh != "" {
		if f, err := os.OpenFile(gh, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "protected=%s\n", *out)
			f.Close()
		}
	}
	return nil
}

// ── scan ─────────────────────────────────────────────────────────────────────

type scanResponse struct {
	OK        bool `json:"ok"`
	Exposures int  `json:"exposures"`
	Findings  []struct {
		Label  string `json:"label"`
		Detail string `json:"detail"`
	} `json:"findings"`
	Error string `json:"error"`
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// cmdScan runs the always-free, unmetered exposure scan: what a decompiler + an AI
// read out of a binary first. It does not consume the monthly build quota.
func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	apiKey := fs.String("api-key", "", "API key (or set VEILCC_KEY)")
	apiURL := fs.String("api-url", "", "Protection API base URL (or set VEILCC_API_URL)")
	pos := parseArgs(fs, args)
	if len(pos) != 1 {
		return errors.New("expected exactly one input file to scan")
	}
	input := pos[0]
	key, base := resolveAuth(*apiKey, *apiURL)
	if key == "" {
		return errors.New("not authenticated: run `veil login`, or set VEILCC_KEY, or pass --api-key")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("binary", baseName(input))
	if err != nil {
		return err
	}
	fw.Write(data)
	mw.Close()

	total := int64(body.Len())
	reqBody, cleanup := uploadBody(body, total, "scanning…")
	req, err := http.NewRequest("POST", strings.TrimRight(base, "/")+"/api/scan", reqBody)
	if err != nil {
		cleanup()
		return err
	}
	req.ContentLength = total
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Do(req)
	cleanup()
	if err != nil {
		return fmt.Errorf("Protection API unreachable at %s: %w", base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var sr scanResponse
	if err := json.Unmarshal(raw, &sr); err != nil {
		return fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, truncate(string(raw), 300))
	}
	if resp.StatusCode != 200 || !sr.OK {
		if sr.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, sr.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	fmt.Printf("veilcc: %d exposure%s in %s  (free, unmetered)\n", sr.Exposures, plural(sr.Exposures), baseName(input))
	for _, f := range sr.Findings {
		if f.Detail != "" {
			fmt.Printf("  ✕ %s — %s\n", f.Label, f.Detail)
		} else {
			fmt.Printf("  ✕ %s\n", f.Label)
		}
	}
	ext := filepath.Ext(baseName(input))
	out := strings.TrimSuffix(baseName(input), ext) + ".sealed" + ext
	fmt.Printf("  harden these: veil protect --seal %s -o %s\n", baseName(input), out)
	return nil
}

// ── verify ───────────────────────────────────────────────────────────────────

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	artifact := fs.String("artifact", "", "the protected artifact the receipt describes (required)")
	pos := parseArgs(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: veil verify <receipt.json> --artifact <file>")
	}
	if *artifact == "" {
		return errors.New("--artifact is required")
	}
	receiptRaw, err := os.ReadFile(pos[0])
	if err != nil {
		return fmt.Errorf("reading receipt: %w", err)
	}
	art, err := os.ReadFile(*artifact)
	if err != nil {
		return fmt.Errorf("reading artifact: %w", err)
	}
	want := receiptField(receiptRaw, "receipt_hash")
	if want == "" {
		return errors.New("receipt has no receipt_hash")
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(art))
	// The receipt carries a short form: first4…last4 of the sha256.
	got := sum[:4] + "…" + sum[len(sum)-4:]
	if got != want {
		return fmt.Errorf("MISMATCH: artifact hashes to %s, receipt says %s", got, want)
	}
	sealed := receiptField(receiptRaw, "sealed_symbol")
	mode := receiptField(receiptRaw, "protect")
	if mode == "" {
		mode = receiptField(receiptRaw, "level") // legacy receipts
	}
	fmt.Printf("veilcc: receipt verified ✓  hash %s · %s", want, mode)
	if sealed != "" {
		fmt.Printf(" · sealed %s", sealed)
	}
	fmt.Println()
	return nil
}

// ── login / logout / whoami ──────────────────────────────────────────────────

type config struct {
	APIURL string `json:"api_url,omitempty"`
	Token  string `json:"token,omitempty"`
	Email  string `json:"email,omitempty"`
	WS     string `json:"ws,omitempty"`
}

func configPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "veilcc", "config.json")
}

func loadConfig() config {
	var c config
	if b, err := os.ReadFile(configPath()); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func saveConfig(c config) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, b, 0o600)
}

// resolveAuth returns the API key and base URL, preferring explicit flags/env,
// then the stored login.
func resolveAuth(apiKey, apiURL string) (key, base string) {
	c := loadConfig()
	key = firstNonEmpty(apiKey, os.Getenv("VEILCC_KEY"), c.Token)
	base = firstNonEmpty(apiURL, os.Getenv("VEILCC_API_URL"), c.APIURL, defaultAPIURL)
	return
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	apiURL := fs.String("api-url", "", "Protection API base URL (or VEILCC_API_URL)")
	withToken := fs.String("with-token", "", "store this API key non-interactively (skip the browser)")
	fs.Parse(args)
	base := firstNonEmpty(*apiURL, os.Getenv("VEILCC_API_URL"), loadConfig().APIURL, defaultAPIURL)

	// Non-interactive: store a key the user already has (headless / CI setup).
	if *withToken != "" {
		if !strings.HasPrefix(*withToken, "veil_sk_") {
			return errors.New("--with-token should be a veil_sk_… API key from the console")
		}
		if err := saveConfig(config{APIURL: base, Token: *withToken}); err != nil {
			return err
		}
		fmt.Printf("Token saved to %s\n", configPath())
		return cmdWhoami(nil)
	}

	// 1) start a device authorization
	var start struct {
		DeviceCode string `json:"device_code"`
		VerifyURL  string `json:"verify_url"`
		Interval   int    `json:"interval"`
		ExpiresIn  int    `json:"expires_in"`
		Error      string `json:"error"`
	}
	if err := postJSON(strings.TrimRight(base, "/")+"/api/cli/start", nil, &start); err != nil {
		return err
	}
	if start.DeviceCode == "" {
		return errors.New("could not start login: " + start.Error)
	}

	fmt.Printf("Opening %s\n", start.VerifyURL)
	fmt.Println("If your browser doesn't open, visit that URL to authorize this CLI.")
	openBrowser(start.VerifyURL)

	// 2) poll until approved
	interval := start.Interval
	if interval < 1 {
		interval = 2
	}
	deadline := time.Now().Add(time.Duration(maxInt(start.ExpiresIn, 60)) * time.Second)
	fmt.Print("Waiting for authorization")
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)
		fmt.Print(".")
		var poll struct {
			Status string `json:"status"`
			Token  string `json:"token"`
			Email  string `json:"email"`
			WS     string `json:"ws"`
		}
		if err := postJSON(strings.TrimRight(base, "/")+"/api/cli/poll", map[string]string{"device_code": start.DeviceCode}, &poll); err != nil {
			continue // transient; keep polling
		}
		switch poll.Status {
		case "approved":
			fmt.Println()
			if err := saveConfig(config{APIURL: base, Token: poll.Token, Email: poll.Email, WS: poll.WS}); err != nil {
				return err
			}
			fmt.Printf("Logged in as %s (workspace %s). Token saved to %s\n", poll.Email, poll.WS, configPath())
			return nil
		case "expired":
			fmt.Println()
			return errors.New("the login request expired, run `veil login` again")
		}
	}
	fmt.Println()
	return errors.New("timed out waiting for authorization")
}

func cmdLogout(_ []string) error {
	c := loadConfig()
	if c.Token == "" {
		fmt.Println("Not logged in.")
		return nil
	}
	c.Token, c.Email, c.WS = "", "", ""
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Println("Logged out. (Revoke the key in the console → API keys to fully invalidate it.)")
	return nil
}

func cmdWhoami(_ []string) error {
	key, base := resolveAuth("", "")
	if key == "" {
		return errors.New("not logged in (run `veil login`) and no VEILCC_KEY set")
	}
	req, _ := http.NewRequest("GET", strings.TrimRight(base, "/")+"/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var w struct {
		WS, Plan, Email, KeyName string
		Usage                    struct{ Used, Limit int }
		Error                    string `json:"error"`
	}
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &w)
	if resp.StatusCode != 200 {
		return errors.New(firstNonEmpty(w.Error, fmt.Sprintf("HTTP %d", resp.StatusCode)))
	}
	who := w.Email
	if who == "" {
		who = w.KeyName
	}
	fmt.Printf("%s · workspace %s · plan %s · %d/%d used this month\n", who, w.WS, w.Plan, w.Usage.Used, w.Usage.Limit)
	return nil
}

func postJSON(url string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest("POST", url, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return json.Unmarshal(raw, out)
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── helpers ──────────────────────────────────────────────────────────────────

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// parseArgs parses flags that may appear before or after positional args
// (Go's flag package stops at the first positional). Returns the positionals.
func parseArgs(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return pos
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func note(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// receiptField pulls a top-level string field out of a receipt JSON blob.
func receiptField(raw json.RawMessage, field string) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}
