package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"strings"
	"time"
)

// Native protection stays before linking. This optional stage works on releases.
func cmdRelease(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: veil release <audit|verify|protect> [flags] <file>; veil release local <project-tool command>")
	}
	action := args[0]
	if action == "local" {
		helper := os.Getenv("VEIL_RELEASE_TOOL")
		if helper == "" {
			helper = "veil-release"
		}
		cmd := exec.Command(helper, args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("local release tools: %w (install the companion from the VeilCC source repository, or set VEIL_RELEASE_TOOL)", err)
		}
		return nil
	}
	if action != "audit" && action != "verify" && action != "protect" {
		return errors.New("release action must be audit, verify, protect, or local")
	}
	fs := flag.NewFlagSet("release "+action, flag.ContinueOnError)
	output := fs.String("out", "", "new output artifact path")
	fs.StringVar(output, "o", "", "output artifact path")
	receipt := fs.String("receipt", "", "optional report JSON output")
	intensity := fs.String("intensity", "balanced", "stealth | balanced | maximum | bankrupt")
	seed := fs.String("seed", "", "reproducible release seed")
	directives := fs.Bool("llm-directives", false, "experimental LLM-facing instruction decoys")
	noHoney := fs.Bool("no-honey-maps", false, "disable generated decoy source maps")
	apiKey := fs.String("api-key", "", "API key (or VEILCC_KEY)")
	apiURL := fs.String("api-url", "", "API base URL")
	var pos []string
	for rest := args[1:]; len(rest) > 0; {
		if err := fs.Parse(rest); err != nil {
			if err == flag.ErrHelp {
				return nil
			}
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(pos) != 1 {
		return errors.New("expected one release file")
	}
	if action == "protect" && *output == "" {
		return errors.New("-o is required for release protection")
	}
	for _, path := range []string{*output, *receipt} {
		if path != "" {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("output already exists: %s", path)
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	if *output != "" && *receipt != "" {
		a, _ := filepath.Abs(*output)
		b, _ := filepath.Abs(*receipt)
		if a == b {
			return errors.New("artifact and report paths must differ")
		}
	}
	key, base := resolveAuth(*apiKey, *apiURL)
	if key == "" {
		return errors.New("not authenticated: run veil login or set VEILCC_KEY")
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 24*1024*1024 {
		return errors.New("upload one nonempty release up to 24 MB")
	}
	options := map[string]any{"intensity": *intensity, "honey_maps": !*noHoney, "llm_directives": *directives}
	if *seed != "" {
		options["seed"] = *seed
	}
	opts, _ := json.Marshal(options)
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	if err = mw.WriteField("action", action); err != nil {
		return err
	}
	if err = mw.WriteField("options", string(opts)); err != nil {
		return err
	}
	part, err := mw.CreateFormFile("binary", filepath.Base(pos[0]))
	if err != nil {
		return err
	}
	if _, err = part.Write(data); err != nil {
		return err
	}
	if err = mw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest("POST", strings.TrimRight(base, "/")+"/api/release", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 96*1024*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 96*1024*1024 {
		return errors.New("release response exceeds size limit")
	}
	var result struct {
		OK       bool   `json:"ok"`
		Error    string `json:"error"`
		Artifact string `json:"artifact_b64"`
		Receipt  struct {
			SHA256 string `json:"artifact_sha256"`
		} `json:"receipt"`
		Upgrade string `json:"upgrade_url"`
		Label   string `json:"action_label"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("invalid release response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 || !result.OK {
		if result.Upgrade != "" {
			root, _ := url.Parse(strings.TrimRight(base, "/") + "/")
			link, e := url.Parse(result.Upgrade)
			if e == nil && root != nil {
				link = root.ResolveReference(link)
				if link.Scheme == "http" || link.Scheme == "https" {
					return fmt.Errorf("%s\n%s: %s", result.Error, result.Label, link.String())
				}
			}
		}
		return fmt.Errorf("release failed (HTTP %d): %s", resp.StatusCode, result.Error)
	}
	if action == "protect" {
		artifact, e := base64.StdEncoding.DecodeString(result.Artifact)
		if e != nil || len(artifact) == 0 {
			return errors.New("runner returned no valid release artifact")
		}
		hash := sha256.Sum256(artifact)
		if result.Receipt.SHA256 != hex.EncodeToString(hash[:]) {
			return errors.New("release artifact SHA-256 does not match receipt")
		}
		mode := os.FileMode(0644)
		if info, e := os.Stat(pos[0]); e == nil {
			mode = info.Mode().Perm()
		}
		f, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if e != nil {
			return e
		}
		_, e = f.Write(artifact)
		closeErr := f.Close()
		if e != nil {
			os.Remove(*output)
			return e
		}
		if closeErr != nil {
			os.Remove(*output)
			return closeErr
		}
		// Keep reports compact; they never embed a second copy of the artifact.
		var report map[string]json.RawMessage
		json.Unmarshal(raw, &report)
		delete(report, "artifact_b64")
		raw, _ = json.MarshalIndent(report, "", "  ")
		fmt.Fprintf(os.Stderr, "Shielded release: %s\nRun application tests before signing and shipping.\n", *output)
	}
	if *receipt != "" {
		f, e := os.OpenFile(*receipt, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(append(raw, '\n'))
		closeErr := f.Close()
		if e != nil {
			return e
		}
		return closeErr
	}
	fmt.Println(string(raw))
	return nil
}
