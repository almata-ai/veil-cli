package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// isTTY reports whether f is a terminal (so we only draw bars/spinners there).
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func humanBytes(n int64) string {
	const u = 1024.0
	units := []string{"B", "KB", "MB", "GB"}
	f, i := float64(n), 0
	for f >= u && i < len(units)-1 {
		f /= u
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", n, units[i])
	}
	return fmt.Sprintf("%.1f%s", f, units[i])
}

// progressReader wraps a reader and draws a tqdm-style upload bar to w as bytes are
// read by the HTTP transport. onDone fires once when the upload completes.
type progressReader struct {
	r        io.Reader
	total    int64
	read     int64
	last     time.Time
	w        io.Writer
	label    string
	onDone   func()
	doneSeen bool
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if time.Since(p.last) > 60*time.Millisecond || p.read >= p.total {
		p.draw()
		p.last = time.Now()
	}
	if p.read >= p.total && !p.doneSeen {
		p.doneSeen = true
		if p.onDone != nil {
			p.onDone()
		}
	}
	return n, err
}

func (p *progressReader) draw() {
	frac := 0.0
	if p.total > 0 {
		frac = float64(p.read) / float64(p.total)
	}
	if frac > 1 {
		frac = 1
	}
	const width = 24
	fill := int(frac * width)
	bar := strings.Repeat("█", fill) + strings.Repeat("░", width-fill)
	fmt.Fprintf(p.w, "\r  %s [%s] %3.0f%%  %s/%s", p.label, bar, frac*100, humanBytes(p.read), humanBytes(p.total))
}

// spinner animates a one-line "working" indicator until Stop is called.
type spinner struct {
	stop chan struct{}
	done chan struct{}
}

func startSpinner(w io.Writer, msg string) *spinner {
	s := &spinner{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		t := time.NewTicker(90 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			select {
			case <-s.stop:
				fmt.Fprint(w, "\r\033[K") // clear the line
				close(s.done)
				return
			case <-t.C:
				fmt.Fprintf(w, "\r  %c %s", frames[i%len(frames)], msg)
			}
		}
	}()
	return s
}

func (s *spinner) stopAndClear() {
	close(s.stop)
	<-s.done
}

// uploadBody wraps a request body with an upload bar + a processing spinner (shown
// after the upload finishes, while the runner works), when stderr is a TTY and the
// body is large enough to be worth it. Returns the reader to send and a cleanup func
// to call once the response has been received. For non-TTY / tiny bodies it's a no-op.
func uploadBody(body io.Reader, total int64, workingMsg string) (io.Reader, func()) {
	if !isTTY(os.Stderr) || total < 64*1024 {
		return body, func() {}
	}
	var sp *spinner
	pr := &progressReader{
		r: body, total: total, w: os.Stderr, label: "uploading",
		onDone: func() {
			fmt.Fprint(os.Stderr, "\r\033[K")
			sp = startSpinner(os.Stderr, workingMsg)
		},
	}
	cleanup := func() {
		if sp != nil {
			sp.stopAndClear()
		} else {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
	}
	return pr, cleanup
}
