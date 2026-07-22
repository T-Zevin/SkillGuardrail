// Package progress renders a small terminal-only progress indicator.
//
// Progress is deliberately written to stderr so reports sent to stdout (or
// redirected to JSON/SARIF files) remain machine-readable. It is disabled for
// non-interactive writers and never changes scan behaviour.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	barWidth   = 24
	frameEvery = 250 * time.Millisecond
)

// Indicator is an indeterminate, staged progress bar. The percentage marks
// the current phase; the animated frame and elapsed time reassure users while
// network fetches or large scans are still in progress.
type Indicator struct {
	w       io.Writer
	enabled bool

	mu      sync.Mutex
	running bool
	percent int
	label   string
	frame   int
	started time.Time
	done    chan struct{}
	wg      sync.WaitGroup
}

// New creates a progress indicator. Pass enabled=false for redirected output,
// JSON/SARIF reports, or CI logs where carriage-return updates are undesirable.
func New(w io.Writer, enabled bool) *Indicator {
	return &Indicator{w: w, enabled: enabled}
}

// EnabledForTerminal reports whether w is an interactive terminal. The CLI
// uses this to keep progress updates out of pipes, files, and CI output.
func EnabledForTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}

// Start begins rendering at percent (0-99) with the supplied phase label.
func (i *Indicator) Start(percent int, label string) {
	if !i.enabled {
		return
	}
	i.mu.Lock()
	i.percent = clampPercent(percent)
	i.label = label
	i.frame = 0
	i.started = time.Now()
	i.running = true
	i.done = make(chan struct{})
	i.wg.Add(1)
	i.renderLocked()
	i.mu.Unlock()
	go i.loop()
}

// Set changes the current staged percentage and label.
func (i *Indicator) Set(percent int, label string) {
	if !i.enabled {
		return
	}
	i.mu.Lock()
	if i.running {
		i.percent = clampPercent(percent)
		i.label = label
		i.renderLocked()
	}
	i.mu.Unlock()
}

// Finish stops the animation and prints a completed line.
func (i *Indicator) Finish(label string) {
	i.stop(100, "✓ "+label)
}

// Fail stops the animation and prints a failed line.
func (i *Indicator) Fail(label string) {
	i.stop(-1, "✗ "+label)
}

func (i *Indicator) loop() {
	defer i.wg.Done()
	ticker := time.NewTicker(frameEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			i.mu.Lock()
			if !i.running {
				i.mu.Unlock()
				return
			}
			i.frame++
			i.renderLocked()
			i.mu.Unlock()
		case <-i.done:
			return
		}
	}
}

func (i *Indicator) stop(percent int, label string) {
	if !i.enabled {
		return
	}
	i.mu.Lock()
	if !i.running {
		i.mu.Unlock()
		return
	}
	if percent >= 0 {
		i.percent = clampPercent(percent)
	}
	i.label = label
	i.running = false
	close(i.done)
	i.renderLocked()
	fmt.Fprintln(i.w)
	i.mu.Unlock()
	i.wg.Wait()
}

func (i *Indicator) renderLocked() {
	if i.w == nil {
		return
	}
	filled := (i.percent * barWidth) / 100
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	frame := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")[i.frame%10]
	elapsed := time.Since(i.started).Round(time.Second)
	fmt.Fprintf(i.w, "\r\033[2K%c [%s] %3d%% %-32s (%s)", frame, bar, i.percent, i.label, elapsed)
}

func clampPercent(percent int) int {
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}
