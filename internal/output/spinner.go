package output

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner displays an animated spinner with elapsed time on stderr.
type Spinner struct {
	message string
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewSpinner creates and starts a spinner with the given message.
func NewSpinner(message string) *Spinner {
	s := &Spinner{
		message: message,
		done:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s
}

// Stop stops the spinner and clears the line.
func (s *Spinner) Stop(finalMessage string) {
	close(s.done)
	s.wg.Wait()
	fmt.Fprintf(os.Stderr, "\r\033[K")
	if finalMessage != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", finalMessage)
	}
}

func (s *Spinner) run() {
	defer s.wg.Done()
	start := time.Now()
	frame := 0
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			elapsed := int(time.Since(start).Seconds())
			fmt.Fprintf(os.Stderr, "\r\033[K  %s %s (%ds)", spinnerFrames[frame%len(spinnerFrames)], s.message, elapsed)
			frame++
		}
	}
}

// ProgressSpinner displays a spinner with a live counter (done/total).
type ProgressSpinner struct {
	total     int
	done      atomic.Int32
	errors    atomic.Int32
	inflight  atomic.Int32
	cancelled atomic.Bool
	stop      chan struct{}
	wg        sync.WaitGroup
}

// NewProgressSpinner creates and starts a progress spinner.
func NewProgressSpinner(total int) *ProgressSpinner {
	s := &ProgressSpinner{
		total: total,
		stop:  make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s
}

// AddInflight increments the in-flight request counter.
func (s *ProgressSpinner) AddInflight() {
	s.inflight.Add(1)
}

// Increment marks one more file as completed (and decrements in-flight).
func (s *ProgressSpinner) Increment() {
	s.done.Add(1)
	s.inflight.Add(-1)
}

// IncrementError marks one more file as failed (and decrements in-flight).
func (s *ProgressSpinner) IncrementError() {
	s.errors.Add(1)
	s.inflight.Add(-1)
}

// SetCancelled marks the spinner as cancelled (waiting for in-flight requests).
func (s *ProgressSpinner) SetCancelled() {
	s.cancelled.Store(true)
}

// Stop stops the spinner and prints the final summary.
func (s *ProgressSpinner) Stop() {
	close(s.stop)
	s.wg.Wait()
	fmt.Fprintf(os.Stderr, "\r\033[K")
	done := int(s.done.Load())
	errs := int(s.errors.Load())
	if errs > 0 {
		fmt.Fprintf(os.Stderr, "  Analyzed %d/%d files (%d errors)\n", done, s.total, errs)
	} else {
		fmt.Fprintf(os.Stderr, "  Analyzed %d/%d files\n", done, s.total)
	}
}

func (s *ProgressSpinner) run() {
	defer s.wg.Done()
	start := time.Now()
	frame := 0
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			elapsed := int(time.Since(start).Seconds())
			done := s.done.Load()
			errs := s.errors.Load()
			suffix := ""
			if errs > 0 {
				suffix = fmt.Sprintf(", %d errors", errs)
			}
			if s.cancelled.Load() {
				inflight := s.inflight.Load()
				fmt.Fprintf(os.Stderr, "\r\033[K  %s Stopping - waiting for %d in-flight request(s) [%d/%d done%s] (%ds)",
					spinnerFrames[frame%len(spinnerFrames)], inflight, done, s.total, suffix, elapsed)
			} else {
				fmt.Fprintf(os.Stderr, "\r\033[K  %s Analyzing [%d/%d%s] (%ds)",
					spinnerFrames[frame%len(spinnerFrames)], done, s.total, suffix, elapsed)
			}
			frame++
		}
	}
}
