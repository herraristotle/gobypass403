/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// progressFileName is the resume checkpoint that lives in the run's outdir.
// It is a sidecar on purpose: the findings DB schema stays untouched, and
// deleting the file simply means "scan everything again".
const progressFileName = "scan.progress.json"

// progressVersion is the checkpoint format this build reads and writes.
const progressVersion = 1

// progressPair is one completed (target, module) unit of work.
type progressPair struct {
	TargetURL string `json:"target_url"`
	Module    string `json:"module"`
}

// progressDocument is the on-disk shape of scan.progress.json. It is written
// with a stable order and no timestamps so two identical runs produce
// identical files.
type progressDocument struct {
	Version   int            `json:"version"`
	Completed []progressPair `json:"completed"`
}

// Progress is the resume checkpoint for a run: the (target_url, module) pairs
// that already finished. A nil *Progress means checkpointing is off, which is
// why the methods are nil-safe: the caller never has to branch.
//
// It is safe for concurrent use, since Phase D's target workers mark pairs
// from several goroutines.
type Progress struct {
	path string

	mu        sync.Mutex
	completed map[string]progressPair
}

// ProgressPath returns the checkpoint path for a run's outdir.
func ProgressPath(outDir string) string {
	return filepath.Join(outDir, progressFileName)
}

// LoadProgress reads a checkpoint. A missing or empty file is a first run and
// returns no error. A file that exists but cannot be understood is reported
// (the caller warns and rescans) while still returning a usable, empty
// checkpoint, so a damaged checkpoint can never block a scan.
func LoadProgress(path string) (*Progress, error) {
	p := &Progress{path: path, completed: make(map[string]progressPair)}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, fmt.Errorf("cannot read resume checkpoint %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return p, nil
	}

	var doc progressDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return p, fmt.Errorf("resume checkpoint %s is unreadable (%v); rescanning", path, err)
	}
	if doc.Version != progressVersion {
		return p, fmt.Errorf("resume checkpoint %s has version %d, want %d; rescanning",
			path, doc.Version, progressVersion)
	}

	for _, pair := range doc.Completed {
		if pair.TargetURL == "" || pair.Module == "" {
			continue
		}
		p.completed[progressKey(pair.TargetURL, pair.Module)] = pair
	}
	return p, nil
}

// progressKey keys a pair by module and target, both exactly as given: no
// prefix or case folding, so two different URLs on one host stay distinct.
func progressKey(targetURL, module string) string {
	return module + "\x00" + targetURL
}

// Has reports whether this (target, module) pair already finished.
func (p *Progress) Has(targetURL, module string) bool {
	if p == nil || targetURL == "" || module == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	_, ok := p.completed[progressKey(targetURL, module)]
	return ok
}

// Mark records a finished (target, module) pair. It only touches memory; call
// Save to make it durable.
func (p *Progress) Mark(targetURL, module string) {
	if p == nil || targetURL == "" || module == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.completed[progressKey(targetURL, module)] = progressPair{TargetURL: targetURL, Module: module}
}

// Count reports how many pairs are marked complete.
func (p *Progress) Count() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.completed)
}

// Save writes the checkpoint atomically: a temp file in the same directory is
// renamed over the target, so a reader (or a crash) never sees a half-written
// checkpoint, and an interrupted save leaves the previous one intact.
func (p *Progress) Save() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	pairs := make([]progressPair, 0, len(p.completed))
	for _, pair := range p.completed {
		pairs = append(pairs, pair)
	}
	p.mu.Unlock()

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].TargetURL != pairs[j].TargetURL {
			return pairs[i].TargetURL < pairs[j].TargetURL
		}
		return pairs[i].Module < pairs[j].Module
	})

	data, err := json.MarshalIndent(progressDocument{Version: progressVersion, Completed: pairs}, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode resume checkpoint: %w", err)
	}
	data = append(data, '\n')

	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("cannot write resume checkpoint %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot replace resume checkpoint %s: %w", p.path, err)
	}
	return nil
}
