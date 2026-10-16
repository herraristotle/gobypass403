/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Internal test for setupOutputDir's error reporting.

Why: passing `-o` a path that already exists as a *file* surfaced the raw
syscall error ("mkdir /path: not a directory"), which reads as an internal
failure and never says the real cause -- the operator pointed -o at a file.
The message must name the path and the actual problem.
*/
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupOutputDirRejectsExistingFileWithClearError(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not_a_dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	o := &CliOptions{OutDir: filePath}
	err := o.setupOutputDir()
	if err == nil {
		t.Fatalf("setupOutputDir on an existing file must fail")
	}

	msg := err.Error()
	if !strings.Contains(msg, filePath) {
		t.Errorf("error must name the offending path %q; got %q", filePath, msg)
	}
	if !strings.Contains(msg, "exists and is not a directory") {
		t.Errorf("error must state the real cause (a file, not a directory); got %q", msg)
	}
	if strings.Contains(msg, "failed to create output directory") {
		t.Errorf("error must not wrap it as a generic create failure; got %q", msg)
	}
}

func TestSetupOutputDirCreatesMissingDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "a", "b", "c")

	o := &CliOptions{OutDir: target}
	if err := o.setupOutputDir(); err != nil {
		t.Fatalf("setupOutputDir on a fresh path must succeed: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		t.Fatalf("target directory was not created: %v", err)
	}
}

func TestSetupOutputDirAcceptsExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	o := &CliOptions{OutDir: dir}
	if err := o.setupOutputDir(); err != nil {
		t.Fatalf("setupOutputDir on an existing directory must succeed: %v", err)
	}
}
