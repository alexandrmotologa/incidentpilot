package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStackTraceParsing(t *testing.T) {
	// Go panic
	goTrace := "panic: runtime error: invalid memory address or nil pointer dereference\n" +
		"github.com/acme/checkout/pkg/checkout.Charge(0x0)\n" +
		"\t/app/pkg/checkout/checkout.go:114 +0x2c\n"
	stGo := ParseStackTrace(goTrace)
	if stGo == nil || stGo.Language != "go" || len(stGo.Frames) != 1 {
		t.Fatalf("failed to parse Go panic: %+v", stGo)
	}
	if stGo.Frames[0].Line != 114 {
		t.Errorf("expected line 114, got: %d", stGo.Frames[0].Line)
	}

	// Python traceback
	pyTrace := "Traceback (most recent call last):\n" +
		"  File \"/srv/app/orders/processor.py\", line 73, in submit\n" +
		"    return total / count\n" +
		"ZeroDivisionError: division by zero"
	stPy := ParseStackTrace(pyTrace)
	if stPy == nil || stPy.Language != "python" || len(stPy.Frames) != 1 {
		t.Fatalf("failed to parse Python trace: %+v", stPy)
	}
	if stPy.Frames[0].Line != 73 || stPy.Frames[0].Function != "submit" {
		t.Errorf("unexpected python frame: %+v", stPy.Frames[0])
	}

	// Universal call frame (Node / Sentry)
	nodeTrace := "TypeError: Cannot read properties of undefined (reading 'id')\n" +
		"    at processCheckout (/app/src/checkout.ts:42:17)\n"
	stNode := ParseStackTrace(nodeTrace)
	if stNode == nil || stNode.Language != "javascript" || len(stNode.Frames) != 1 {
		t.Fatalf("failed to parse Node trace: %+v", stNode)
	}
	if stNode.Frames[0].Line != 42 {
		t.Errorf("expected line 42, got: %d", stNode.Frames[0].Line)
	}
}

func TestJsonlCollector(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log.jsonl")

	now := time.Now().UTC()
	lines := []string{
		`{"timestamp":"` + now.Add(-30*time.Minute).Format(time.RFC3339) + `","level":"ERROR","service":"checkout","message":"too old"}`,
		`{"timestamp":"` + now.Add(-5*time.Minute).Format(time.RFC3339) + `","level":"INFO","service":"checkout","message":"info message"}`,
		`{"timestamp":"` + now.Add(-3*time.Minute).Format(time.RFC3339) + `","level":"ERROR","service":"checkout","message":"nil pointer dereference"}`,
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(logFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	collector := &JsonlLogCollector{FilePath: logFile}
	entries, err := collector.FetchErrorLogs(context.Background(), "checkout", now.Add(-15*time.Minute), now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("FetchErrorLogs failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Message != "nil pointer dereference" {
		t.Errorf("unexpected log message: %s", entries[0].Message)
	}
}
