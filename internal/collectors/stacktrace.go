package collectors

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

var (
	goFrameRe   = regexp.MustCompile(`^\s*(?P<file>[^\s:]+\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-fA-F]+)?`)
	goFuncRe    = regexp.MustCompile(`^(?P<func>[a-zA-Z0-9_./*-]+)\([^)]*\)\s*$`)
	goPanicRe   = regexp.MustCompile(`^panic:\s*(?P<msg>.+)$`)
	pyFrameRe   = regexp.MustCompile(`^\s*File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>.+))?$`)
	pyErrRe     = regexp.MustCompile(`^(?P<type>[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Panic)):\s*(?P<msg>.+)$`)
	callFrameRe = regexp.MustCompile(`^\s*at\s+(?:(?P<func>[^\s(]+)\s+\()?(?P<file>[^():\n]+\.[a-zA-Z0-9_-]+):(?P<line>\d+)(?::\d+)?\)?`)
	javaFrameRe = regexp.MustCompile(`^\s*at\s+(?P<func>[\w.$<>]+)\((?P<file>[\w.$]+\.java):(?P<line>\d+)\)`)
	rustFrameRe = regexp.MustCompile(`^\s*(?:at\s+)?(?P<file>[^\s:]+\.rs):(?P<line>\d+)(?::\d+)?`)
)

func NormalizeFilePath(p string) string {
	cleaned := strings.ReplaceAll(p, "\\", "/")
	cleaned = strings.TrimSpace(cleaned)
	for strings.HasPrefix(cleaned, "./") {
		cleaned = cleaned[2:]
	}
	return cleaned
}

func ParseStackTrace(text string) *models.ParsedStackTrace {
	if strings.TrimSpace(text) == "" {
		return nil
	}

	lines := strings.Split(text, "\n")
	var frames []models.StackFrame
	errorType := ""
	errorMessage := ""
	language := "unknown"
	pendingGoFunc := ""

	if strings.Contains(text, "Traceback (most recent call last):") {
		language = "python"
	}

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r\n")

		if errorMessage == "" {
			if m := goPanicRe.FindStringSubmatch(strings.TrimSpace(line)); len(m) > 1 {
				errorType = "panic"
				errorMessage = strings.TrimSpace(m[1])
				language = "go"
				continue
			}
			if m := pyErrRe.FindStringSubmatch(strings.TrimSpace(line)); len(m) > 2 {
				errorType = m[1]
				errorMessage = strings.TrimSpace(m[2])
				continue
			}
		}

		// Python frame
		if m := pyFrameRe.FindStringSubmatch(line); len(m) > 2 {
			language = "python"
			lineNum, _ := strconv.Atoi(m[2])
			fn := ""
			if len(m) > 3 {
				fn = strings.TrimSpace(m[3])
			}
			frames = append(frames, models.StackFrame{
				File:     NormalizeFilePath(m[1]),
				Line:     lineNum,
				Function: fn,
				Language: "python",
				Raw:      strings.TrimSpace(line),
			})
			continue
		}

		// Go function name before file:line
		if m := goFuncRe.FindStringSubmatch(strings.TrimSpace(line)); len(m) > 1 {
			fn := m[1]
			if strings.Contains(fn, "/") || strings.Contains(fn, ".") {
				pendingGoFunc = fn
				continue
			}
		}

		// Go frame
		if m := goFrameRe.FindStringSubmatch(line); len(m) > 2 {
			language = "go"
			lineNum, _ := strconv.Atoi(m[2])
			frames = append(frames, models.StackFrame{
				File:     NormalizeFilePath(m[1]),
				Line:     lineNum,
				Function: pendingGoFunc,
				Language: "go",
				Raw:      strings.TrimSpace(line),
			})
			pendingGoFunc = ""
			continue
		}

		// Call frame (Universal: Node/TS, Sentry, Python formatted, etc.)
		if m := callFrameRe.FindStringSubmatch(line); len(m) > 2 {
			subexp := callFrameRe.SubexpNames()
			var fn, file, lineStr string
			for i, name := range subexp {
				if i >= len(m) {
					continue
				}
				switch name {
				case "func":
					fn = m[i]
				case "file":
					file = m[i]
				case "line":
					lineStr = m[i]
				}
			}

			normFile := NormalizeFilePath(file)
			lineNum, _ := strconv.Atoi(lineStr)
			detectedLang := language
			if detectedLang == "unknown" {
				if strings.HasSuffix(normFile, ".js") || strings.HasSuffix(normFile, ".ts") || strings.HasSuffix(normFile, ".tsx") {
					detectedLang = "javascript"
				} else if strings.HasSuffix(normFile, ".py") {
					detectedLang = "python"
				} else if strings.HasSuffix(normFile, ".go") {
					detectedLang = "go"
				}
			}
			if language == "unknown" && detectedLang != "unknown" {
				language = detectedLang
			}

			frames = append(frames, models.StackFrame{
				File:     normFile,
				Line:     lineNum,
				Function: strings.TrimSpace(fn),
				Language: detectedLang,
				Raw:      strings.TrimSpace(line),
			})
			continue
		}

		// Java frame
		if m := javaFrameRe.FindStringSubmatch(line); len(m) > 3 {
			language = "java"
			lineNum, _ := strconv.Atoi(m[3])
			frames = append(frames, models.StackFrame{
				File:     NormalizeFilePath(m[2]),
				Line:     lineNum,
				Function: m[1],
				Language: "java",
				Raw:      strings.TrimSpace(line),
			})
			continue
		}

		// Rust frame
		if m := rustFrameRe.FindStringSubmatch(line); len(m) > 2 {
			language = "rust"
			lineNum, _ := strconv.Atoi(m[2])
			frames = append(frames, models.StackFrame{
				File:     NormalizeFilePath(m[1]),
				Line:     lineNum,
				Function: "",
				Language: "rust",
				Raw:      strings.TrimSpace(line),
			})
			continue
		}
	}

	if len(frames) == 0 && errorMessage == "" {
		return nil
	}

	if errorMessage == "" && len(lines) > 0 {
		errorMessage = strings.TrimSpace(lines[0])
	}

	return &models.ParsedStackTrace{
		ErrorType:    errorType,
		ErrorMessage: errorMessage,
		Language:     language,
		Frames:       frames,
	}
}
