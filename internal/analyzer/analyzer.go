package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
)

type Severity int

type Finding struct {
	Rule     string
	File     string
	Line     int
	Severity Severity
	Message  string
}

type Analyzer interface {
	Name() string
	Analyze(path string, content []byte) []Finding
}

const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	default:
		return "unknown"
	}
}

func isBinary(content []byte) bool {
	return bytes.IndexByte(content, 0) != -1
}

type Bidi struct{}

func (Bidi) Name() string {
	return "bidi-unicode"
}

func isBidiRune(r rune) bool {
	return (r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069')
}

func (a Bidi) Analyze(path string, content []byte) []Finding {
	if isBinary(content) {
		return nil
	}

	var findings []Finding

	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		if bytes.ContainsFunc(line, isBidiRune) {
			findings = append(findings, Finding{
				Rule:     a.Name(),
				File:     path,
				Line:     i + 1,
				Severity: High,
				Message:  "caracter unicode de control bidireccional detectado",
			})
		}
	}

	return findings
}

var (
	reDownload = regexp.MustCompile(`(?i)\b(curl|wget|iwr|Invoke-WebRequest|DownloadString)\b`)
	reExec     = regexp.MustCompile(`(?i)(\|\s*(sudo\s+)?(sh|bash|zsh)\b|\b(iex|Invoke-Expression)\b)`)
)

type DownloadExec struct{}

func (DownloadExec) Name() string {
	return "dowload-exec"
}

func (a DownloadExec) Analyze(path string, content []byte) []Finding {

	if isBinary(content) {
		return nil
	}

	var findings []Finding

	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		if reDownload.Match(line) && reExec.Match(line) {
			findings = append(findings, Finding{
				Rule:     a.Name(),
				File:     path,
				Line:     i + 1,
				Severity: High,
				Message:  "descarga y ejecución en la misma línea",
			})
		}
	}

	return findings
}

var reNetCmd = regexp.MustCompile(`(?i)\b(curl|wget)\b`)

type InstallHooks struct{}

func (InstallHooks) Name() string {
	return "install-hooks"
}

func (a InstallHooks) Analyze(path string, content []byte) []Finding {
	if filepath.Base(path) != "package.json" {
		return nil
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}

	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil
	}

	var findings []Finding

	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		cmd, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}

		sev := Medium

		if reNetCmd.MatchString(cmd) {
			sev = High
		}

		findings = append(findings, Finding{
			Rule:     a.Name(),
			File:     path,
			Line:     0,
			Severity: sev,
			Message:  fmt.Sprintf("script de instalación %s detectado: %s", hook, cmd),
		})
	}

	return findings
}

var reToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]+`)

type Entropy struct {
	MinLen    int
	Threshold float64
}

func (Entropy) Name() string {
	return "high-entropy"
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}

	var counts [256]int

	for _, c := range b {
		counts[c]++
	}

	n := float64(len(b))

	var entropy float64

	for _, count := range counts {
		if count > 0 {
			p := float64(count) / n
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (a Entropy) Analyze(path string, content []byte) []Finding {
	if isBinary(content) {
		return nil
	}

	minLen := a.MinLen

	if minLen == 0 {
		minLen = 40
	}

	threshold := a.Threshold
	if threshold == 0 {
		threshold = 4.5
	}

	var findings []Finding

	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		tokens := reToken.FindAll(line, -1)
		for _, tok := range tokens {
			if len(tok) < minLen {
				continue
			}

			ent := shannonEntropy(tok)

			if ent >= threshold {
				findings = append(findings, Finding{
					Rule:     a.Name(),
					File:     path,
					Line:     i + 1,
					Severity: Medium,
					Message:  fmt.Sprintf("cadena con alta entropía (%.2f) detectada: ", ent),
				})

				break
			}
		}
	}

	return findings
}

func All() []Analyzer {
	return []Analyzer{
		Bidi{},
		DownloadExec{},
		InstallHooks{},
		Entropy{},
	}
}
