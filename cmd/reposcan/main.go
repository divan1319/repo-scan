package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"

	"github.com/divan1319/repo-scan/internal/analyzer"
	"github.com/divan1319/repo-scan/internal/fetch"
	"github.com/divan1319/repo-scan/internal/walk"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {

	fs := flag.NewFlagSet("reposcan", flag.ContinueOnError)

	fs.SetOutput(stderr)

	dirFlag := fs.String("dir", "", "analiza un directorio local (sin red)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	posArgs := fs.Args()

	if (*dirFlag != "" && len(posArgs) > 0) || (*dirFlag == "" && len(posArgs) != 1) {
		fmt.Fprintln(stderr, "uso: reposcan <url> | reposcan -dir <path>")
		return 2
	}

	targetDir := *dirFlag

	if targetDir == "" {
		canonURL, err := fetch.ValidateURL(posArgs[0])

		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}

		tmpDir, err := os.MkdirTemp("", "reposcan-*")

		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}

		defer os.RemoveAll(tmpDir)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

		defer stop()

		if err := fetch.Clone(ctx, canonURL, tmpDir); err != nil {
			fmt.Fprintln(stderr, err)

			return 2
		}

		targetDir = tmpDir
	}

	// Analizar el directorio (local o clonado)

	analyzers := analyzer.All()

	var findings []analyzer.Finding

	skipped, err := walk.Walk(targetDir, func(rel string, data []byte) {
		for _, a := range analyzers {
			findings = append(findings, a.Analyze(rel, data)...)
		}
	})

	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	// Reportar archivos omitidos por tamaño o permisos en stderr

	for _, rel := range skipped {
		fmt.Fprintf(stderr, "omitido: %s\n", rel)
	}

	if len(findings) == 0 {
		return 0
	}

	// Ordenar por archivo y luego por número de línea
	slices.SortStableFunc(findings, func(a, b analyzer.Finding) int {
		return cmp.Or(
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
		)
	})

	// Imprimir hallazagos en stdout

	for _, f := range findings {
		if f.Line == 0 {
			fmt.Fprintf(stdout, "%s: [%s] %s: %s\n", f.File, f.Severity, f.Rule, f.Message)
		} else {
			fmt.Fprintf(stdout, "%s:%d: [%s] %s: %s\n", f.File, f.Line, f.Severity, f.Rule, f.Message)
		}
	}

	return 1
}
