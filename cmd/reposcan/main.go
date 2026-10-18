// Comando reposcan: escanea un repositorio (remoto o local) en busca de
// patrones sospechosos.
//
// Uso:
//
//	reposcan [-json] [-ignore <archivo>] <url>
//	reposcan [-json] [-ignore <archivo>] -dir <ruta>
//
// Códigos de salida: 0 sin hallazgos, 1 con hallazgos, 2 error.
//
// Los comentarios "PASO 5" marcan lo que cambió respecto a tu versión.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	// PASO 5: ya no importamos cmp ni slices aquí. El orden ahora es
	// responsabilidad de report.New.
	"github.com/divan1319/repo-scan/internal/analyzer"
	"github.com/divan1319/repo-scan/internal/fetch"
	"github.com/divan1319/repo-scan/internal/ignore"
	"github.com/divan1319/repo-scan/internal/report"
	"github.com/divan1319/repo-scan/internal/walk"
)

func run(args []string, stdout, stderr io.Writer) int {

	fs := flag.NewFlagSet("reposcan", flag.ContinueOnError)

	fs.SetOutput(stderr)

	dirFlag := fs.String("dir", "", "analiza un directorio local (sin red)")

	// PASO 5: dos flags nuevos.
	//
	// fs.Bool crea un flag booleano: basta con escribir -json (no hace
	// falta -json=true). fs.String exige un valor: -ignore <archivo>.
	jsonFlag := fs.Bool("json", false, "escribe el reporte en JSON")
	ignoreFlag := fs.String("ignore", "", "archivo de supresiones (debe estar FUERA del repo)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	posArgs := fs.Args()

	if (*dirFlag != "" && len(posArgs) > 0) || (*dirFlag == "" && len(posArgs) != 1) {
		fmt.Fprintln(stderr, "uso: reposcan [-json] [-ignore archivo] <url> | reposcan [-json] [-ignore archivo] -dir <path>")
		return 2
	}

	// PASO 5: cargar las reglas de supresión ANTES de clonar.
	//
	// Por qué antes: si el archivo de reglas tiene un error, preferimos
	// fallar de inmediato y no después de descargar un repo de varios MB.
	// Regla general: valida toda la configuración al principio.
	//
	// `var rules ignore.Rules` es el valor cero: sin reglas, Match siempre
	// devuelve false. Así, más abajo, llamamos a rules.Match sin preguntar
	// si el usuario pasó -ignore o no. Un if menos.
	//
	// SEGURIDAD: el único lugar de donde se leen reglas es el flag -ignore.
	// Nunca buscamos un .reposcanignore dentro de targetDir.
	var rules ignore.Rules
	if *ignoreFlag != "" {
		f, err := os.Open(*ignoreFlag)
		if err != nil {
			// El error de os.Open ya incluye la ruta:
			// "open /x/no-existe: no such file or directory".
			fmt.Fprintln(stderr, err)
			return 2
		}

		rules, err = ignore.Parse(f)

		// Cerramos aquí y no con defer: el archivo solo se necesita para
		// Parse, y run sigue corriendo mucho rato después (clonar,
		// analizar). Un defer lo mantendría abierto hasta el final de run.
		f.Close()

		if err != nil {
			// Anteponemos el nombre del archivo: "reglas.txt: línea 2: ...".
			fmt.Fprintf(stderr, "%s: %v\n", *ignoreFlag, err)
			return 2
		}
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

	// PASO 5: separamos lo que se reporta de lo que se suprime.
	//
	// Filtramos aquí, dentro del callback, en vez de juntar todo y filtrar
	// después: así nunca guardamos en memoria hallazgos que no vamos a usar.
	// Para los suprimidos solo necesitamos el número, no los hallazgos.
	var kept []analyzer.Finding
	suppressed := 0

	skipped, err := walk.Walk(targetDir, func(rel string, data []byte) {
		for _, a := range analyzers {
			for _, f := range a.Analyze(rel, data) {
				if rules.Match(f) {
					suppressed++
					continue
				}
				kept = append(kept, f)
			}
		}
	})

	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	// PASO 5: report.New ordena, normaliza slices nil y cuenta por
	// severidad. Lo que antes hacía main a mano.
	rep := report.New(kept, skipped, suppressed)

	if *jsonFlag {
		// En modo JSON, stdout debe contener SOLO el JSON, para poder hacer
		// `reposcan -json ... | jq`. Los omitidos ya van dentro del JSON
		// (campo "skipped"), así que no los repetimos en stderr.
		if err := rep.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		// Reportar archivos omitidos por tamaño o permisos en stderr
		for _, rel := range rep.Skipped {
			fmt.Fprintf(stderr, "omitido: %s\n", rel)
		}

		// El formato de texto que antes estaba aquí ahora vive en
		// report.WriteText.
		if err := rep.WriteText(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	// PASO 5: informar SIEMPRE cuántos se suprimieron, en los dos modos.
	// Una herramienta de seguridad no debe esconder cosas en silencio: si
	// alguien te pasa un archivo de reglas con "*", este mensaje lo delata.
	// Va a stderr porque es información para el humano, no un hallazgo.
	if suppressed > 0 {
		fmt.Fprintf(stderr, "suprimidos: %d\n", suppressed)
	}

	// PASO 5: el código de salida solo cuenta lo que se REPORTA. Si el
	// usuario suprimió todo, ya decidió que no le importa: código 0.
	//
	// Antes había un `return 0` temprano cuando no había hallazgos. Ahora
	// no conviene: en modo JSON hay que imprimir el reporte vacío igual
	// ("findings": []), y el mensaje de suprimidos también debe salir.
	if len(rep.Findings) > 0 {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
