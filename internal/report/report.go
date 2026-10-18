// Package report presenta los hallazgos de un escaneo, en texto o en JSON.
//
// Separación de responsabilidades:
//   - analyzer decide QUÉ es sospechoso.
//   - ignore decide qué se SUPRIME.
//   - report decide CÓMO se muestra (y en qué orden).
//
// main solo conecta las piezas. Gracias a eso, cada parte se testea por
// separado y cambiar el formato de salida no obliga a tocar los analizadores.
package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/divan1319/repo-scan/internal/analyzer"
)

// Summary cuenta los hallazgos por severidad.
//
// Usamos un struct y no un map[string]int por dos razones:
//  1. Las tres claves SIEMPRE aparecen en el JSON, aunque valgan 0. Con un
//     map, una severidad sin hallazgos podría faltar, y quien consume el
//     JSON tendría que manejar ese caso.
//  2. encoding/json escribe los campos de un struct en el orden en que
//     están declarados: la salida es siempre la misma, fácil de comparar.
//     (Para maps, json ordena las claves alfabéticamente, así que el orden
//     sería high, low, medium: estable, pero menos natural.)
type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// Report es el resultado completo de un escaneo, listo para mostrarse.
//
// Los campos son exportados (empiezan con mayúscula) porque encoding/json
// solo puede ver campos exportados. Un campo en minúscula se ignora en
// silencio al serializar: es un error muy común al empezar con Go.
type Report struct {
	Findings   []analyzer.Finding `json:"findings"`
	Skipped    []string           `json:"skipped"`
	Suppressed int                `json:"suppressed"`
	Summary    Summary            `json:"summary"`
}

// New arma un Report a partir de los hallazgos ya filtrados.
//
// Garantías:
//   - Findings sale ordenado por archivo y luego por línea.
//   - No modifica los slices que recibe.
//   - Findings y Skipped nunca son nil (en JSON salen como [] y no null).
func New(findings []analyzer.Finding, skipped []string, suppressed int) Report {
	// slices.Clone hace una copia del slice. Es necesario porque
	// slices.SortStableFunc ordena EN EL LUGAR: modifica el arreglo que hay
	// debajo del slice. Un slice en Go es una "vista" (puntero + longitud +
	// capacidad) sobre un arreglo; si ordenáramos `findings` directamente,
	// quien llamó a New vería su propio slice reordenado.
	//
	// Detalle útil: slices.Clone(nil) devuelve nil, no un slice vacío. Por
	// eso el chequeo de abajo.
	fs := slices.Clone(findings)
	if fs == nil {
		// nil y vacío se comportan igual con len, range y append...
		// pero json.Marshal escribe nil como null y []T{} como [].
		fs = []analyzer.Finding{}
	}

	// SortStableFunc recibe una función de comparación que devuelve:
	//   negativo si a va antes que b, 0 si son "iguales", positivo si a va
	//   después.
	//
	// cmp.Compare hace exactamente eso para strings y números.
	// cmp.Or devuelve el primer valor que no sea cero: si los archivos son
	// distintos, decide el archivo; si son iguales (Compare devolvió 0),
	// pasa a comparar la línea. Es la forma idiomática de ordenar por
	// varios criterios (Go 1.22+).
	//
	// "Stable" significa que dos hallazgos con mismo archivo y línea
	// conservan su orden original (el de All()). Así la salida es
	// determinista: siempre la misma para el mismo repo.
	slices.SortStableFunc(fs, func(a, b analyzer.Finding) int {
		return cmp.Or(
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
		)
	})

	sk := slices.Clone(skipped)
	if sk == nil {
		sk = []string{}
	}

	// Contamos sobre fs (lo que SÍ se reporta). Los suprimidos ya no están
	// aquí: el resumen describe la salida, no todo lo que se encontró.
	var sum Summary // valor cero: todos los contadores en 0
	for _, f := range fs {
		switch f.Severity {
		case analyzer.High:
			sum.High++
		case analyzer.Medium:
			sum.Medium++
		case analyzer.Low:
			sum.Low++
		}
		// Una severidad desconocida (0) no se cuenta en ninguna categoría.
		// No debería pasar: el valor cero de Severity existe justo para que
		// un error así se note ("unknown" en la salida).
	}

	return Report{
		Findings:   fs,
		Skipped:    sk,
		Suppressed: suppressed,
		Summary:    sum,
	}
}

// WriteText escribe un hallazgo por línea, en el formato de compiladores:
//
//	archivo:línea: [severidad] regla: mensaje
//	archivo: [severidad] regla: mensaje          (si Line == 0)
//
// Recibe un io.Writer (no un *os.File) para poder escribir en cualquier
// lado: os.Stdout en el programa, un bytes.Buffer en los tests, un archivo,
// una conexión de red...
//
// Solo escribe hallazgos. Los omitidos y suprimidos son mensajes para el
// humano y main los manda a stderr.
func (r Report) WriteText(w io.Writer) error {
	for _, f := range r.Findings {
		// %s con f.Severity llama a su método String() (fmt.Stringer).
		var err error
		if f.Line == 0 {
			_, err = fmt.Fprintf(w, "%s: [%s] %s: %s\n", f.File, f.Severity, f.Rule, f.Message)
		} else {
			_, err = fmt.Fprintf(w, "%s:%d: [%s] %s: %s\n", f.File, f.Line, f.Severity, f.Rule, f.Message)
		}
		// Fprintf puede fallar (disco lleno, pipe cerrado: por ejemplo
		// `reposcan ... | head -1`). Devolvemos el error y que decida main.
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON escribe el reporte completo como JSON indentado.
//
// Usamos json.Encoder en lugar de json.Marshal porque Encoder permite
// configurar dos cosas que Marshal no:
//
//   - SetIndent: salida legible y fácil de comparar en un diff.
//   - SetEscapeHTML(false): por defecto, encoding/json escapa <, > y &
//     como \u003c, \u003e y \u0026, para que el JSON se pueda
//     incrustar sin peligro dentro de HTML. Aquí no lo necesitamos, y
//     escapar estorba: un comando con "<(" o "&&" saldría como "\u003c("
//     o "\u0026\u0026", y un grep por "<(" no lo encontraría. El JSON
//     es válido en ambos casos.
//
// Encode agrega un salto de línea al final, como espera cualquier
// herramienta de línea de comandos.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ") // sin prefijo, 2 espacios por nivel
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
