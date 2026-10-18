// Package ignore decide qué hallazgos suprimir, a partir de un archivo de
// reglas que escribe el USUARIO.
//
// Regla de seguridad: este archivo nunca debe venir del repo escaneado. Si
// reposcan leyera un .reposcanignore dentro del repo, el atacante podría
// silenciar su propio código malicioso. Por eso este paquete no abre
// archivos: solo parsea un io.Reader. Decidir de dónde se lee (un flag
// -ignore, fuera del repo) es responsabilidad de main.
//
// Formato, una regla por línea:
//
//	# comentario
//	vendor/                      carpeta (termina en /), desde la raíz
//	*_test.go                    sin /: contra el nombre del archivo
//	internal/*.go                con /: contra la ruta completa
//	package.json install-hooks   segundo campo opcional: solo esa regla
package ignore

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/divan1319/repo-scan/internal/analyzer"
)

// entry es una regla ya parseada. No se exporta: quien usa el paquete no
// necesita conocer la representación interna, solo Parse y Match. Eso nos
// deja cambiarla después (por ejemplo, para soportar "**") sin romper a
// nadie.
type entry struct {
	pattern string // glob, o carpeta si termina en "/"
	rule    string // "" = aplica a cualquier regla
}

// Rules es un conjunto de reglas de supresión.
//
// Envolvemos el slice en un struct (en vez de `type Rules []entry`) para que
// el campo quede privado: nadie de fuera puede agregar o modificar entradas
// sin pasar por Parse, que es donde se validan.
//
// El valor cero, Rules{}, tiene entries == nil, y recorrer un slice nil con
// range simplemente no hace nada. Así que Rules{}.Match siempre devuelve
// false sin ningún caso especial: un "valor cero útil".
type Rules struct {
	entries []entry
}

// Parse lee reglas desde r. Devuelve un error que indica la línea si alguna
// regla está mal escrita.
//
// Validamos todo AQUÍ, al arrancar, y no después en Match. Si un patrón es
// inválido, es mejor que el programa se niegue a correr ("línea 4: patrón
// inválido") a que escanee con una regla rota y el usuario crea que algo
// estaba suprimido cuando no.
func Parse(r io.Reader) (Rules, error) {
	var rs Rules

	// bufio.Scanner lee línea por línea. Su límite de 64 KB por línea no es
	// problema aquí: una regla nunca mide eso. (En los analizadores sí lo
	// era, por los archivos minificados; por eso allí usamos bytes.Split.)
	sc := bufio.NewScanner(r)

	// Contamos TODAS las líneas, incluidas vacías y comentarios, para que el
	// número del error coincida con el que muestra tu editor.
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// strings.Fields separa por cualquier cantidad de espacios o tabs,
		// así "vendor/    install-hooks" funciona igual que con uno solo.
		fields := strings.Fields(line)
		if len(fields) > 2 {
			return Rules{}, fmt.Errorf("línea %d: se esperaba \"<patrón> [regla]\", hay %d campos", lineNo, len(fields))
		}

		e := entry{pattern: fields[0]}
		if len(fields) == 2 {
			e.rule = fields[1]
		}

		// Las carpetas ("vendor/") se comparan como prefijo, no como glob,
		// así que no hace falta validarlas.
		//
		// Para los globs usamos un truco: path.Match valida el patrón
		// completo antes de comparar, así que path.Match(patrón, "") devuelve
		// path.ErrBadPattern si el patrón está mal (por ejemplo "[abc" sin
		// cerrar), sin importar el texto contra el que se compara.
		if !strings.HasSuffix(e.pattern, "/") {
			if _, err := path.Match(e.pattern, ""); err != nil {
				// %w envuelve el error original: quien lo reciba puede usar
				// errors.Is(err, path.ErrBadPattern) si le interesa.
				return Rules{}, fmt.Errorf("línea %d: patrón inválido %q: %w", lineNo, e.pattern, err)
			}
		}

		rs.entries = append(rs.entries, e)
	}

	// sc.Scan() devuelve false tanto al llegar al final como ante un error
	// de lectura. sc.Err() distingue los dos casos (nil = fin normal).
	// Olvidar este chequeo es un error clásico con bufio.Scanner.
	if err := sc.Err(); err != nil {
		return Rules{}, err
	}
	return rs, nil
}

// Match indica si el hallazgo f debe suprimirse.
func (rs Rules) Match(f analyzer.Finding) bool {
	// Walk devuelve rutas con el separador del sistema ("\" en Windows).
	// Las reglas siempre usan "/", así que normalizamos antes de comparar.
	file := filepath.ToSlash(f.File)

	for _, e := range rs.entries {
		// Si la regla nombra un analizador, solo aplica a ese. Así
		// "package.json install-hooks" no esconde, por ejemplo, un secreto
		// detectado por high-entropy en el mismo archivo.
		if e.rule != "" && e.rule != f.Rule {
			continue
		}

		switch {
		case strings.HasSuffix(e.pattern, "/"):
			// Carpeta. Comparamos con la barra incluida: "vendor/" coincide
			// con "vendor/x.js" pero no con "vendorx/x.js". Si quitáramos la
			// barra, HasPrefix("vendorx/x.js", "vendor") sería true: bug.
			if strings.HasPrefix(file, e.pattern) {
				return true
			}

		case !strings.Contains(e.pattern, "/"):
			// Sin "/": contra el nombre del archivo, en cualquier carpeta.
			// Necesario porque en path.Match el * NO cruza "/":
			//   path.Match("*_test.go", "internal/a_test.go") == false
			//   path.Match("*_test.go", "a_test.go")          == true
			// path.Base devuelve el último elemento: "a_test.go".
			//
			// El error de path.Match se ignora con _ porque ya validamos el
			// patrón en Parse: aquí no puede fallar.
			if ok, _ := path.Match(e.pattern, path.Base(file)); ok {
				return true
			}

		default:
			// Con "/": contra la ruta completa desde la raíz del repo.
			if ok, _ := path.Match(e.pattern, file); ok {
				return true
			}
		}
	}
	return false
}
