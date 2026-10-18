// Tests para el paquete ignore: supresión de falsos positivos.
//
// ---------------------------------------------------------------------------
// Regla de seguridad: el archivo de supresiones NO viene del repo escaneado
// ---------------------------------------------------------------------------
//
// Si reposcan leyera un .reposcanignore DENTRO del repo, un atacante solo
// tendría que agregar uno que diga "*" junto a su curl|sh y el escáner no
// diría nada. Por eso:
//
//   - El archivo se pasa con un flag: reposcan -ignore ~/reposcan.ignore ...
//   - Este paquete solo parsea un io.Reader: no sabe ni le importa de dónde
//     viene el contenido. Decidir de dónde se lee es trabajo de main.
//   - main cuenta los hallazgos suprimidos y los informa. Nada desaparece en
//     silencio.
//
// ---------------------------------------------------------------------------
// Formato del archivo
// ---------------------------------------------------------------------------
//
//	# comentario (líneas vacías y que empiezan con # se ignoran)
//	vendor/                      todo lo que esté bajo vendor/ (desde la raíz)
//	*_test.go                    sin "/": se compara contra el NOMBRE del archivo,
//	                             en cualquier carpeta (como en .gitignore)
//	internal/*.go                con "/": se compara contra la ruta COMPLETA
//	package.json install-hooks   segundo campo opcional: solo esa regla
//
// Las rutas usan "/" siempre, también en Windows (filepath.ToSlash).
//
// ---------------------------------------------------------------------------
// Contrato
// ---------------------------------------------------------------------------
//
//	type Rules struct { ... }   // los campos son cosa tuya (no exportados)
//
//	func Parse(r io.Reader) (Rules, error)
//	func (rs Rules) Match(f analyzer.Finding) bool
//
// El valor cero de Rules (sin parsear nada) no suprime nada. Así main puede
// declarar `var rules ignore.Rules` y llamar a rules.Match sin un if.
//
// Herramientas:
//   - bufio.Scanner para leer línea por línea (aquí las líneas son cortas,
//     así que el límite de 64 KB no es problema).
//   - strings.Fields para separar los campos (ignora espacios repetidos).
//   - path.Match para los globs. OJO: el paquete "path", no "path/filepath".
//     path siempre usa "/"; filepath usa el separador del sistema.
//   - path.Base para el nombre del archivo.
//
// Cómo correrlos:
//
//	go test ./internal/ignore -v
package ignore

import (
	"strings"
	"testing"

	"github.com/divan1319/repo-scan/internal/analyzer"
)

// parse es un atajo para los tests: parsea un string o falla el test.
func parse(t *testing.T, text string) Rules {
	t.Helper()
	// strings.NewReader convierte un string en un io.Reader.
	rs, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse falló: %v", err)
	}
	return rs
}

// ---------------------------------------------------------------------------
// Parse: errores con número de línea
// ---------------------------------------------------------------------------

// Cuando un archivo de configuración tiene un error, el mensaje debe decir
// EN QUÉ LÍNEA. "patrón inválido" sin más obliga a revisar el archivo entero.
func TestParseErrores(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantLine string // texto que debe aparecer en el error
	}{
		{
			name:     "demasiados campos",
			text:     "# comentario\n\nvendor/ install-hooks extra\n",
			wantLine: "línea 3",
		},
		{
			// "[" abre una clase de caracteres que nunca se cierra.
			// path.Match devuelve path.ErrBadPattern. Detéctalo al PARSEAR,
			// no cuando ya estás escaneando. Pista: path.Match(patrón, "").
			name:     "glob inválido",
			text:     "ok.txt\n[abc\n",
			wantLine: "línea 2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.text))
			if err == nil {
				t.Fatal("se esperaba un error")
			}
			if !strings.Contains(err.Error(), tt.wantLine) {
				t.Errorf("el error debe mencionar %q, got: %v", tt.wantLine, err)
			}
		})
	}
}

func TestParseVacioYComentarios(t *testing.T) {
	// Un archivo sin reglas reales es válido y no suprime nada.
	rs := parse(t, "# solo comentarios\n\n   \n# otro\n")
	f := analyzer.Finding{Rule: "download-exec", File: "a.sh", Line: 1}
	if rs.Match(f) {
		t.Error("un archivo sin reglas no debe suprimir nada")
	}
}

// El valor cero de Rules debe ser usable.
func TestValorCero(t *testing.T) {
	var rs Rules
	if rs.Match(analyzer.Finding{Rule: "x", File: "y"}) {
		t.Error("Rules{} no debe suprimir nada")
	}
}

// ---------------------------------------------------------------------------
// Match
// ---------------------------------------------------------------------------

func TestMatch(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		file  string
		rule  string // regla del hallazgo
		want  bool
	}{
		// ----- Carpetas (patrón que termina en /) -----
		{"carpeta: archivo dentro", "vendor/", "vendor/lib/x.js", "high-entropy", true},
		// Prefijo de texto no es lo mismo que carpeta: "vendorx" no está
		// dentro de "vendor/". Si comparas con HasPrefix(file, "vendor")
		// sin la barra, este caso falla.
		{"carpeta: nombre parecido", "vendor/", "vendorx/a.js", "high-entropy", false},
		// La carpeta se cuenta desde la raíz del repo.
		{"carpeta: anidada no cuenta", "vendor/", "src/vendor/a.js", "high-entropy", false},

		// ----- Sin "/": contra el nombre del archivo -----
		{"nombre: en la raíz", "*_test.go", "a_test.go", "bidi-unicode", true},
		// path.Match("*_test.go", "internal/x/a_test.go") es false porque
		// * no cruza "/". Por eso, sin "/" en el patrón, compara con path.Base.
		{"nombre: en subcarpeta", "*_test.go", "internal/x/a_test.go", "bidi-unicode", true},
		{"nombre: no coincide", "*_test.go", "internal/x/a.go", "bidi-unicode", false},

		// ----- Con "/": contra la ruta completa -----
		{"ruta: mismo nivel", "internal/*.go", "internal/a.go", "high-entropy", true},
		{"ruta: * no cruza /", "internal/*.go", "internal/x/a.go", "high-entropy", false},
		{"ruta exacta", "docs/ejemplo.sh", "docs/ejemplo.sh", "download-exec", true},
		{"ruta exacta: otro archivo", "docs/ejemplo.sh", "docs/otro.sh", "download-exec", false},

		// ----- Filtro por regla (segundo campo) -----
		{"regla: coincide", "package.json install-hooks", "package.json", "install-hooks", true},
		// Suprimir el hook de instalación NO debe esconder otros hallazgos
		// del mismo archivo, por ejemplo un secreto.
		{"regla: otra regla del mismo archivo", "package.json install-hooks", "package.json", "high-entropy", false},

		// ----- Varias reglas: basta con que una coincida -----
		{"varias: la segunda", "vendor/\n*.md\n", "README.md", "high-entropy", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := parse(t, tt.rules)
			f := analyzer.Finding{Rule: tt.rule, File: tt.file, Line: 1, Severity: analyzer.High}
			if got := rs.Match(f); got != tt.want {
				t.Errorf("reglas %q, hallazgo %s (%s): Match = %v, want %v",
					tt.rules, tt.file, tt.rule, got, tt.want)
			}
		})
	}
}
