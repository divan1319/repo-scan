// Package analyzer contiene los analizadores estáticos que repo-scan aplica
// sobre cada archivo de un repositorio para detectar patrones sospechosos o
// potencialmente maliciosos.
//
// # Modelo general
//
// Cada analizador implementa la interfaz [Analyzer]: recibe la ruta del
// archivo y su contenido completo en memoria, y devuelve una lista (posiblemente
// vacía) de [Finding]. Los analizadores son:
//
//   - Sin estado: no guardan información entre llamadas, por lo que una misma
//     instancia puede reutilizarse para todos los archivos e incluso usarse
//     desde varias goroutines a la vez.
//   - Independientes: ninguno depende del resultado de otro. El orquestador
//     (quien recorre el repositorio) decide cuáles ejecutar; normalmente se usa
//     [All] para obtener el conjunto por defecto.
//   - Tolerantes a fallos: si un archivo no aplica (binario, JSON inválido,
//     nombre que no corresponde, etc.) simplemente devuelven nil en lugar de
//     un error. Un archivo "raro" nunca debe detener el escaneo.
//
// # Analizadores incluidos
//
//   - [Bidi]: caracteres Unicode de control bidireccional (ataque "Trojan Source").
//   - [DownloadExec]: descarga y ejecución en la misma línea (`curl ... | sh`).
//   - [InstallHooks]: scripts de ciclo de vida de npm (preinstall/install/postinstall).
//   - [Entropy]: cadenas de alta entropía (posibles secretos o payloads ofuscados).
//
// # Cómo añadir un analizador nuevo
//
//  1. Definir un tipo (normalmente un struct vacío o con parámetros de configuración).
//  2. Implementar Name() con un identificador estable en kebab-case.
//  3. Implementar Analyze(path, content) devolviendo los hallazgos.
//  4. Registrarlo en [All] si debe ejecutarse por defecto.
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
)

// Severity indica qué tan grave es un hallazgo.
//
// Se representa como un entero para que las severidades puedan compararse y
// ordenarse de forma natural (Low < Medium < High), por ejemplo para filtrar
// "solo hallazgos de severidad Medium o superior" o para calcular un código de
// salida del programa.
//
// El valor cero (0) NO corresponde a ninguna severidad válida: las constantes
// empiezan en 1 a propósito (ver más abajo). Así, un Finding cuya severidad no
// fue asignada explícitamente se detecta fácilmente porque su String() devuelve
// "unknown".
type Severity int

// Finding representa un hallazgo individual producido por un analizador.
//
// Un mismo archivo puede generar varios Finding, ya sea del mismo analizador
// (por ejemplo, una línea sospechosa distinta cada vez) o de analizadores
// diferentes.
type Finding struct {
	// Rule es el identificador del analizador que generó el hallazgo.
	// Coincide con el valor devuelto por Analyzer.Name() (por ejemplo
	// "bidi-unicode" o "high-entropy"). Sirve para agrupar, filtrar o
	// suprimir hallazgos por regla.
	Rule string

	// File es la ruta del archivo analizado, tal cual se le pasó a Analyze.
	// El paquete no la normaliza: si el llamador pasa rutas relativas al
	// repositorio, aquí aparecerán relativas.
	File string

	// Line es el número de línea (empezando en 1) donde se encontró el
	// problema. El valor 0 tiene un significado especial: el hallazgo aplica
	// al archivo completo y no a una línea concreta (es el caso de
	// InstallHooks, que trabaja sobre el JSON ya parseado y no conoce las
	// posiciones originales).
	Line int

	// Severity es la gravedad estimada del hallazgo.
	Severity Severity

	// Message es una descripción legible para humanos, en español, que
	// explica qué se detectó.
	Message string
}

// Analyzer es la interfaz que deben implementar todos los analizadores.
type Analyzer interface {
	// Name devuelve un identificador corto, único y estable del analizador
	// (en kebab-case). Se copia en el campo Finding.Rule de cada hallazgo, por
	// lo que cambiarlo puede romper filtros o configuraciones de usuarios.
	Name() string

	// Analyze inspecciona un archivo y devuelve los hallazgos encontrados.
	//
	//   - path: ruta del archivo. Algunos analizadores la usan para decidir si
	//     el archivo les aplica (por ejemplo, InstallHooks solo mira
	//     "package.json"); otros solo la copian al Finding.
	//   - content: contenido completo del archivo. El analizador NO debe
	//     modificar este slice, ya que el mismo contenido se comparte con
	//     el resto de analizadores.
	//
	// Debe devolver nil (o un slice vacío) si no hay hallazgos o si el
	// archivo no aplica. Nunca debe entrar en pánico por un contenido
	// inesperado.
	Analyze(path string, content []byte) []Finding
}

// Niveles de severidad disponibles.
//
// Se usa `iota + 1` para que el primer valor sea 1 y no 0. De esta forma el
// valor cero de Severity queda reservado como "no asignado / desconocido".
const (
	// Low: algo poco habitual que merece un vistazo, pero que casi siempre
	// es legítimo.
	Low Severity = iota + 1

	// Medium: comportamiento con riesgo real que puede ser legítimo según el
	// contexto (por ejemplo, un hook de instalación o una cadena con aspecto
	// de secreto). Requiere revisión manual.
	Medium

	// High: patrón fuertemente asociado a ataques (por ejemplo, Trojan Source
	// o `curl | sh`). Debe revisarse antes de confiar en el repositorio.
	High
)

// String implementa fmt.Stringer para que una Severity se imprima de forma
// legible ("low", "medium", "high") en lugar de como número, tanto con
// fmt.Print/%v como en cualquier salida de texto.
//
// Cualquier valor fuera del rango conocido (incluido el valor cero) devuelve
// "unknown", lo que facilita detectar hallazgos mal construidos.
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

// isBinary aplica una heurística sencilla para decidir si un contenido es
// binario: considera binario cualquier contenido que contenga al menos un byte
// nulo (0x00).
//
// Es la misma heurística que usan herramientas como git o grep. Funciona bien
// en la práctica porque los archivos de texto (ASCII, UTF-8) prácticamente
// nunca contienen bytes nulos, mientras que los ejecutables, imágenes,
// archivos comprimidos, etc. casi siempre los tienen.
//
// Limitación conocida: los archivos de texto codificados en UTF-16/UTF-32
// contienen bytes nulos y serán tratados como binarios (y por tanto ignorados).
//
// Los analizadores basados en texto la usan para saltarse los binarios, lo que
// evita falsos positivos (un binario está lleno de "cadenas de alta entropía")
// y ahorra tiempo de procesamiento.
func isBinary(content []byte) bool {
	return bytes.IndexByte(content, 0) != -1
}

// ---------------------------------------------------------------------------
// Bidi: caracteres Unicode de control bidireccional ("Trojan Source")
// ---------------------------------------------------------------------------

// Bidi detecta caracteres Unicode de control bidireccional dentro de archivos
// de texto.
//
// # Por qué es peligroso
//
// Unicode define caracteres invisibles que alteran la dirección en la que se
// muestra el texto (pensados para mezclar idiomas de izquierda a derecha, como
// el español, con idiomas de derecha a izquierda, como el árabe o el hebreo).
// Un atacante puede insertarlos en el código fuente para que lo que el revisor
// VE en su editor sea distinto de lo que el compilador/intérprete EJECUTA.
// Por ejemplo, puede hacer que una instrucción real parezca estar dentro de un
// comentario, o que una comprobación de permisos parezca cerrarse antes de lo
// que realmente lo hace.
//
// Este ataque se conoce como "Trojan Source" (CVE-2021-42574). Como en código
// fuente legítimo estos caracteres son extremadamente raros, cualquier
// aparición se reporta con severidad High.
//
// # Comportamiento
//
//   - Ignora archivos binarios.
//   - Recorre el archivo línea por línea.
//   - Genera como máximo UN hallazgo por línea, aunque la línea contenga
//     varios caracteres bidi (lo importante es señalar la línea a revisar).
type Bidi struct{}

// Name devuelve el identificador de la regla: "bidi-unicode".
func (Bidi) Name() string {
	return "bidi-unicode"
}

// isBidiRune indica si r es uno de los caracteres de control bidireccional
// asociados al ataque Trojan Source. Cubre dos rangos contiguos:
//
//	U+202A  LRE  Left-to-Right Embedding
//	U+202B  RLE  Right-to-Left Embedding
//	U+202C  PDF  Pop Directional Formatting
//	U+202D  LRO  Left-to-Right Override
//	U+202E  RLO  Right-to-Left Override   (el más usado en ataques)
//
//	U+2066  LRI  Left-to-Right Isolate
//	U+2067  RLI  Right-to-Left Isolate
//	U+2068  FSI  First Strong Isolate
//	U+2069  PDI  Pop Directional Isolate
//
// No incluye las marcas de dirección simples (LRM U+200E, RLM U+200F,
// ALM U+061C), que son mucho menos potentes para este tipo de ataque.
//
// Caracteres Unicode "normales" como tildes, eñes o emojis NO están en estos
// rangos y por tanto no se consideran sospechosos.
func isBidiRune(r rune) bool {
	return (r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069')
}

// Analyze implementa Analyzer para Bidi.
func (a Bidi) Analyze(path string, content []byte) []Finding {
	// Los binarios pueden contener cualquier secuencia de bytes, incluidas
	// las que por casualidad decodifican como caracteres bidi. Se ignoran
	// para evitar falsos positivos.
	if isBinary(content) {
		return nil
	}

	var findings []Finding

	// Se divide por '\n'. Si el archivo usa finales de línea Windows (CRLF),
	// cada línea conservará un '\r' al final, lo cual no afecta a la búsqueda.
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		// bytes.ContainsFunc decodifica la línea como UTF-8 runa a runa y se
		// detiene en cuanto isBidiRune devuelve true. Esto garantiza un solo
		// hallazgo por línea sin importar cuántos caracteres bidi contenga.
		if bytes.ContainsFunc(line, isBidiRune) {
			findings = append(findings, Finding{
				Rule:     a.Name(),
				File:     path,
				Line:     i + 1, // i empieza en 0; las líneas se numeran desde 1.
				Severity: High,
				Message:  "caracter unicode de control bidireccional detectado",
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// DownloadExec: descarga + ejecución en la misma línea
// ---------------------------------------------------------------------------

// Expresiones regulares usadas por DownloadExec. Se compilan una única vez al
// cargar el paquete (regexp.MustCompile entra en pánico si el patrón es
// inválido, lo cual se detectaría inmediatamente al arrancar o en los tests).
//
// Ambas usan el flag (?i) para no distinguir mayúsculas de minúsculas, de modo
// que variantes como "CURL ... | SH" no esquiven la regla (PowerShell, además,
// es insensible a mayúsculas por diseño).
var (
	// reDownload detecta herramientas o funciones que descargan contenido
	// remoto:
	//   - curl, wget                → Unix/Linux/macOS.
	//   - iwr, Invoke-WebRequest    → PowerShell (iwr es el alias corto).
	//   - DownloadString            → método de System.Net.WebClient en
	//                                 PowerShell/.NET, muy usado en
	//                                 one-liners maliciosos.
	//
	// Los \b (límite de palabra) evitan coincidencias dentro de otras
	// palabras (por ejemplo, "libcurlx" no coincide con "curl").
	reDownload = regexp.MustCompile(`(?i)\b(curl|wget|iwr|Invoke-WebRequest|DownloadString)\b`)

	// reExec detecta que el contenido descargado se ejecuta directamente.
	// Es una alternancia (A|B|C) de tres formas de ejecución:
	//
	// A) Tubería hacia un shell:
	//
	//	\|\s*(sudo\s+(-[a-z0-9-]+\s+)*)?(/[a-z0-9._-]+/)?(sh|bash|zsh)\b
	//
	//	   \|\s*                    un "|" seguido de espacios opcionales.
	//	   (sudo\s+(-[a-z0-9-]+\s+)*)?
	//	                            sudo opcional, con cero o más flags SIN
	//	                            valor detrás ("-E", "-H", "--preserve-env").
	//	   (/[a-z0-9._-]+/)?        un único directorio absoluto opcional
	//	                            delante del shell ("/bin/").
	//	   (sh|bash|zsh)\b          el intérprete. El \b final hace que
	//	                            "| shasum" o "| /usr/bin/shasum" NO
	//	                            coincidan.
	//
	//	Ejemplos que coinciden: "| sh", "|bash", "| sudo bash",
	//	"| sudo -E bash", "| /bin/bash".
	//
	// B) Shell que recibe el script por sustitución de comandos o procesos
	// (sin "|" en la línea; es la forma que usa, por ejemplo, Homebrew):
	//
	//	\b(sh|bash|zsh)\s+(-c\s+)?["']?(\$\(|<\()
	//
	//	   (sh|bash|zsh)\s+         el intérprete seguido de espacios.
	//	   (-c\s+)?                 el flag -c opcional.
	//	   ["']?                    comilla opcional ("$(...)" suele ir citado).
	//	   (\$\(|<\()               inmediatamente $( (sustitución de comandos)
	//	                            o <( (sustitución de procesos).
	//
	//	Ejemplos: `bash -c "$(curl ...)"`, `sh -c "$(wget -qO- ...)"`,
	//	`bash <(curl ...)`.
	//
	//	Exigir que el $( o <( vaya JUSTO después del shell es lo que evita
	//	falsos positivos como `curl -o x.sh URL && echo "$(cat x.sh)"`, donde
	//	aparecen "sh" y "$(" en la misma línea pero nada ejecuta lo
	//	descargado.
	//
	// C) PowerShell:
	//
	//	\b(iex|Invoke-Expression)\b
	//
	//	Invoke-Expression (alias iex) evalúa una cadena como código. Cubre
	//	"iex (...DownloadString(...))" y "iwr ... | iex".
	//
	// Limitaciones conocidas (posibles evasiones aún no cubiertas):
	//   - Rutas con más de un directorio tras el "|": "| /usr/bin/bash" o
	//     "| /usr/local/bin/zsh" no coinciden, porque (/[a-z0-9._-]+/)? solo
	//     admite un segmento.
	//   - Flags de sudo con valor: "| sudo -u root bash" no coincide, porque
	//     "root" no empieza por "-".
	//   - Otros intérpretes (python, perl, node, dash, ksh, fish...) o
	//     "| env bash" no están contemplados.
	//   - Descarga y ejecución en líneas separadas (ver DownloadExec).
	reExec = regexp.MustCompile(`(?i)(\|\s*(sudo\s+(-[a-z0-9-]+\s+)*)?(/[a-z0-9._-]+/)?(sh|bash|zsh)\b|\b(sh|bash|zsh)\s+(-c\s+)?["']?(\$\(|<\()|\b(iex|Invoke-Expression)\b)`)
)

// DownloadExec detecta líneas que descargan contenido de Internet y lo
// ejecutan inmediatamente, sin guardarlo ni verificarlo. Ejemplos típicos:
//
//	curl -fsSL https://ejemplo.com/install.sh | sh
//	wget -qO- https://ejemplo.com/x | sudo bash
//	iex (New-Object Net.WebClient).DownloadString('https://ejemplo.com/x')
//	iwr https://ejemplo.com/x | iex
//
// # Por qué es peligroso
//
// Ejecutar código remoto sin revisarlo significa confiar ciegamente en el
// servidor (que puede estar comprometido o cambiar su contenido en cualquier
// momento). Es además la técnica más común con la que un script malicioso
// instala un payload de segunda etapa. Por eso se reporta como High.
//
// # Comportamiento
//
//   - Ignora archivos binarios.
//   - Analiza línea por línea: solo reporta si AMBAS condiciones (descarga y
//     ejecución) se cumplen en la MISMA línea. Una línea que solo descarga
//     ("curl -o archivo url") o que solo ejecuta ("bash script.sh") no
//     genera hallazgo. Esto reduce falsos positivos, a costa de no detectar
//     casos en que la descarga y la ejecución están en líneas separadas.
//   - Como máximo un hallazgo por línea.
//
// Variantes cubiertas además de las anteriores (ver reExec para el detalle):
//
//	curl -fsSL https://ejemplo.com/i.sh | /bin/bash
//	curl https://ejemplo.com/i.sh | sudo -E bash
//	/bin/bash -c "$(curl -fsSL https://ejemplo.com/install.sh)"
//	sh -c "$(wget -qO- https://ejemplo.com/i.sh)"
//	bash <(curl -s https://ejemplo.com/i.sh)
type DownloadExec struct{}

// Name devuelve el identificador de la regla: "download-exec".
//
// Este valor se copia en Finding.Rule; cambiarlo afecta a cualquier filtro
// o configuración que dependa del nombre de la regla (y a TestAll).
func (DownloadExec) Name() string {
	return "download-exec"
}

// Analyze implementa Analyzer para DownloadExec.
func (a DownloadExec) Analyze(path string, content []byte) []Finding {

	if isBinary(content) {
		return nil
	}

	var findings []Finding

	// Se trabaja por líneas para poder reportar el número de línea exacto y
	// para exigir que descarga y ejecución aparezcan juntas en la misma línea.
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		// Se evalúa primero reDownload: la mayoría de líneas no contienen
		// ninguna herramienta de descarga, así que el && corta la evaluación
		// pronto y reExec solo se ejecuta en las líneas candidatas.
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

// ---------------------------------------------------------------------------
// InstallHooks: scripts de instalación de npm
// ---------------------------------------------------------------------------

// reNetCmd detecta comandos de red (curl o wget) dentro de un script de
// instalación. Si un hook de npm los usa, la severidad del hallazgo sube de
// Medium a High. Es insensible a mayúsculas y usa límites de palabra.
var reNetCmd = regexp.MustCompile(`(?i)\b(curl|wget)\b`)

// InstallHooks detecta scripts de ciclo de vida de npm que se ejecutan
// automáticamente al instalar un paquete.
//
// # Por qué es peligroso
//
// Cuando se ejecuta `npm install`, npm corre automáticamente los scripts
// "preinstall", "install" y "postinstall" definidos en el package.json de cada
// dependencia, con los permisos del usuario que instala. Es el vector de
// ataque más frecuente en la cadena de suministro de npm: basta con publicar
// (o comprometer) un paquete y añadir un postinstall malicioso.
//
// # Severidad
//
//   - Medium: existe el hook. Muchos paquetes legítimos los usan (por ejemplo,
//     para compilar módulos nativos), así que requiere revisión pero no es
//     malicioso por sí mismo.
//   - High: el hook invoca curl o wget, es decir, descarga algo de Internet
//     durante la instalación, lo cual es mucho más sospechoso.
//
// # Comportamiento
//
//   - Solo analiza archivos cuyo nombre base sea exactamente "package.json"
//     (en cualquier directorio, incluidos los de dependencias anidadas).
//   - Si el JSON es inválido, lo ignora silenciosamente (no es tarea de este
//     analizador validar la sintaxis).
//   - Tolera scripts que no son strings: si OTRO script del objeto "scripts"
//     es un número, array, objeto, etc., se sigue analizando el resto (npm
//     hace lo mismo: ignora el valor inválido y ejecuta los hooks válidos).
//     Esto evita una evasión en la que un atacante añade algo como
//     `"x": 1` para que el parseo falle y el postinstall pase desapercibido.
//   - Si el propio hook no es un string (por ejemplo `"postinstall": 123`),
//     no se reporta: npm no tiene ningún comando que ejecutar.
//   - Los hallazgos se reportan con Line = 0, porque tras parsear el JSON no
//     se conoce la línea original del script; el hallazgo aplica al archivo.
//   - El mensaje incluye el nombre del hook y el comando completo, para que
//     el usuario pueda evaluarlo sin abrir el archivo.
type InstallHooks struct{}

// Name devuelve el identificador de la regla: "install-hooks".
func (InstallHooks) Name() string {
	return "install-hooks"
}

// Analyze implementa Analyzer para InstallHooks.
func (a InstallHooks) Analyze(path string, content []byte) []Finding {
	// filepath.Base extrae el último elemento de la ruta, así que coincide
	// con "package.json", "./package.json" o "node_modules/x/package.json".
	if filepath.Base(path) != "package.json" {
		return nil
	}

	// Struct anónimo con solo el campo que interesa. encoding/json ignora el
	// resto de claves del package.json (name, version, dependencies, ...),
	// lo que hace el parseo más simple y tolerante.
	//
	// Scripts se decodifica como map[string]any y NO como map[string]string
	// a propósito: con map[string]string, un solo valor que no sea string
	// (p. ej. `"x": 1` o `"x": ["a"]`) hace que json.Unmarshal devuelva error
	// y el analizador no reportaría nada, aunque npm sí ejecutaría los hooks.
	// Con any, cada valor se decodifica a su tipo natural de Go (string,
	// float64, []any, map[string]any, bool o nil) y luego se filtran solo
	// los strings (ver el type assertion más abajo).
	var pkg struct {
		Scripts map[string]any `json:"scripts"`
	}

	// Unmarshal solo falla ahora si el JSON está mal formado o si "scripts"
	// existe pero no es un objeto (por ejemplo, un string o un array). En
	// ese caso no se puede analizar: se devuelve nil sin reportar error.
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil
	}

	var findings []Finding

	// Se recorre una lista fija en lugar del map pkg.Scripts por dos motivos:
	//   1. Solo interesan los hooks que npm ejecuta automáticamente al
	//      instalar; otros scripts ("test", "build", ...) requieren que el
	//      usuario los invoque explícitamente.
	//   2. El orden de iteración de un map en Go es aleatorio; con un slice
	//      el orden de los hallazgos es determinista (preinstall → install →
	//      postinstall), que además es el orden real de ejecución de npm.
	//
	// Leer de un map nil (si el package.json no tiene "scripts") es seguro en
	// Go: simplemente devuelve ok == false.
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		// raw es de tipo any: puede contener cualquier valor JSON.
		raw, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}

		// Type assertion con la forma "comma ok": si raw no es un string,
		// ok es false (en lugar de entrar en pánico) y el hook se ignora,
		// porque npm no tendría ningún comando que ejecutar.
		cmd, ok := raw.(string)
		if !ok {
			continue // Si el hook es un número, array, etc., lo ignoramos
		}

		// Severidad base: la mera presencia del hook merece revisión.
		sev := Medium

		// Si el hook descarga algo de la red, se eleva a High.
		if reNetCmd.MatchString(cmd) {
			sev = High
		}

		findings = append(findings, Finding{
			Rule:     a.Name(),
			File:     path,
			Line:     0, // 0 = aplica al archivo completo (ver doc de Finding.Line).
			Severity: sev,
			Message:  fmt.Sprintf("script de instalación %s detectado: %s", hook, cmd),
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Entropy: cadenas de alta entropía
// ---------------------------------------------------------------------------

// reToken define qué se considera un "token" candidato a ser analizado por
// entropía: una secuencia continua de caracteres del alfabeto Base64 estándar
// (A-Z, a-z, 0-9, '+', '/', '=') y Base64 URL-safe ('-', '_').
//
// Cualquier otro carácter (espacios, comillas, puntos, dos puntos, paréntesis,
// etc.) actúa como separador. Gracias a esto:
//   - Una clave entre comillas (`"AKIA..."`) se extrae sin las comillas.
//   - Las URLs se fragmentan en trozos cortos (por ':' y '.'), por lo que
//     normalmente no alcanzan la longitud mínima.
var reToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]+`)

// Entropy detecta cadenas con una entropía de Shannon alta, que suelen
// corresponder a secretos incrustados en el código (API keys, tokens, claves
// privadas) o a payloads ofuscados/codificados (por ejemplo, un script
// malicioso en Base64).
//
// # Idea intuitiva
//
// La entropía mide qué tan "impredecible" es una cadena. El texto humano y los
// identificadores de código son muy repetitivos (ciertas letras aparecen mucho
// más que otras), así que tienen entropía baja. Una cadena generada
// aleatoriamente usa todos los símbolos de su alfabeto con frecuencias
// parecidas, así que su entropía se acerca al máximo posible.
//
// # Configuración
//
// Los campos son opcionales: su valor cero significa "usar el valor por
// defecto". Por eso Entropy{} (como se usa en All) es una configuración
// válida.
type Entropy struct {
	// MinLen es la longitud mínima (en bytes) que debe tener un token para ser
	// evaluado. Los tokens más cortos se ignoran porque con pocos caracteres
	// la entropía es poco fiable y generaría muchos falsos positivos.
	// Valor por defecto (si es 0): 40.
	MinLen int

	// Threshold es la entropía mínima (en bits por carácter) a partir de la
	// cual un token se reporta. Valor por defecto (si es 0): 4.5.
	//
	// Referencias útiles para elegir el umbral:
	//   - Entropía máxima de una cadena hexadecimal (16 símbolos): log2(16) = 4.0
	//   - Entropía máxima de una cadena Base64 (64 símbolos):     log2(64) = 6.0
	//   - Texto en inglés/español o identificadores típicos:      ~3.0 – 4.0
	//
	// Con el valor por defecto (4.5) se detectan cadenas tipo Base64, pero
	// NUNCA cadenas hexadecimales (hashes, UUIDs sin guiones, etc.), ya que
	// por definición no pueden superar 4.0. Para detectar secretos en hex hay
	// que bajar el umbral (por ejemplo, a 3.5), asumiendo más falsos
	// positivos.
	Threshold float64
}

// Name devuelve el identificador de la regla: "high-entropy".
func (Entropy) Name() string {
	return "high-entropy"
}

// shannonEntropy calcula la entropía de Shannon de b, medida en bits por byte,
// usando la fórmula:
//
//	H = -Σ p(x) · log2(p(x))
//
// donde p(x) es la frecuencia relativa de cada byte x dentro de b (número de
// apariciones de x dividido entre la longitud total).
//
// Propiedades del resultado:
//   - Vale 0 si b está vacío o si todos los bytes son iguales ("aaaa...").
//   - Su máximo es log2(k), donde k es el número de símbolos distintos que
//     aparecen; se alcanza cuando todos aparecen con la misma frecuencia.
//   - Nunca supera 8 (log2(256)), el máximo para bytes arbitrarios.
//
// Trabaja a nivel de byte, no de runa Unicode; para los tokens que produce
// reToken (solo ASCII) ambos son equivalentes.
func shannonEntropy(b []byte) float64 {
	// Evita la división por cero de más abajo.
	if len(b) == 0 {
		return 0
	}

	// Tabla de frecuencias: un contador por cada posible valor de byte.
	// Un array fijo en la pila es más rápido que un map para este caso.
	var counts [256]int

	for _, c := range b {
		counts[c]++
	}

	n := float64(len(b))

	var entropy float64

	for _, count := range counts {
		// Los bytes que no aparecen se saltan: aportan 0 a la suma
		// (lím p→0 de p·log2(p) = 0) y además log2(0) sería -Inf.
		if count > 0 {
			p := float64(count) / n
			// p está en (0, 1], así que log2(p) <= 0; se resta para que la
			// entropía resultante sea positiva.
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// Analyze implementa Analyzer para Entropy.
func (a Entropy) Analyze(path string, content []byte) []Finding {
	// Los binarios (imágenes, ejecutables, zips...) son por naturaleza de
	// alta entropía; analizarlos produciría ruido sin valor.
	if isBinary(content) {
		return nil
	}

	// Resolución de valores por defecto. Se hace en variables locales para no
	// modificar el receptor (que además es por valor) y mantener el
	// analizador sin estado.
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
		// FindAll con n = -1 devuelve todas las coincidencias no solapadas
		// de reToken en la línea, en orden de aparición.
		tokens := reToken.FindAll(line, -1)
		for _, tok := range tokens {
			// Filtro barato primero: descartar tokens cortos antes de
			// calcular la entropía.
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
					// Nota: el mensaje deliberadamente NO incluye el token,
					// ya que podría ser un secreto real y acabaría expuesto
					// en la salida/logs del escáner.
					Message: fmt.Sprintf("cadena con alta entropía (%.2f) detectada", ent),
				})

				// Basta con un hallazgo por línea: se deja de evaluar el
				// resto de tokens de esta línea y se pasa a la siguiente.
				break
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Registro de analizadores
// ---------------------------------------------------------------------------

// All devuelve el conjunto de analizadores que repo-scan ejecuta por defecto,
// cada uno con su configuración por defecto (por ejemplo, Entropy{} usa
// MinLen = 40 y Threshold = 4.5).
//
// Cada llamada devuelve un slice nuevo, así que el llamador puede modificarlo
// (filtrar, reordenar o añadir analizadores) sin afectar a otras llamadas.
//
// Al crear un analizador nuevo, hay que añadirlo aquí para que se ejecute
// automáticamente.
func All() []Analyzer {
	return []Analyzer{
		Bidi{},
		DownloadExec{},
		InstallHooks{},
		Entropy{},
	}
}
