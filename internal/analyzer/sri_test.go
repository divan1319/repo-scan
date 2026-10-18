// Tests de la excepción SRI ("Subresource Integrity") en el analizador Entropy.
//
// ---------------------------------------------------------------------------
// El problema
// ---------------------------------------------------------------------------
//
// Los lockfiles guardan un hash de cada dependencia:
//
//	"integrity": "sha512-gJnl2DddbNolw5fU1cLC...o9HqQQ=="
//
// Un hash es indistinguible de datos aleatorios, así que Entropy lo marca
// (~5.4 de entropía). En un package-lock.json con 800 dependencias, son 800
// falsos positivos.
//
// ---------------------------------------------------------------------------
// La solución, y por qué tiene tres condiciones
// ---------------------------------------------------------------------------
//
// Entropy debe saltarse un token SOLO si se cumplen las tres:
//
//  1. La línea contiene la palabra "integrity" (sin distinguir mayúsculas).
//     Aparece en todos los formatos legítimos:
//     npm:  "integrity": "sha512-..."
//     yarn: integrity sha512-...
//     pnpm: resolution: {integrity: sha512-...}
//     HTML: <script src="..." integrity="sha384-...">
//
//  2. El token tiene la forma <algoritmo>-<base64>, con algoritmo sha1,
//     sha256, sha384 o sha512, y el base64 es VÁLIDO.
//
//  3. El base64 decodificado mide EXACTAMENTE lo que mide ese hash:
//     sha1 = 20 bytes, sha256 = 32, sha384 = 48, sha512 = 64.
//
// ¿Por qué no basta con "empieza con sha512-"? Porque entonces el atacante
// escribe "sha512-" delante de su payload en base64 y Entropy lo ignora.
// Una excepción en una herramienta de seguridad es una puerta: hay que
// pensar quién más puede pasar por ella.
//
//   - La condición 3 limita lo que cabe por la puerta: 64 bytes es muy poco
//     para un payload útil.
//   - La condición 1 evita que cualquier string con forma de hash en
//     cualquier archivo quede excluido.
//   - La excepción es POR TOKEN, no por línea: si en una línea con
//     "integrity" hay además otro string sospechoso, se reporta.
//
// Limitación que queda (documéntala en tu código): un atacante podría partir
// un payload en muchos trozos de 64 bytes, cada uno en una línea con la
// palabra "integrity", y unirlos en tiempo de ejecución. Es más trabajo y
// deja otras huellas (el código que los une), pero esta regla sola no lo ve.
//
// Herramientas que vas a usar:
//   - bytes.Cut para separar "sha512" de la parte base64.
//   - encoding/base64: base64.StdEncoding.DecodeString valida caracteres y
//     relleno (=) por ti. Mejor que un regex hecho a mano.
//   - Un map[string]int de algoritmo -> bytes esperados.
//
// Cómo correrlos:
//
//	go test ./internal/analyzer -run 'TestEntropySRI|TestIsSRIHash' -v
package analyzer

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"
)

// Generamos hashes REALES en vez de pegar strings mágicos en el test.
// Así cada caso es correcto por construcción, y si alguien lee el test
// entiende de dónde sale cada valor.
//
// sha512.Sum512 devuelve un [64]byte (un ARRAY, no un slice). La sintaxis
// sum[:] crea un slice que apunta a ese array, que es lo que pide
// EncodeToString.
func sri512(seed string) string {
	sum := sha512.Sum512([]byte(seed))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func sri384(seed string) string {
	sum := sha512.Sum384([]byte(seed)) // SHA-384 vive en el paquete sha512
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
}

func sri256(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func sri1(seed string) string {
	sum := sha1.Sum([]byte(seed))
	return "sha1-" + base64.StdEncoding.EncodeToString(sum[:])
}

// payloadB64 simula un payload ofuscado: 192 bytes "aleatorios" (tres hashes
// pegados) en base64. Son 256 caracteres, muy por encima de los 88 de un
// sha512 real.
func payloadB64() string {
	var b []byte
	for _, s := range []string{"a", "b", "c"} {
		sum := sha512.Sum512([]byte(s))
		b = append(b, sum[:]...)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// isSRIHash: la función auxiliar, probada sola
// ---------------------------------------------------------------------------

// Firma esperada (no exportada, por eso la prueba este archivo en el mismo
// paquete):
//
//	func isSRIHash(tok []byte) bool
//
// Solo verifica el FORMATO del token (condiciones 2 y 3). La condición 1, la
// palabra "integrity", depende de la línea y se revisa en Analyze.
func TestIsSRIHash(t *testing.T) {
	valid512 := sri512("x")
	b64 := strings.TrimPrefix(valid512, "sha512-")

	tests := []struct {
		name string
		tok  string
		want bool
	}{
		{"sha512 real", valid512, true},
		{"sha384 real", sri384("x"), true},
		{"sha256 real", sri256("x"), true},
		{"sha1 real (lockfiles viejos de npm)", sri1("x"), true},

		// Longitud incorrecta: el truco del prefijo falso.
		{"payload largo con prefijo sha512", "sha512-" + payloadB64(), false},
		// Base64 válido de 64 bytes, pero con la etiqueta de otro algoritmo.
		// El algoritmo y la longitud tienen que corresponder.
		{"64 bytes etiquetados como sha256", "sha256-" + b64, false},
		{"algoritmo inventado", "sha999-" + b64, false},
		{"sin algoritmo", b64, false},
		// Mayúsculas: el estándar usa minúsculas. No seamos más permisivos
		// que los programas que generan estos hashes.
		{"algoritmo en mayúsculas", "SHA512-" + b64, false},
		// '_' no pertenece al base64 estándar (sí al "URL-safe", que SRI no
		// usa). Misma longitud, pero inválido: DecodeString debe fallar.
		{"base64 con caracter inválido", "sha512-_" + b64[1:], false},
		// Sin el relleno "==" final ya no es base64 estándar válido.
		{"base64 sin relleno", "sha512-" + strings.TrimRight(b64, "="), false},
		{"vacío después del guion", "sha512-", false},
		{"vacío", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSRIHash([]byte(tt.tok)); got != tt.want {
				t.Errorf("isSRIHash(%q) = %v, want %v", tt.tok, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Entropy.Analyze con la excepción
// ---------------------------------------------------------------------------

func TestEntropySRI(t *testing.T) {
	h512 := sri512("lodash")
	h384 := sri384("cdn")
	payload := payloadB64()

	tests := []struct {
		name    string
		path    string
		content string
		want    []string // usa summarize y none de analyzer_test.go
	}{
		// ----- Casos legítimos: no deben reportarse -----
		{
			name: "package-lock.json",
			path: "web/package-lock.json",
			content: "{\n" +
				`  "node_modules/lodash": {` + "\n" +
				`    "version": "4.17.21",` + "\n" +
				`    "integrity": "` + h512 + `"` + "\n" +
				"  }\n}\n",
			want: none,
		},
		{
			name:    "yarn.lock",
			path:    "yarn.lock",
			content: "lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity " + h512 + "\n",
			want:    none,
		},
		{
			name:    "pnpm-lock.yaml",
			path:    "pnpm-lock.yaml",
			content: "  /lodash@4.17.21:\n    resolution: {integrity: " + h512 + "}\n",
			want:    none,
		},
		{
			// Mayúsculas en "Integrity": la palabra se busca sin distinguirlas.
			name:    "script con integrity en HTML",
			path:    "index.html",
			content: `<script src="https://cdn.example.invalid/x.js" Integrity="` + h384 + `" crossorigin="anonymous"></script>` + "\n",
			want:    none,
		},
		{
			// pnpm y otros pueden listar varios hashes en una línea.
			name:    "dos hashes válidos en la misma línea",
			path:    "pnpm-lock.yaml",
			content: "integrity: " + h512 + " " + sri512("otro") + "\n",
			want:    none,
		},

		// ----- Evasiones: deben reportarse -----
		{
			// La línea tiene "integrity" y el token empieza con "sha512-",
			// pero mide 263 caracteres: no es un hash sha512.
			name:    "payload disfrazado con prefijo sha512",
			path:    "index.js",
			content: `const integrity = "sha512-` + payload + `";` + "\n",
			want:    []string{"1:medium"},
		},
		{
			// Formato perfecto de hash, pero sin la palabra "integrity" en la
			// línea. Lo reportamos: es más conservador, y un hash suelto en el
			// código merece una mirada.
			name:    "hash perfecto sin la palabra integrity",
			path:    "index.js",
			content: `const k = "` + h512 + `";` + "\n",
			want:    []string{"1:medium"},
		},
		{
			// La excepción es POR TOKEN. El hash se salta, pero el otro string
			// de la misma línea sí se evalúa. Si tu código hace `continue`
			// con toda la línea al ver "integrity", este caso lo detecta.
			name:    "hash válido y otro token sospechoso en la misma línea",
			path:    "package-lock.json",
			content: `"integrity": "` + h512 + `", "x": "` + payload + `"` + "\n",
			want:    []string{"1:medium"},
		},
		{
			// "integrity" se busca POR LÍNEA, no en todo el archivo. Aquí la
			// línea 2 tiene un token con formato de hash perfecto, pero sin
			// la palabra "integrity" en ESA línea, así que debe reportarse.
			// Si buscas la palabra en todo el contenido, la línea 1 "protegería"
			// a todo el archivo y este caso falla.
			name:    "integrity en la línea 1 no protege la línea 2",
			path:    "package-lock.json",
			content: `"integrity": "` + h512 + `",` + "\n" + `"otro": "` + sri512("oculto") + `"` + "\n",
			want:    []string{"2:medium"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, Entropy{}, tt.path, tt.content, tt.want)
		})
	}
}
