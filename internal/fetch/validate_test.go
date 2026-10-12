// Archivo de tests para ValidateURL.
//
// Convenciones de Go que conviene saber:
//   - Los tests viven en archivos que terminan en _test.go. `go build` los
//     ignora; solo `go test` los compila.
//   - Este archivo declara `package fetch` (el mismo paquete que el código),
//     así que puede ver funciones y variables NO exportadas, como
//     `allowedHosts`. A esto se le llama "white-box testing".
//     (La alternativa es `package fetch_test`, que solo ve lo exportado,
//     como lo vería un usuario de tu paquete.)
//   - Una función de test empieza con `Test`, recibe `*testing.T` y no
//     devuelve nada. Una de fuzzing empieza con `Fuzz` y recibe `*testing.F`.
//
// Cómo correrlos (desde la raíz del proyecto):
//
//	go test ./internal/fetch -v                  -> todos los tests, con detalle
//	go test ./internal/fetch -run TestValidateURL -v
//	go test ./internal/fetch -run 'TestValidateURL/http_plano' -v  -> un solo caso
//	go test ./internal/fetch -fuzz=FuzzValidateURL -fuzztime=30s   -> fuzzing
package fetch

import (
	"net/url"
	"strings"
	"testing"
)

// TestValidateURL usa el patrón más común en Go: "table-driven tests".
// En vez de escribir una función por caso, defines una tabla (un slice de
// structs) con entradas y resultados esperados, y la recorres en un loop.
// Agregar un caso nuevo es agregar una línea a la tabla.
func TestValidateURL(t *testing.T) {
	// Struct anónimo: lo declaramos y lo usamos aquí mismo, no hace falta
	// darle un nombre de tipo porque solo existe para esta tabla.
	tests := []struct {
		name    string // nombre del caso; aparece en la salida de `go test -v`
		input   string // lo que el usuario escribiría
		want    string // URL normalizada esperada (solo si wantErr es false)
		wantErr bool   // true si esperamos que la función rechace la entrada
	}{
		// ---------- Casos válidos: deben aceptarse ----------
		{
			name:  "github básico",
			input: "https://github.com/owner/repo",
			want:  "https://github.com/owner/repo.git",
		},
		{
			name:  "github con .git al final",
			input: "https://github.com/owner/repo.git",
			want:  "https://github.com/owner/repo.git",
		},
		{
			// Los hosts no distinguen mayúsculas, así que esto es legítimo.
			name:  "host en mayúsculas y barra final",
			input: "https://GitHub.com/owner/repo/",
			want:  "https://github.com/owner/repo.git",
		},
		{
			// GitLab permite subgrupos anidados: grupo/subgrupo/proyecto.
			name:  "gitlab con subgrupo",
			input: "https://gitlab.com/grupo/subgrupo/proyecto",
			want:  "https://gitlab.com/grupo/subgrupo/proyecto.git",
		},

		// ---------- Casos inválidos: deben rechazarse ----------
		// Para estos solo importa wantErr; `want` queda vacío.
		{name: "http plano", input: "http://github.com/a/b", wantErr: true},
		{name: "esquema file", input: "file:///etc/passwd", wantErr: true},
		{name: "formato ssh", input: "git@github.com:a/b", wantErr: true},
		{name: "credenciales en la URL", input: "https://user:pass@github.com/a/b", wantErr: true},
		{name: "puerto explícito", input: "https://github.com:8443/a/b", wantErr: true},
		{name: "query string", input: "https://github.com/a/b?x=1", wantErr: true},
		{name: "fragmento", input: "https://github.com/a/b#readme", wantErr: true},
		{name: "host no permitido", input: "https://evil.com/a/b", wantErr: true},
		// Si compararas con strings.Contains, este pasaría. Debe fallar.
		{name: "host que imita a github", input: "https://github.com.evil.com/a/b", wantErr: true},
		{name: "path traversal", input: "https://github.com/a/../b", wantErr: true},
		{name: "solo owner", input: "https://github.com/solo-owner", wantErr: true},
		// En GitHub una URL de repo es exactamente owner/repo.
		{name: "github con 3 segmentos", input: "https://github.com/a/b/c", wantErr: true},
		{name: "segmento vacío", input: "https://github.com/a//b", wantErr: true},
		{name: "caracteres raros", input: "https://github.com/a/b;rm", wantErr: true},
		// Intento de inyección de argumentos a git.
		{name: "parece un flag", input: "-uupload-pack=touch /tmp/x", wantErr: true},
		{name: "cadena vacía", input: "", wantErr: true},
	}

	for _, tt := range tests {
		// t.Run crea un "subtest" con nombre. Ventajas:
		//   - En la salida ves cada caso por separado (PASS/FAIL).
		//   - Puedes correr uno solo con -run 'TestValidateURL/nombre'
		//     (los espacios del nombre se convierten en guiones bajos).
		//   - Si un caso falla con t.Fatalf, solo se detiene ESE subtest.
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateURL(tt.input)

			// Primero verificamos el error. Patrón típico:
			// comparar "¿hubo error?" contra "¿esperaba error?".
			if (err != nil) != tt.wantErr {
				// %q imprime el string entre comillas y con escapes,
				// muy útil para ver espacios o caracteres invisibles.
				t.Fatalf("ValidateURL(%q) error = %v, wantErr %v (got %q)",
					tt.input, err, tt.wantErr, got)
			}

			// Si esperábamos error y lo hubo, ya terminamos.
			if tt.wantErr {
				return
			}

			// t.Errorf marca el test como fallido pero sigue ejecutando;
			// t.Fatalf lo marca y detiene el subtest. Usa Fatalf cuando
			// seguir no tiene sentido (como arriba), Errorf cuando quieres
			// ver todas las diferencias de una vez.
			if got != tt.want {
				t.Errorf("ValidateURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// FuzzValidateURL usa el fuzzing nativo de Go (disponible desde Go 1.18).
//
// Idea: en lugar de decir "para esta entrada espero esta salida", defines
// PROPIEDADES que siempre deben cumplirse, y Go genera miles de entradas
// aleatorias (mutando las semillas) buscando una que rompa alguna propiedad.
//
// Con `go test` normal, solo se ejecutan las semillas (f.Add) como si fueran
// casos fijos. El fuzzing real solo corre con el flag -fuzz.
//
// Si el fuzzer encuentra un caso que falla, lo guarda en
// testdata/fuzz/FuzzValidateURL/ y desde entonces ese caso se ejecuta en
// cada `go test` normal. Conviene subir esa carpeta al repo.
func FuzzValidateURL(f *testing.F) {
	// Semillas: ejemplos variados para que el fuzzer tenga de dónde mutar.
	seeds := []string{
		"https://github.com/owner/repo",
		"https://gitlab.com/grupo/sub/proyecto.git",
		"https://GitHub.com/a/b/",
		"http://github.com/a/b",
		"https://github.com/a/../b",
		"https://user@github.com/a/b",
		"-uupload-pack=x",
		"file:///etc/passwd",
		"https://github.com/%2e%2e/b",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// f.Fuzz recibe una función cuyos parámetros (después de *testing.T)
	// deben coincidir en tipo con lo que pasaste a f.Add (aquí, un string).
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := ValidateURL(raw)
		if err != nil {
			// Rechazar es siempre seguro. Las propiedades que nos importan
			// son sobre lo que la función ACEPTA.
			return
		}

		// Propiedad 1: el resultado nunca puede empezar con "-",
		// porque git lo interpretaría como un flag.
		if strings.HasPrefix(out, "-") {
			t.Fatalf("resultado empieza con '-': %q (entrada %q)", out, raw)
		}

		// Propiedad 2: siempre https y con host permitido.
		u, perr := url.Parse(out)
		if perr != nil {
			t.Fatalf("el resultado no se puede parsear: %q: %v", out, perr)
		}
		if u.Scheme != "https" {
			t.Fatalf("esquema inesperado %q en %q (entrada %q)", u.Scheme, out, raw)
		}
		if !allowedHosts[u.Host] { // u.Host completo: no debe traer puerto
			t.Fatalf("host no permitido %q en %q (entrada %q)", u.Host, out, raw)
		}

		// Propiedad 3: sin credenciales, query ni fragmento.
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("el resultado conserva partes prohibidas: %q (entrada %q)", out, raw)
		}

		// Propiedad 4: idempotencia. Validar algo ya validado debe dar
		// exactamente lo mismo. Si no, la normalización es inconsistente.
		again, err := ValidateURL(out)
		if err != nil {
			t.Fatalf("el resultado %q no pasa su propia validación: %v", out, err)
		}
		if again != out {
			t.Fatalf("no es idempotente: %q -> %q -> %q", raw, out, again)
		}
	})
}
