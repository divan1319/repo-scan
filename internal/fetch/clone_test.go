// Tests para Clone.
//
// Estos tests son distintos a los de ValidateURL: aquí probamos que las
// defensas de Clone funcionan POR SÍ SOLAS, aunque alguien se salte
// ValidateURL. A eso se le llama "defensa en profundidad": cada capa debe
// protegerse sin asumir que la anterior hizo su trabajo.
//
// Cómo correrlos:
//
//	go test ./internal/fetch -run TestClone -v
//
// El test que clona un repo real de GitHub necesita internet, así que está
// desactivado por defecto. Para activarlo:
//
//	REPOSCAN_NET_TESTS=1 go test ./internal/fetch -run TestCloneRepoReal -v
package fetch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireGit salta el test si git no está instalado.
//
// t.Helper() le dice a Go que esta función es un "ayudante": si falla algo
// aquí dentro, el error se reporta en la línea del test que la llamó, no en
// esta. Así los mensajes de error apuntan a donde importa.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		// t.Skip no es un fallo: marca el test como "SKIP" y sigue con los demás.
		t.Skip("git no está instalado")
	}
}

// makeLocalRepo crea un repositorio git real en una carpeta temporal y
// devuelve su ruta. Lo usamos para intentar clonarlo con file:// y
// comprobar que Clone lo bloquea por política, no porque el repo no exista.
func makeLocalRepo(t *testing.T) string {
	t.Helper()

	// t.TempDir() crea una carpeta única para este test y la BORRA
	// automáticamente al terminar. No necesitas defer os.RemoveAll.
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hola\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Ejecutamos varios comandos git seguidos. Un slice de slices es una
	// forma simple de expresar "esta lista de comandos".
	cmds := [][]string{
		{"init", "-q"},
		{"add", "."},
		// -c user.name/email para que el commit funcione aunque la máquina
		// no tenga git configurado (por ejemplo, en CI).
		{"-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "init"},
	}
	for _, args := range cmds {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir // equivale a hacer `cd dir` antes de correr el comando
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// TestCloneBloqueaTransportesPeligrosos verifica que Clone rechaza URLs que
// ValidateURL nunca dejaría pasar. Si algún día alguien llama a Clone
// directamente (o hay un bug en ValidateURL), esta capa sigue protegiendo.
func TestCloneBloqueaTransportesPeligrosos(t *testing.T) {
	requireGit(t)

	// Archivo "trampa": si algún ataque logra ejecutar un comando, lo creará.
	// Al final verificamos que NO exista.
	markerDir := t.TempDir()
	marker := filepath.Join(markerDir, "pwned")

	tests := []struct {
		name    string
		url     string
		wantMsg string // texto que esperamos en el error de git ("" = no revisar)
	}{
		{
			// Clonar desde el disco local podría leer archivos de tu máquina.
			name:    "transporte file",
			url:     "file://" + makeLocalRepo(t),
			wantMsg: "not allowed",
		},
		{
			// El transporte ext:: ejecuta un comando arbitrario. En la
			// sintaxis de ext, "% " representa un espacio.
			// Ojo: git ya bloquea ext:: por defecto, así que este caso pasa
			// incluso sin protocol.allow=never. Lo dejamos como protección
			// contra regresiones: si alguien algún día agrega
			// "-c protocol.ext.allow=always", este test lo detecta.
			name:    "transporte ext ejecuta comandos",
			url:     "ext::sh -c touch% " + marker,
			wantMsg: "not allowed",
		},
		{
			// Inyección de argumentos. Gracias al "--" en Clone, git trata
			// toda la cadena como el NOMBRE del repositorio, y responde:
			//   repository '--upload-pack=...' does not exist
			// Si quitas el "--", git la interpreta como una opción y el
			// mensaje cambia (habla de otro repositorio). Por eso revisamos
			// el texto exacto: es lo único que distingue ambos casos.
			name:    "url que parece un flag",
			url:     "--upload-pack=touch " + marker,
			wantMsg: "repository '--upload-pack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "clone")

			// context.Background() es el contexto "raíz": sin timeout ni
			// cancelación. Clone le agrega su propio timeout por dentro.
			err := Clone(context.Background(), tt.url, dest)
			if err == nil {
				t.Fatalf("Clone(%q) debía fallar y no falló", tt.url)
			}

			// Verificamos que falló por la razón correcta. Esto protege
			// contra falsos positivos: un test que "pasa" porque el
			// comando falló por otro motivo no prueba nada.
			// Nota: funciona porque Clone limpia el entorno (sin LANG),
			// así que git responde en inglés.
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error inesperado: %v\n(esperaba que contuviera %q)", err, tt.wantMsg)
			}

			// os.Stat devuelve error si el archivo no existe. Si NO hay
			// error, el archivo existe y el ataque funcionó.
			if _, statErr := os.Stat(marker); statErr == nil {
				t.Fatalf("¡el ataque ejecutó un comando! existe %s", marker)
			}
		})
	}
}

// TestCloneContextoCancelado verifica que Clone respeta el context.
// Esto es lo que más adelante te permitirá cancelar un escaneo con Ctrl+C
// o imponer un tiempo máximo desde main.
func TestCloneContextoCancelado(t *testing.T) {
	requireGit(t)

	// WithCancel devuelve un contexto y una función para cancelarlo.
	// La llamamos de inmediato: el contexto nace "muerto".
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// La URL ni siquiera importa: exec.CommandContext no debe arrancar
	// el proceso si el contexto ya está cancelado.
	err := Clone(ctx, "https://github.com/octocat/Hello-World.git", filepath.Join(t.TempDir(), "x"))
	if err == nil {
		t.Fatal("Clone con contexto cancelado debía fallar")
	}
}

// TestCloneRepoReal es un test de integración: clona un repo pequeño y
// público de verdad. Está apagado por defecto porque depende de internet,
// y los tests que dependen de la red son lentos e inestables.
func TestCloneRepoReal(t *testing.T) {
	requireGit(t)

	// os.Getenv devuelve "" si la variable no existe.
	if os.Getenv("REPOSCAN_NET_TESTS") != "1" {
		t.Skip("define REPOSCAN_NET_TESTS=1 para correr tests con red")
	}

	dest := filepath.Join(t.TempDir(), "hello")
	if err := Clone(context.Background(), "https://github.com/octocat/Hello-World.git", dest); err != nil {
		t.Fatalf("Clone falló: %v", err)
	}

	// El repo Hello-World tiene un archivo README en la raíz.
	if _, err := os.Stat(filepath.Join(dest, "README")); err != nil {
		t.Errorf("no se encontró README en el clon: %v", err)
	}

	// Verificamos que el clon sea superficial (--depth 1): debe haber
	// exactamente un commit en el historial.
	cmd := exec.Command("git", "rev-list", "--count", "HEAD")
	cmd.Dir = dest
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-list: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "1" {
		t.Errorf("se esperaba 1 commit (clon superficial), hay %s", got)
	}
}
