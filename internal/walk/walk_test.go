// Tests para Walk.
//
// Estrategia: construimos un árbol de archivos "trampa" en una carpeta
// temporal (archivos normales, una carpeta .git, un archivo gigante y
// symlinks que apuntan fuera), corremos Walk y verificamos exactamente qué
// archivos leyó y cuáles reportó como omitidos.
//
// Cómo correrlos:
//
//	go test ./internal/walk -v
package walk

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeFile crea un archivo (y sus carpetas padre) dentro de root.
// rel usa "/" como separador; filepath.FromSlash lo convierte a "\" en
// Windows, así el test funciona en cualquier sistema operativo.
func writeFile(t *testing.T, root, rel string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))

	// 0o755 y 0o644 son permisos en octal (el prefijo 0o es la forma
	// moderna de escribir octales en Go).
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

// collect corre Walk y devuelve:
//   - visited: mapa ruta -> contenido de cada archivo que Walk entregó a fn
//   - skipped: rutas omitidas, ordenadas para poder compararlas
//
// Normalizamos las rutas a "/" con filepath.ToSlash para que las
// comparaciones no dependan del sistema operativo.
func collect(t *testing.T, root string) (visited map[string]string, skipped []string) {
	t.Helper()
	visited = map[string]string{}

	// Aquí pasamos una función anónima (closure) como callback. Puede
	// modificar `visited` porque la "captura" del ámbito exterior.
	skippedRaw, err := Walk(root, func(rel string, data []byte) {
		visited[filepath.ToSlash(rel)] = string(data)
	})
	if err != nil {
		t.Fatalf("Walk devolvió error: %v", err)
	}

	for _, s := range skippedRaw {
		skipped = append(skipped, filepath.ToSlash(s))
	}
	slices.Sort(skipped)
	return visited, skipped
}

// TestWalkArchivosNormales: el caso feliz. Lee archivos en la raíz y en
// subcarpetas, con su contenido correcto.
func TestWalkArchivosNormales(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "README.md", []byte("hola"))
	writeFile(t, root, "src/main.go", []byte("package main"))
	writeFile(t, root, "src/util/helpers.go", []byte("package util"))

	visited, skipped := collect(t, root)

	want := map[string]string{
		"README.md":           "hola",
		"src/main.go":         "package main",
		"src/util/helpers.go": "package util",
	}

	// maps.Equal (Go 1.21+) compara dos mapas clave por clave.
	if !maps.Equal(visited, want) {
		t.Errorf("archivos visitados:\n got  %v\n want %v", visited, want)
	}
	if len(skipped) != 0 {
		t.Errorf("no debía omitir nada, omitió %v", skipped)
	}
}

// TestWalkIgnoraCarpetaGit: el contenido de .git no es código del proyecto
// y puede ser enorme. Walk debe saltarse la carpeta completa.
func TestWalkIgnoraCarpetaGit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.js", []byte("console.log(1)"))
	writeFile(t, root, ".git/config", []byte("[core]"))
	writeFile(t, root, ".git/objects/ab/cdef", []byte("blob"))

	visited, _ := collect(t, root)

	// Recorrer un mapa con range da clave y valor; aquí solo usamos la
	// clave, así que omitimos el segundo valor.
	for rel := range visited {
		if strings.HasPrefix(rel, ".git/") {
			t.Errorf("Walk entró a .git: leyó %s", rel)
		}
	}
	if _, ok := visited["app.js"]; !ok {
		// El "comma ok idiom": ok es false si la clave no existe en el mapa.
		t.Error("Walk no leyó app.js")
	}
}

// TestWalkOmiteArchivosGrandes: un archivo que supera maxFileSize no se
// lee, pero SÍ se reporta en skipped. Lo que no se analizó también es
// información para el usuario.
func TestWalkOmiteArchivosGrandes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "small.txt", []byte("ok"))

	// make([]byte, n) crea un slice de n bytes en cero. Usamos la
	// constante del paquete (visible porque estamos en `package walk`).
	writeFile(t, root, "big.bin", make([]byte, maxFileSize+1))

	visited, skipped := collect(t, root)

	if _, ok := visited["big.bin"]; ok {
		t.Error("Walk leyó big.bin aunque supera maxFileSize")
	}
	if !slices.Equal(skipped, []string{"big.bin"}) {
		t.Errorf("skipped = %v, want [big.bin]", skipped)
	}
}

// TestWalkNoSigueSymlinks: un repo malicioso puede incluir symlinks que
// apunten a archivos de tu máquina (por ejemplo ~/.ssh/id_rsa). Walk no
// debe leerlos ni entrar a carpetas enlazadas.
//
// Walk tiene DOS capas contra esto:
//  1. `if !d.Type().IsRegular()` salta cualquier cosa que no sea archivo normal.
//  2. Leer con os.Root (r.Open) impide abrir rutas que salgan de la raíz.
//
// Este test pasa mientras al menos UNA de las dos funcione. Si quitas solo
// una, sigue en verde (lo comprobamos). Eso es la defensa en profundidad
// funcionando, pero también significa que este test no detecta si una de
// las capas se rompe. Un ejercicio para después: probar cada capa por
// separado.
func TestWalkNoSigueSymlinks(t *testing.T) {
	// "outside" simula archivos sensibles FUERA del repo.
	outside := t.TempDir()
	writeFile(t, outside, "secret.txt", []byte("CLAVE-SECRETA"))
	writeFile(t, outside, "dir/otro-secreto.txt", []byte("CLAVE-SECRETA"))

	root := t.TempDir()
	writeFile(t, root, "normal.txt", []byte("ok"))

	// Symlink a un archivo y a una carpeta, ambos fuera de root.
	// En Windows crear symlinks puede requerir permisos especiales;
	// si falla, saltamos el test en vez de reportar un falso fallo.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link-archivo")); err != nil {
		t.Skipf("no se pudo crear symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "dir"), filepath.Join(root, "link-carpeta")); err != nil {
		t.Skipf("no se pudo crear symlink: %v", err)
	}

	visited, _ := collect(t, root)

	for rel, content := range visited {
		if strings.Contains(content, "CLAVE-SECRETA") {
			t.Errorf("Walk leyó contenido de fuera del repo a través de %s", rel)
		}
	}
	if _, ok := visited["normal.txt"]; !ok {
		t.Error("Walk no leyó normal.txt")
	}
}

// TestWalkRaizInexistente: si la carpeta no existe, Walk debe devolver
// un error en lugar de "terminar bien" sin haber leído nada.
func TestWalkRaizInexistente(t *testing.T) {
	_, err := Walk(filepath.Join(t.TempDir(), "no-existe"), func(string, []byte) {})
	if err == nil {
		t.Fatal("se esperaba error para una raíz inexistente")
	}
}
