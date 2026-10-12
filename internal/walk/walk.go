// Package walk recorre de forma segura el árbol de archivos de un repositorio clonado.
package walk

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Límites para evitar abusos de recursos (p. ej. repositorios maliciosos).
const (
	maxFileSize = 2 << 20 // 2MB por archivo\
	maxFiles    = 50_000  // número máximo de archivos a procesar
)

// Walk recorre root y llama a fn con la ruta relativa y el contenido de cada
// archivo regular.
//
// Comportamiento:
//   - Ignora el directorio .git y todo lo que no sea archivo regular
//     (symlinks, dispositivos, pipes).
//   - Los archivos que superan maxFileSize, o cuya info no se puede leer, no se
//     pasan a fn: se devuelven en skipped.
//   - Los archivos que no se pueden abrir se omiten en silencio, igual que los
//     errores de acceso durante el recorrido.
//   - Si se superan maxFiles archivos, el recorrido se aborta con error.
//   - Usa os.Root para que las lecturas no puedan escapar de root (p. ej. por
//     symlinks).
//
// Devuelve la lista de rutas omitidas y el error del recorrido, si lo hubo.
func Walk(root string, fn func(rel string, data []byte)) (skipped []string, err error) {
	// Abre root como raíz confinada: las aperturas posteriores no pueden salir de él.
	r, err := os.OpenRoot(root)

	if err != nil {
		return nil, err
	}

	defer r.Close()

	// Contador de archivos regulares vistos, para aplicar maxFiles.
	count := 0

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Errores de acceso a una entrada: se ignora y se continúa.
		if err != nil {
			return nil //
		}

		// No se desciende al directorio de metadatos de git.
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}

		// Solo se procesan archivos regulares.
		if !d.Type().IsRegular() {
			return nil // salta symlinks, dispositivos, pipes
		}

		// Aborta el recorrido si hay demasiados archivos.
		if count++; count > maxFiles {
			return errors.New("demasiados archivos")
		}

		// Ruta relativa a root; es la que se usa con os.Root y se reporta a fn.
		rel, _ := filepath.Rel(root, path)

		// Archivos ilegibles o demasiado grandes se registran como omitidos.
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			skipped = append(skipped, rel) // archivos grandes tambien son señal
			return nil
		}

		// Abre el archivo a través de la raíz confinada; si falla, se omite.
		f, err := r.Open(rel)

		if err != nil {
			return nil
		}

		defer f.Close()

		// Lee como máximo maxFileSize bytes (defensa ante cambios de tamaño).
		data, _ := io.ReadAll(io.LimitReader(f, maxFileSize))

		// Entrega el archivo al llamador.
		fn(rel, data)

		return nil
	})

	return skipped, err
}
