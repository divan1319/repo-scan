package fetch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Clone clona de forma segura el repositorio repoURL en el directorio dest.
//
// Hace un clon superficial (--depth 1) de una sola rama, sin tags ni
// submódulos, y endurece git para tratar el repositorio como no confiable:
// solo HTTPS, sin symlinks, sin hooks, sin prompts de credenciales, sin LFS
// y sin leer configuración del sistema o del usuario.
//
// repoURL debería haber sido validada previamente con ValidateURL. La
// operación se cancela si ctx termina o tras 2 minutos. Si git falla,
// devuelve un error que envuelve el original e incluye la salida de git.
func Clone(ctx context.Context, repoURL, dest string) error {
	// Limita la duración total del clon a 2 minutos.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Argumentos de git: primero las opciones de seguridad (-c), luego el clon.
	args := []string{
		"-c", "protocol.allow=never", // bloquea todos los transportes...
		"-c", "protocol.https.allow=always", // ...excepto https
		"-c", "core.symlinks=false", // symlinks se escriben como archivos de texto
		"-c", "core.hooksPath=/dev/null", // ningún hook se ejecuta
		"clone",
		"--depth", "1", "--single-branch", "--no-tags",
		"--no-recurse-submodules",
		"--", repoURL, dest, // "--" evita que repoURL sea interpretado como opción
	}

	cmd := exec.CommandContext(ctx, "git", args...)

	// Entorno mínimo y explícito: no hereda variables del proceso padre
	// (evita filtrar secretos o configuraciones peligrosas a git).
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.TempDir(),
		"GIT_TERMINAL_PROMPT=0",       // nunca pedir credenciales
		"GIT_LFS_SKIP_SMUDGE=1",       // no descargar archivos LFS
		"GIT_CONFIG_NOSYSTEM=1",       // ignorar config del sistema
		"GIT_CONFIG_GLOBAL=/dev/null", // ignorar ~/.gitconfig (git 2.32+)
	}

	// Ejecuta git y captura stdout+stderr para incluirlo en el error.
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("falló git clone: %w: %s", err, out)
	}

	return nil
}
