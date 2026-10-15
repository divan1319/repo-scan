// Package fetch contiene utilidades para validar y obtener repositorios remotos.
package fetch

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// allowedHosts es la lista blanca de hosts desde los que se permite clonar.
var allowedHosts = map[string]bool{"github.com": true, "gitlab.com": true}

// segment define los caracteres válidos para cada segmento del path
// (letras, números, punto, guion y guion bajo).
var segment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

var ErrScheme = errors.New("solo se permite HTTPS")
var ErrPort = errors.New("no se permiten puertos explícitos")
var ErrUser = errors.New("no se permiten credenciales, queries o fragmentos")
var ErrPath = errors.New("URL debe tener al menos el owner y el repo")
var ErrSegment = errors.New("segmento invalido")
var ErrHost = errors.New("host no permitido")
var ErrGitHub = errors.New("los repositorios de GitHub deben tener exactamente owner y repo")

// ValidateURL valida que raw sea una URL de repositorio segura y devuelve
// su forma canónica: "https://<host>/<owner>/<repo>.git".
//
// Reglas:
//   - Solo esquema HTTPS.
//   - Host en allowedHosts (comparación sin distinguir mayúsculas).
//   - Sin puerto explícito, credenciales, query ni fragmento.
//   - El path debe tener al menos owner y repo; cada segmento debe cumplir
//     segment y no ser "." ni ".." (evita path traversal).
//   - GitHub exige exactamente owner/repo; GitLab admite subgrupos.
//
// Devuelve un error descriptivo si alguna regla no se cumple.
func ValidateURL(raw string) (string, error) {
	// Parsea la URL; un error de sintaxis se propaga tal cual.
	u, err := url.Parse(raw)

	if err != nil {
		return "", err
	}

	if u.Scheme != "https" {
		return "", ErrScheme
	}

	host := strings.ToLower(u.Hostname())
	if !allowedHosts[host] {
		return "", fmt.Errorf("%s: %s", ErrHost, host)
	}

	if u.Port() != "" {
		return "", ErrPort
	}

	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrUser
	}

	// Normaliza el path: quita barras sobrantes y el sufijo ".git" opcional.
	cleanPath := strings.Trim(u.Path, "/")
	cleanPath = strings.TrimSuffix(cleanPath, ".git")
	cleanPath = strings.Trim(cleanPath, "/")

	parts := strings.Split(cleanPath, "/")

	if len(parts) < 2 {
		return "", ErrPath
	}

	// Valida cada segmento contra la regex y rechaza "." y "..".
	for _, p := range parts {
		if !segment.MatchString(p) || p == "." || p == ".." {
			return "", fmt.Errorf("%w: %q", ErrSegment, p)
		}
	}

	// Github: exactamente owner/repo. Gitlab permite subgrupos
	if host == "github.com" && len(parts) != 2 {
		return "", ErrGitHub
	}

	// Reconstruye la URL canónica con host en minúsculas y sufijo ".git".
	return "https://" + host + "/" + strings.Join(parts, "/") + ".git", nil
}
