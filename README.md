# repo-scan

Herramienta en Go para obtener y analizar repositorios remotos de forma segura, tratándolos siempre como **código no confiable**.

> ⚠️ Estado: en desarrollo inicial. La CLI (`cmd/reposcan`) aún es un esqueleto; por ahora está implementada la capa de validación y clonado seguro.

## Características

- **Validación estricta de URLs** (`fetch.ValidateURL`):
  - Solo HTTPS, hosts permitidos: `github.com` y `gitlab.com`.
  - Rechaza puertos, credenciales, queries y fragmentos.
  - Protección contra path traversal (`.` / `..`) y caracteres inválidos.
  - GitHub exige `owner/repo`; GitLab admite subgrupos.
  - Devuelve la URL canónica: `https://<host>/<owner>/<repo>.git`.
- **Clonado endurecido** (`fetch.Clone`):
  - Clon superficial (`--depth 1`), una sola rama, sin tags ni submódulos.
  - Solo transporte HTTPS, sin symlinks, sin hooks, sin LFS.
  - Entorno mínimo, sin prompts de credenciales y sin leer configuración de git del sistema/usuario.
  - Timeout de 2 minutos y soporte de cancelación vía `context`.

## Requisitos

- Go 1.27+
- `git` instalado y disponible en el `PATH`

## Estructura del proyecto

```
.
├── cmd/reposcan/        # Punto de entrada de la CLI (en construcción)
└── internal/fetch/
    ├── validate.go      # Validación y normalización de URLs
    ├── clone.go         # Clonado seguro con git
    └── *_test.go        # Tests
```

## Uso (como librería interna)

```go
url, err := fetch.ValidateURL("https://github.com/divan1319/repo-scan")
if err != nil {
    log.Fatal(err)
}

if err := fetch.Clone(context.Background(), url, "/tmp/repo"); err != nil {
    log.Fatal(err)
}
```

## Tests

```bash
go test ./...
```

## Roadmap

- [ ] Leer argumentos posicionales en la CLI
- [ ] Análisis del repositorio clonado
- [ ] Reporte de resultados
- [ ] Limpieza automática de directorios temporales

## Licencia

Distribuido bajo la licencia [MIT](LICENSE).
