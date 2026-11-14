module github.com/FacileStudio/porte/mcpauth

go 1.26.11

require (
	github.com/FacileStudio/porte v0.20.1
	github.com/FacileStudio/porte/directory v0.5.0
	github.com/FacileStudio/porte/forfait v0.1.1
	github.com/FacileStudio/tronc v0.17.1
	github.com/modelcontextprotocol/go-sdk v1.8.0
)

require (
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/go-chi/chi/v5 v5.5.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.9 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace (
	github.com/FacileStudio/porte => ../
	github.com/FacileStudio/porte/directory => ../directory
	github.com/FacileStudio/porte/forfait => ../forfait
)
