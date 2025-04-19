module github.com/lstoll/tinkrotate/e2e

go 1.24

require github.com/lstoll/tinkrotate v0.0.0

require (
	github.com/stretchr/testify v1.10.0
	github.com/tink-crypto/tink-go v0.0.0-20230613075026-d6de17e3f164
	github.com/tink-crypto/tink-go/v2 v2.4.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.28
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// --- Tell Go where to find the parent module LOCALLY ---
// This maps the required parent module path to the relative filesystem path.
replace github.com/lstoll/tinkrotate => ../
