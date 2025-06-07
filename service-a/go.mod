module github.com/NissesSenap/spffie-ambient-auth/service-a

go 1.24.1

require (
	github.com/NissesSenap/spffie-ambient-auth/pkg/oidc v0.0.0-00010101000000-000000000000
	github.com/spiffe/go-spiffe/v2 v2.5.0
)

replace github.com/NissesSenap/spffie-ambient-auth/pkg/oidc => ../pkg/oidc

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/coreos/go-oidc/v3 v3.9.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.4 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250219182151-9fdb1cabc7b2 // indirect
	google.golang.org/grpc v1.70.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
)
