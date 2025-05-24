module github.com/NissesSenap/spffie-ambient-auth/service-b

go 1.24.1

require (
	github.com/NissesSenap/spffie-ambient-auth/spicedb v0.0.0-00010101000000-000000000000
	github.com/spiffe/go-spiffe/v2 v2.5.0
)

replace github.com/NissesSenap/spffie-ambient-auth/spicedb => ../spicedb

require (
	cloud.google.com/go/compute/metadata v0.5.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/authzed/authzed-go v0.11.0 // indirect
	github.com/authzed/grpcutil v0.0.0-20230908193239-4286bb1d6403 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/certifi/gocertifi v0.0.0-20210507211836-431795d63e8d // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/envoyproxy/protoc-gen-validate v1.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.4 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.1 // indirect
	github.com/jzelinskie/stringz v0.0.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/samber/lo v1.39.0 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241202173237-19429a94021a // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
	google.golang.org/grpc v1.70.0 // indirect
	google.golang.org/protobuf v1.36.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
