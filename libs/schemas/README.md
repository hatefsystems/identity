# @hatef/schemas

Protocol Buffers are the **single source of truth** for the Hatef Identity
Platform's API contracts (see `docs/architecture.md` §4 "Type Safety"). Go
structs, gRPC service stubs, and TypeScript types are all generated from the
`.proto` files in this library using [`buf`](https://buf.build).

## Layout

```
libs/schemas/
├── buf.yaml                          # module config (lint STANDARD, breaking FILE)
├── buf.gen.yaml                      # codegen plugin wiring (Go, gRPC, TS)
├── go.mod                            # pins the buf + protoc plugin tool binaries
├── proto/
│   └── hatef/identity/v1/
│       ├── common.proto              # shared enums/messages (e.g. UserStatus)
│       └── identity_service.proto    # internal IdentityService gRPC contract
└── gen/                              # generated output (gitignored build artifact)
    ├── go/                           # Go structs + gRPC stubs
    └── ts/                           # TypeScript types for apps/web
```

## Tooling (reproducible, no global installs)

`buf` and the Go protobuf plugins are pinned as Go `tool` dependencies in
`go.mod`, so anyone with the Go toolchain can run them at the exact pinned
version without a separate install step:

- `github.com/bufbuild/buf/cmd/buf`
- `google.golang.org/protobuf/cmd/protoc-gen-go`
- `google.golang.org/grpc/cmd/protoc-gen-go-grpc`

They are invoked via `go tool <name>`. The TypeScript plugin
(`buf.build/bufbuild/es`) is a remote BSR plugin resolved by `buf` at
generation time.

## Commands

Through Nx (preferred):

```bash
pnpm nx generate schemas   # buf generate  -> gen/go + gen/ts
pnpm nx lint schemas       # buf lint
pnpm nx format schemas     # buf format -w (see Windows note below)
pnpm nx breaking schemas   # buf breaking against main
```

Or directly from this directory:

```bash
go tool buf lint
go tool buf generate
go tool buf format -w
```

### Windows: `buf format` requires a `diff` binary

`buf format` shells out to an external `diff` executable. Linux/macOS ship one
by default; **Windows does not**, so `buf format` (and `nx format schemas`) fail
with:

```
Failure: exec: "diff": executable file not found in %PATH%
```

`lint`, `generate`, and `breaking` are unaffected — only `format` needs `diff`.
Git for Windows already bundles one; just add its `usr\bin` to your PATH:

```powershell
# current session only
$env:PATH = "C:\Program Files\Git\usr\bin;" + $env:PATH
# or add C:\Program Files\Git\usr\bin permanently via System Environment Variables
```

Alternatively install GNU diffutils (e.g. `winget install GnuWin32.DiffUtils`).

## Notes

- Generated code under `gen/` is **not committed**; it is regenerated from the
  `.proto` sources. Run generation after pulling changes to the contracts.
- Proto files must live under a path matching their package
  (`hatef/identity/v1/...`) to satisfy `buf lint` STANDARD rules.
- The seed `IdentityService` contract mirrors `docs/api-design.md` §2.2; the
  full method set and validation semantics land in Phase 6 (Tasks 6.1–6.3).
