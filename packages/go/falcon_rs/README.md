## Uniffi Bindings for Go

## Generation

```bash
cargo build --release && cargo bin uniffi-bindgen-go --out-dir packages/go/ --library target/release/libfalcon_rs.a
```

Then make sure the CGO_LDFLAGS are correct set by adding the following cgo directory to [falcon_rs.go](./falcon_rs/falcon_rs.go)

```go
/*
#include <falcon_rs.h>
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lfalcon_rs
*/
import "C"
```

## Benchmark

Comparison of uniffi-generated bindings to direct cgo bindings

```bash
go test -bench=. -benchmem -benchtime=500x ./falcon_benchmark_test.go
```

Results on M4 Pro:

```bash
goos: darwin
goarch: arm64
cpu: Apple M4 Pro
BenchmarkFalconCKeyGen-14                            500          16896431 ns/op            9691 B/op          5 allocs/op
BenchmarkFalconRustKeyGen-14                         500          15938309 ns/op            5540 B/op         13 allocs/op
BenchmarkFalconCSignCompressed-14                    500           4175430 ns/op            3080 B/op          3 allocs/op
BenchmarkFalconRustSignCompressed-14                 500           4240066 ns/op           12980 B/op         22 allocs/op
BenchmarkFalconCVerify-14                            500             24558 ns/op               0 B/op          0 allocs/op
BenchmarkFalconRustVerify-14                         500             28751 ns/op           12124 B/op         24 allocs/op
PASS
ok      command-line-arguments  25.387s
```