package falcon_test

import (
	"crypto/rand"
	"testing"

	"github.com/algorand/falcon"
	falcon_rs "github.com/algorand/falcon/packages/go/falcon_rs"
)

// BenchmarkFalconCKeyGen benchmarks key generation using the C implementation
func BenchmarkFalconCKeyGen(b *testing.B) {
	var seed [48]byte
	rand.Read(seed[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := falcon.GenerateKey(seed[:])
		if err != nil {
			b.Fatalf("GenerateKey with error %v", err)
		}
	}
}

// BenchmarkFalconRustKeyGen benchmarks key generation using the Rust implementation
func BenchmarkFalconRustKeyGen(b *testing.B) {
	var seed [48]byte
	rand.Read(seed[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := falcon_rs.GenerateKey(seed[:])
		if err != nil {
			b.Fatalf("GenerateKey with error %v", err)
		}
	}
}

// BenchmarkFalconCSignCompressed benchmarks signing using the C implementation
func BenchmarkFalconCSignCompressed(b *testing.B) {
	_, sk, err := falcon.GenerateKey([]byte("seed"))
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sk.SignCompressed(strs[i][:])
		if err != nil {
			b.Fatalf("SignCompressed failed with error %v", err)
		}
	}
}

// BenchmarkFalconRustSignCompressed benchmarks signing using the Rust implementation
func BenchmarkFalconRustSignCompressed(b *testing.B) {
	keyPair, err := falcon_rs.GenerateKey([]byte("seed"))
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := falcon_rs.SignCompressed(keyPair.PrivateKey, strs[i][:])
		if err != nil {
			b.Fatalf("SignCompressed failed with error %v", err)
		}
	}
}

// BenchmarkFalconCVerify benchmarks verification using the C implementation
func BenchmarkFalconCVerify(b *testing.B) {
	pk, sk, err := falcon.GenerateKey([]byte("seed"))
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	sigs := make([]falcon.CompressedSignature, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
		sigs[i], err = sk.SignCompressed(msg[:])
		if err != nil {
			b.Fatalf("SignCompressed failed with error %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := pk.Verify(sigs[i], strs[i][:])
		if err != nil {
			b.Fatalf("Verify failed with error %v", err)
		}
	}
}

// BenchmarkFalconRustVerify benchmarks verification using the Rust implementation
func BenchmarkFalconRustVerify(b *testing.B) {
	keyPair, err := falcon_rs.GenerateKey([]byte("seed"))
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	sigs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
		sigs[i], err = falcon_rs.SignCompressed(keyPair.PrivateKey, msg[:])
		if err != nil {
			b.Fatalf("SignCompressed failed with error %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := falcon_rs.Verify(keyPair.PublicKey, sigs[i], strs[i][:])
		if err != nil {
			b.Fatalf("Verify failed with error %v", err)
		}
	}
}
