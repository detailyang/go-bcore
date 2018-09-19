package bcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

const HashSize = 32

var (
	HashZero = Hash{0x0000000000000000000000000000000000000000000000000000000000000000}
)

type Hash [HashSize]byte

func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashSize:]
	}

	copy(h[HashSize-len(b):], b)
}

func (h Hash) Equal(target Hash) bool {
	return bytes.Equal(h[:], target[:])
}

func (h Hash) IsZero() bool {
	return h.Equal(HashZero)
}

func (h Hash) Bytes() []byte {
	return h[:]
}

func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

func (h Hash) String() string {
	return h.Hex()
}

func DHash256(data []byte) Hash {
	var hash Hash

	h := sha256.New()
	h.Write(data)
	h.Write(h.Sum(nil))
	hash.SetBytes(h.Sum(nil))

	return hash
}
