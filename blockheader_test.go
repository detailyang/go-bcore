package bcore

import (
	"bytes"
	"testing"
)

func TestBlockHeaderFromBytes(t *testing.T) {
	ebh := &BlockHeader{
		Version: 1,
		PrevHash: Hash{
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		},
		MerkleRoot: Hash{
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		},
		Time:  4,
		Bits:  NewCompact(5),
		Nonce: 6,
	}

	stream := []byte{
		1, 0, 0, 0,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		4, 0, 0, 0,
		5, 0, 0, 0,
		6, 0, 0, 0,
	}

	bh, err := NewBlockHeaderFromBytes(stream)
	if err != nil {
		t.Fatal(err)
	}

	if !bh.Equal(ebh) {
		t.Fatalf("expected:%s got:%s", ebh, bh)
	}
}

func TestBlockHeaderBytes(t *testing.T) {
	bh := &BlockHeader{
		Version: 1,
		PrevHash: Hash{
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		},
		MerkleRoot: Hash{
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		},
		Time:  4,
		Bits:  NewCompact(5),
		Nonce: 6,
	}

	stream := []byte{
		1, 0, 0, 0,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		4, 0, 0, 0,
		5, 0, 0, 0,
		6, 0, 0, 0,
	}

	if !bytes.Equal(stream, bh.Bytes()) {
		t.Fatalf("expected:%v got:%v", stream, bh.Bytes())
	}
}
