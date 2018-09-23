package bcore

import (
	"bytes"
	"testing"

	. "github.com/detailyang/go-bprimitives"
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

func TestBlockHeaderString(t *testing.T) {
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

	expect := `version   :1
prevhash  :0202020202020202020202020202020202020202020202020202020202020202
merkleroot:0303030303030303030303030303030303030303030303030303030303030303
time      :4
bits      :5
nonce     :6`

	if bh.String() != expect {
		t.Errorf("expect \n%s got \n%s", expect, bh.String())
	}
}
