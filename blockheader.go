package bcore

import (
	"bytes"
	"encoding/hex"
	"errors"
)

var (
	ErrBlockHeaderWrongSize = errors.New("blockheader: wrong size")
)

const (
	BlockHeaderSize = 80
)

type BlockHeader struct {
	Version    uint32
	PrevHash   Hash
	MerkleRoot Hash
	Time       uint32
	Bits       Compact
	Nonce      uint32
}

func NewBlockHeaderFromHexString(hexstring string) (*BlockHeader, error) {
	b, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}

	return NewBlockHeaderFromBytes(b)
}

func NewBlockHeaderFromBytes(data []byte) (*BlockHeader, error) {
	if len(data) != BlockHeaderSize {
		return nil, ErrBlockHeaderWrongSize
	}

	var bh BlockHeader
	NewReadBuffer(data).
		Uint32(&bh.Version).
		Hash(&bh.PrevHash).
		Hash(&bh.MerkleRoot).
		Uint32(&bh.Time).
		Compact(&bh.Bits).
		Uint32(&bh.Nonce)

	return &bh, nil
}

func (bh *BlockHeader) Equal(tbh *BlockHeader) bool {
	return bytes.Equal(bh.Bytes(), tbh.Bytes())
}

func (bh *BlockHeader) Hash() Hash {
	return DHash256(bh.Bytes())
}

func (bh *BlockHeader) Bytes() []byte {
	return NewBuffer().
		PutUint32(bh.Version).
		PutHash(bh.PrevHash).
		PutHash(bh.MerkleRoot).
		PutUint32(bh.Time).
		PutCompact(bh.Bits).
		PutUint32(bh.Nonce).
		Bytes()
}

func (bh *BlockHeader) String() string {
	return NewFormatter("\n", 10).
		PutField("version", bh.Version).
		PutField("prevhash", bh.PrevHash).
		PutField("merkleroot", bh.MerkleRoot).
		PutField("time", bh.Time).
		PutField("bits", bh.Bits).
		PutField("nonce", bh.Nonce).
		String()
}
