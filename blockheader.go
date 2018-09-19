package bcore

import (
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
	Bits       uint32
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
	if len(data) != 80 {
		return nil, ErrBlockHeaderWrongSize
	}

	var bh BlockHeader
	NewReadBuffer(data).
		Uint32(&bh.Version).
		Hash(&bh.PrevHash).
		Hash(&bh.MerkleRoot).
		Uint32(&bh.Time).
		Uint32(&bh.Bits).
		Uint32(&bh.Nonce)

	return &bh, nil
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
		PutUint32(bh.Bits).
		PutUint32(bh.Nonce).
		Bytes()
}

func (bh *BlockHeader) Strin() string {
	return NewFormatter("\n").
		PutField("version", bh.Version).
		PutField("prevhash", bh.PrevHash).
		PutField("merkleroot", bh.MerkleRoot).
		PutField("time", bh.Time).
		PutField("bits", bh.Bits).
		PutField("nonce", bh.Nonce).
		String()
}
