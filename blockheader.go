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
	// The block version number indicates which set of block validation rules to follow
	Version uint32
	// A SHA256(SHA256()) hash in internal byte order of the previous block’s header. This ensures no previous block can be changed without also changing this block’s header.
	PrevHash Hash
	// A SHA256(SHA256()) hash in internal byte order.
	// The merkle root is derived from the hashes of all transactions included in this block, ensuring that none of those transactions can be modified without modifying the header
	MerkleRoot Hash
	// The block time is a Unix epoch time when the miner started hashing the header (according to the miner).
	// Must be strictly greater than the median time of the previous 11 blocks.
	// Full nodes will not accept blocks with headers more than two hours in the future according to their clock.
	Time uint32
	// An encoded version of the target threshold this block’s header hash must be less than or equal to.
	Bits Compact
	// An arbitrary number miners change to modify the header hash in order to produce a hash less than or equal to the target threshold. If all 32-bit values are tested, the time can be updated or the coinbase transaction can be changed and the merkle root updated.
	Nonce uint32
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

	return NewBlockHeaderFromBuffer(NewReadBuffer(data))
}

func NewBlockHeaderFromBuffer(buffer *Buffer) (*BlockHeader, error) {
	version, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	prevHash, err := buffer.GetHash()
	if err != nil {
		return nil, err
	}

	merkleRoot, err := buffer.GetHash()
	if err != nil {
		return nil, err
	}

	time, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	bits, err := buffer.GetCompact()
	if err != nil {
		return nil, err
	}

	nonce, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	return &BlockHeader{
		Version:    version,
		PrevHash:   prevHash,
		MerkleRoot: merkleRoot,
		Time:       time,
		Bits:       bits,
		Nonce:      nonce,
	}, nil
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
