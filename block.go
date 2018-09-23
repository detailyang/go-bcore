package bcore

import (
	"encoding/hex"

	. "github.com/detailyang/go-bprimitives"
)

// Block represents bitcoin block header and transactions
type Block struct {
	Header       *BlockHeader
	Transactions []*Transaction
}

func NewBlock(header *BlockHeader, transactions []*Transaction) *Block {
	return &Block{
		Header:       header,
		Transactions: transactions,
	}
}

func NewBlockFromHexString(hexstring string) (*Block, error) {
	b, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}

	return NewBlockFromBytes(b)
}

func NewBlockFromBytes(data []byte) (*Block, error) {
	return NewBlockFromBuffer(NewReadBuffer(data))
}

func NewBlockFromBuffer(buffer *Buffer) (*Block, error) {
	bh, err := NewBlockHeaderFromBuffer(buffer)
	if err != nil {
		return nil, err
	}

	ntx, err := buffer.GetVarInt()
	if err != nil {
		return nil, err
	}

	transactions := make([]*Transaction, ntx)
	for i := 0; i < int(ntx); i++ {
		transaction, err := NewTransactionFromBuffer(buffer)
		if err != nil {
			return nil, err
		}
		transactions[i] = transaction
	}

	return &Block{
		Header:       bh,
		Transactions: transactions,
	}, nil
}

func (b *Block) Hash() Hash {
	return b.Header.Hash()
}

func (b *Block) H256() Hash {
	return b.Hash()
}

func (b *Block) Bytes() []byte {
	buffer := NewBuffer().PutBytes(b.Header.Bytes())

	ntx := len(b.Transactions)
	buffer.PutVarInt(uint64(ntx))
	for i := 0; i < ntx; i++ {
		buffer.PutBytes(b.Transactions[i].Bytes())
	}

	return nil
}
