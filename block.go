package bcore

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

func (b *Block) Hash() Hash {
	return b.Header.Hash()
}

func (b *Block) H256() Hash {
	return b.Hash()
}

func (b *Block) Bytes() []byte {
	// NewBuffer().
	// 	PutBytes(b.Header.Bytes()).
	return nil
}
