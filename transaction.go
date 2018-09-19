package bcore

import (
	"math"
)

const (
	TransactionFinalSequence = 0xffffffff
)

type Transaction struct {
	Version  uint32
	Inputs   []TransactionInput
	Outputs  []TransactionOutput
	Locktime uint32
}

type OutPoint struct {
	Hash  Hash
	Index uint32
}

type TransactionInput struct {
	PrevOutput    OutPoint
	ScriptSig     []byte
	Sequence      uint32
	ScriptWitness [][]byte
}

type TransactionOutput struct {
	Value        uint64
	ScriptPubkey []byte
}

func NewOutPoint() *OutPoint {
	return &OutPoint{
		Hash:  HashZero,
		Index: math.MaxUint32,
	}
}

func (o OutPoint) IsNull() bool {
	return o.Hash.IsZero()
}

func (o OutPoint) Bytes() []byte {
	return NewBuffer().
		PutHash(o.Hash).
		PutUint32(o.Index).
		Bytes()
}

func (ti *TransactionInput) IsFinal() bool {
	return ti.Sequence == TransactionFinalSequence
}

func (ti *TransactionInput) HasWitness() bool {
	return false
}

func (ti *TransactionInput) Bytes() []byte {
	return NewBuffer().
		PutBytes(ti.PrevOutput.Bytes()).
		PutBytes(ti.ScriptSig).
		PutUint32(ti.Sequence).
		Bytes()
}

func (to *TransactionOutput) Bytes() []byte {
	return NewBuffer().
		PutUint64(to.Value).
		PutBytes(to.ScriptPubkey).
		Bytes()
}

func (t *Transaction) IsEmpty() bool {
	return len(t.Inputs) == 0 || len(t.Outputs) == 0
}

func (t *Transaction) IsNull() bool {
	for _, input := range t.Inputs {
		if input.PrevOutput.IsNull() {
			return true
		}
	}

	return false
}

func (t *Transaction) IsCoinbase() bool {
	return len(t.Inputs) == 1 && t.Inputs[0].PrevOutput.IsNull()
}

func (t *Transaction) HasWitness() bool {
	for _, input := range t.Inputs {
		if input.HasWitness() {
			return true
		}
	}

	return false
}

func (t *Transaction) TotalSpends() uint64 {
	sum := uint64(0)
	for _, output := range t.Outputs {
		sum += output.Value
	}
	return sum
}

// TODO: support witness
func (t *Transaction) Bytes() []byte {
	buffer := NewBuffer().PutUint32(t.Version)

	buffer.PutVarInt(uint64(len(t.Inputs)))
	for i := 0; i < len(t.Inputs); i++ {
		buffer.PutBytes(t.Inputs[i].Bytes())
	}

	buffer.PutVarInt(uint64(len(t.Outputs)))
	for i := 0; i < len(t.Outputs); i++ {
		buffer.PutBytes(t.Outputs[i].Bytes())
	}

	buffer.PutUint32(t.Locktime)

	return buffer.Bytes()
}

func (t *Transaction) Hash() Hash {
	return DHash256(t.Bytes())
}
