package bcore

import (
	"encoding/hex"
	"errors"
	"math"
)

var (
	ErrTransactionInputWrongSize         = errors.New("transaction input:  wrong size")
	ErrTransactionInputOutPointWrongSize = errors.New("transaction outpoint: wrong size")
)

const (
	TransactionFinalSequence = 0xffffffff
	TransactionWitnessMarker = 0x00
	TransactionWitnessFlag   = 0x01

	TransactionOutPointSize = HashSize + 4
)

type Transaction struct {
	Version  uint32
	Inputs   []*TransactionInput
	Outputs  []*TransactionOutput
	Locktime uint32
}

type OutPoint struct {
	Hash  Hash
	Index uint32
}

type TransactionInput struct {
	PrevOutput    *OutPoint
	ScriptSig     []byte
	Sequence      uint32
	ScriptWitness ScriptWitness
}

type TransactionOutput struct {
	Value        uint64
	ScriptPubkey []byte
}

type ScriptWitness [][]byte

func NewScriptWitness() ScriptWitness {
	return ScriptWitness([][]byte{})
}

func (s ScriptWitness) Size() int { return len(s) }

func (s ScriptWitness) Bytes() []byte {
	n := s.Size()
	buffer := NewBuffer().PutVarInt(uint64(n))

	for i := 0; i < n; i++ {
		buffer.PutVarBytes(s[i])
	}

	return buffer.Bytes()
}

func NewOutPoint() *OutPoint {
	return &OutPoint{
		Hash:  HashZero,
		Index: math.MaxUint32,
	}
}

func NewOutPointFromBytes(data []byte) (*OutPoint, error) {
	if len(data) != TransactionOutPointSize {
		return nil, ErrTransactionInputOutPointWrongSize
	}

	var op OutPoint

	NewReadBuffer(data).
		Hash(&op.Hash).
		Uint32(&op.Index)

	return &op, nil
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

func NewTransactionInputFromBuffer(buffer *Buffer) (*TransactionInput, error) {
	data, err := buffer.GetBytes(TransactionOutPointSize)
	if err != nil {
		return nil, err
	}

	outpoint, err := NewOutPointFromBytes(data)
	if err != nil {
		return nil, err
	}

	scriptSig, err := buffer.GetVarBytes()
	if err != nil {
		return nil, err
	}

	sequence, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	return &TransactionInput{
		PrevOutput:    outpoint,
		ScriptSig:     scriptSig,
		Sequence:      sequence,
		ScriptWitness: NewScriptWitness(),
	}, nil
}

func NewTransactionInputFromBytes(data []byte) (*TransactionInput, error) {
	buffer := NewReadBuffer(data)
	return NewTransactionInputFromBuffer(buffer)
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
		PutVarBytes(ti.ScriptSig).
		PutUint32(ti.Sequence).
		Bytes()
}

func NewTransactionOutputFromBuffer(buffer *Buffer) (*TransactionOutput, error) {
	value, err := buffer.GetUint64()
	if err != nil {
		return nil, err
	}

	scriptPubkey, err := buffer.GetVarBytes()
	if err != nil {
		return nil, err
	}

	return &TransactionOutput{
		Value:        value,
		ScriptPubkey: scriptPubkey,
	}, nil
}

func (to *TransactionOutput) Bytes() []byte {
	return NewBuffer().
		PutUint64(to.Value).
		PutVarBytes(to.ScriptPubkey).
		Bytes()
}

func NewTransactionFromHexString(hexstring string) (*Transaction, error) {
	b, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}

	return NewTransactionFromBytes(b)
}

func NewTransactionFromBytes(data []byte) (*Transaction, error) {
	buffer := NewReadBuffer(data)

	version, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	ninputs, err := buffer.GetVarInt()
	if err != nil {
		return nil, err
	}

	inputs := make([]*TransactionInput, ninputs)
	for i := 0; i < int(ninputs); i++ {
		input, err := NewTransactionInputFromBuffer(buffer)
		if err != nil {
			return nil, err
		}
		inputs[i] = input
	}

	noutputs, err := buffer.GetVarInt()
	if err != nil {
		return nil, err
	}

	outputs := make([]*TransactionOutput, noutputs)
	for i := 0; i < int(noutputs); i++ {
		output, err := NewTransactionOutputFromBuffer(buffer)
		if err != nil {
			return nil, err
		}
		outputs[i] = output
	}

	locktime, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	return &Transaction{
		Version:  version,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
	}, nil
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

//BytesWithWitness
// [nVersion][marker][flag][txins][txouts][witness][nLockTime]
func (t *Transaction) BytesWithWitness() []byte {
	if !t.HasWitness() {
		return t.Bytes()
	}

	buffer := NewBuffer().PutUint32(t.Version)
	buffer.PutUint8(TransactionWitnessMarker)
	buffer.PutUint8(TransactionWitnessFlag)

	buffer.PutVarInt(uint64(len(t.Inputs)))
	for i := 0; i < len(t.Inputs); i++ {
		buffer.PutBytes(t.Inputs[i].Bytes())
	}

	buffer.PutVarInt(uint64(len(t.Outputs)))
	for i := 0; i < len(t.Outputs); i++ {
		buffer.PutBytes(t.Outputs[i].Bytes())
	}

	for i := 0; i < len(t.Inputs); i++ {
		buffer.PutBytes(t.Inputs[i].ScriptWitness.Bytes())
	}

	buffer.PutUint32(t.Locktime)

	return buffer.Bytes()
}

func (t *Transaction) Hash() Hash {
	return DHash256(t.Bytes())
}
