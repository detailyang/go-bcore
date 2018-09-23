package bcore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
)

var (
	ErrTransactionInputWrongSize         = errors.New("transaction input:  wrong size")
	ErrTransactionInputOutPointWrongSize = errors.New("transaction outpoint: wrong size")
	ErrTransactionNoWitnessMarker        = errors.New("transaction: no witness marker")
	ErrTransactionNoWitnessFlag          = errors.New("transaction: no witness flag")
)

const (
	TransactionFinalSequence = 0xffffffff
	TransactionWitnessMarker = 0x00
	TransactionWitnessFlag   = 0x01

	TransactionOutPointSize = HashSize + 4
)

type Transaction struct {
	// Transaction version number; currently version 1.
	// Programs creating transactions using newer consensus rules may use higher version numbers.
	Version uint32
	Inputs  []*TransactionInput
	Outputs []*TransactionOutput
	// A time (Unix epoch time) or block number. See the locktime parsing rules.
	Locktime uint32
}

type OutPoint struct {
	// The TXID of the transaction holding the output to spend. The TXID is a hash provided here in internal byte order.
	Hash Hash
	// The output index number of the specific output to spend from the transaction. The first output is 0x00000000.
	Index uint32
}

type TransactionInput struct {
	// The previous outpoint being spent
	PrevOutput *OutPoint
	// A script-language script which satisfies the conditions placed in the outpoint’s pubkey script. Should only contain data pushes
	ScriptSig []byte
	// Sequence number. Default for Bitcoin Core and almost all other programs is 0xffffffff.
	Sequence      uint32
	ScriptWitness ScriptWitness
}

type TransactionOutput struct {
	// Number of satoshis to spend. May be zero; the sum of all outputs may not exceed the sum of satoshis previously spent to the outpoints provided in the input section
	Value uint64
	// Defines the conditions which must be satisfied to spend this output.
	ScriptPubkey []byte
}

type ScriptWitness [][]byte

func NewScriptWitness(b [][]byte) ScriptWitness {
	witness := ScriptWitness(b)
	return witness
}

func NewScriptWitnessFromBuffer(buffer *Buffer) (ScriptWitness, error) {
	n, err := buffer.GetVarInt()
	if err != nil {
		return nil, err
	}

	witness := make([][]byte, n)
	for i := 0; i < int(n); i++ {
		b, err := buffer.GetVarBytes()
		if err != nil {
			return nil, err
		}
		witness[i] = b
	}

	return NewScriptWitness(witness), nil
}

func (s ScriptWitness) Equal(t ScriptWitness) bool {
	if s.Size() != t.Size() {
		return false
	}

	for i, _ := range s {
		if !bytes.Equal(s[i], t[i]) {
			return false
		}
	}

	return true
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

func (o OutPoint) Clone() *OutPoint {
	return &OutPoint{
		Hash:  o.Hash.Clone(),
		Index: o.Index,
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
		ScriptWitness: NewScriptWitness([][]byte{}),
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

func NewDefaultTransactionOutput() *TransactionOutput {
	return &TransactionOutput{
		Value:        0xffffffffffffffff,
		ScriptPubkey: []byte{},
	}
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

func (to *TransactionOutput) Clone() *TransactionOutput {
	scriptPubkey := make([]byte, len(to.ScriptPubkey))
	copy(scriptPubkey, to.ScriptPubkey)

	return &TransactionOutput{
		Value:        to.Value,
		ScriptPubkey: scriptPubkey,
	}
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

func NewTransactionWitnessFromHexString(hexstring string) (*Transaction, error) {
	b, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}

	return NewTransactionWitnessFromBytes(b)
}

func NewTransactionFromBytes(data []byte) (*Transaction, error) {
	return NewTransactionFromBuffer(NewReadBuffer(data))
}

func NewTransactionFromBuffer(buffer *Buffer) (*Transaction, error) {
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

func NewTransactionWitnessFromBytes(data []byte) (*Transaction, error) {
	buffer := NewReadBuffer(data)

	version, err := buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	marker, err := buffer.GetUint8()
	if err != nil {
		return nil, err
	}

	if marker != TransactionWitnessMarker {
		return nil, ErrTransactionNoWitnessMarker
	}

	flag, err := buffer.GetUint8()
	if err != nil {
		return nil, err
	}

	if flag != TransactionWitnessFlag {
		return nil, ErrTransactionNoWitnessFlag
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

	for i := 0; i < int(ninputs); i++ {
		witness, err := NewScriptWitnessFromBuffer(buffer)
		if err != nil {
			return nil, err
		}
		inputs[i].ScriptWitness = witness
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

func (t *Transaction) WitnessHash() Hash {
	return DHash256(t.BytesWithWitness())
}

func (t *Transaction) Hash() Hash {
	return DHash256(t.Bytes())
}
