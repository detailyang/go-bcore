package bcore

import (
	"encoding/hex"
	"testing"
)

func TestNewTransactionFromBytes(t *testing.T) {
	b := "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000"
	tx, err := NewTransactionFromHexString(b)
	if err != nil {
		t.Fatal(err)
	}

	if tx.Version != 1 {
		t.Fatalf("version: expect 1, got %d", tx.Version)
	}

	if len(tx.Inputs) != 1 {
		t.Fatalf("inputs len: expect 1, got %d", len(tx.Inputs))
	}

	if len(tx.Outputs) != 1 {
		t.Fatalf("outputs len: expect 1, got %d", len(tx.Outputs))
	}

	if tx.Locktime != 0 {
		t.Fatalf("locktime: expect 1, got %d", tx.Locktime)
	}

	input := tx.Inputs[0]
	if input.Sequence != 4294967295 {
		t.Fatalf("sequenece: expect 4294967295, got %d", input.Sequence)
	}

	if hex.EncodeToString(input.ScriptSig) != "48304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501" {
		t.Fatalf("input script signature: got %x", input.ScriptSig)
	}

	output := tx.Outputs[0]
	if output.Value != 5000000000 {
		t.Fatalf("ouput value: expect 5000000000, got %d", output.Value)
	}

	if hex.EncodeToString(output.ScriptPubkey) != "76a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac" {
		t.Fatalf("script pubkey: got %x", output.ScriptPubkey)
	}

	if tx.HasWitness() {
		t.Fatalf("should have no witness")
	}
}

func TestTransactionHash(t *testing.T) {
	b := "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000"
	tx, err := NewTransactionFromHexString(b)
	if err != nil {
		t.Fatal(err)
	}

	if tx.Hash().RString() != "5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2" {
		t.Fatal("tx rstring: got 5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2")
	}
}

func TestTransactionWithWitness(t *testing.T) {
	b := "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
	tx, err := NewTransactionWitnessFromHexString(b)
	if err != nil {
		t.Fatal(err)
	}

	if tx.Version != 1 {
		t.Fatalf("version: expect 1, got %d", tx.Version)
	}

	if len(tx.Inputs) != 2 {
		t.Fatalf("inputs len: expect 2, got %d", len(tx.Inputs))
	}

	in1 := tx.Inputs[0]
	if in1.PrevOutput.Hash.String() != "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" {
		t.Fatalf("inputs[0] prevoutpoint: got %s", "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f")
	}

	if in1.PrevOutput.Index != 0 {
		t.Fatalf("inputs[0] index: got %d", in1.PrevOutput.Index)
	}

	if hex.EncodeToString(in1.ScriptSig) != "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01" {
		t.Fatalf("inputs[0] hex: got %s", "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01")
	}

	if in1.Sequence != 0xffffffee {
		t.Fatalf("inputs[0] sequence got %d", in1.Sequence)
	}

	if in1.ScriptWitness.Size() != 0 {
		t.Fatalf("inputs[0] witness got %d", in1.ScriptWitness.Size())
	}

	in2 := tx.Inputs[1]
	if in2.PrevOutput.Hash.String() != "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" {
		t.Fatalf("inputs[1] prevoutpoint: got %s", in2.PrevOutput.Hash.String())
	}

	if in2.PrevOutput.Index != 1 {
		t.Fatalf("inputs[1] index: got %d", in1.PrevOutput.Index)
	}

	if hex.EncodeToString(in2.ScriptSig) != "" {
		t.Fatalf("inputs[1] hex: got %x", in2.ScriptSig)
	}

	if in2.Sequence != 0xffffffff {
		t.Fatalf("inputs[1] sequence got %d", in2.Sequence)
	}

	if in2.ScriptWitness.Size() != 2 {
		t.Fatalf("inputs[1] witness got %d", in2.ScriptWitness.Size())
	}

	b1, _ := hex.DecodeString("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01")
	b2, _ := hex.DecodeString("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")

	if !in2.ScriptWitness.Equal(NewScriptWitness([][]byte{
		b1, b2,
	})) {
		t.Fatalf("inputs[2] witness got %x", in2.ScriptWitness.Bytes())
	}
}
