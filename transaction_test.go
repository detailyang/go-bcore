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

}
