package bcore

import (
	"testing"
)

func TestNewBlock(t *testing.T) {
	s := "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000"
	b, err := NewBlockFromHexString(s)
	if err != nil {
		t.Fatal(err)
	}

	if b.Header.Version != 1 {
		t.Fatalf("block header version: got %d", b.Header.Version)
	}

	if b.Header.Time != 1284613427 {
		t.Fatalf("block header time: got %d", b.Header.Time)
	}

	if b.Header.PrevHash.RString() != "00000000001937917bd2caba204bb1aa530ec1de9d0f6736e5d85d96da9c8bba" {
		t.Fatalf("block header prev hash: got %s", b.Header.PrevHash.RString())
	}

	if b.Header.MerkleRoot.RString() != "8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719" {
		t.Fatalf("block header merkle root hash: got %s", b.Header.MerkleRoot.RString())
	}

	if b.Header.Bits != 459009510 {
		t.Fatalf("block header bits: got %d", b.Header.Bits)
	}

	if b.Header.Nonce != 1462756097 {
		t.Fatalf("block header nonce: got %d", b.Header.Nonce)
	}

	if len(b.Transactions) != 2 {
		t.Fatalf("block transactions: got %d", len(b.Transactions))
	}
}
