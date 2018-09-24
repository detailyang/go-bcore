package bcore

import (
	"testing"

	bscript "github.com/detailyang/go-bscript"
)

func TestVerifyScript(t *testing.T) {
	txhex := "0100000001484d40d45b9ea0d652fca8258ab7caa42541eb52975857f96fb50cd732c8b481000000008a47304402202cb265bf10707bf49346c3515dd3d16fc454618c58ec0a0ff448a676c54ff71302206c6624d762a1fcef4618284ead8f08678ac05b13c84235f1654e6ad168233e8201410414e301b2328f17442c0b8310d787bf3d8a404cfbd0704f135b6ad4b2d3ee751310f981926e53a6e8c39bd7d3fefd576c543cce493cbac06388f2651d1aacbfcdffffffff0162640100000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac00000000"
	tx, err := NewTransactionFromHexString(txhex)
	if err != nil {
		t.Fatal(err)
	}

	signer := NewTransactionSigner(tx, 0, 0)
	inputhex := "47304402202cb265bf10707bf49346c3515dd3d16fc454618c58ec0a0ff448a676c54ff71302206c6624d762a1fcef4618284ead8f08678ac05b13c84235f1654e6ad168233e8201410414e301b2328f17442c0b8310d787bf3d8a404cfbd0704f135b6ad4b2d3ee751310f981926e53a6e8c39bd7d3fefd576c543cce493cbac06388f2651d1aacbfcd"
	outputhex := "76a914df3bd30160e6c6145baaf2c88a8844c13a00d1d588ac"
	input, err := bscript.NewScriptFromHexString(inputhex)
	if err != nil {
		t.Fatal(err)
	}

	// disassembler := bscript.NewDisassembler()
	// fmt.Println(disassembler.Disassemble(input))

	output, err := bscript.NewScriptFromHexString(outputhex)
	if err != nil {
		t.Fatal(err)
	}

	// fmt.Println(disassembler.Disassemble(output))

	var flag bscript.Flag
	flag.Enable(bscript.ScriptVerfiyP2SH)

	err = bscript.VerifyScript(
		input,
		output,
		bscript.NewScriptWitness([][]byte{}),
		flag,
		signer,
		bscript.SignatureVersionBase,
	)
	if err != nil {
		t.Fatal(err)
	}
}
