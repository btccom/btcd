package txscript

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"testing"
)

func TestSignOpCacheFixture(t *testing.T) {
	sig1 := "304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd37801"
	sig2 := "304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d7401"
	pk1 := "0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc"
	pk2 := "04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0"
	pk3 := "043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186"
	txidFixture := "30dbd90e410098d25feacc8fa9cd7b453565621f4b1b60e91667c3cbf0fe0d51"
	params := &chaincfg.MainNetParams
	fixture := makeTx110Fixture(params)

	if fixture.tx.TxHash().String() != txidFixture {
		t.Errorf("Wrong tx hash for test fixture")
		return
	}

	if fixture.txIdx != 0 {
		t.Errorf("Wrong txidx for test fixture")
		return
	}

	if len(fixture.expectedOp) != 1 {
		t.Errorf("Wrong number of signOpcodes, 1 expected, got %d", len(fixture.expectedOp))
		return
	}

	op := fixture.expectedOp[0]
	if len(op.uncheckedSigs) != 2 {
		t.Errorf("Wrong number of unchecked signatures for fixture, got %d", len(op.uncheckedSigs))
		return
	}

	if err := checkSigAtIdx(op, 0, sig1); err != nil {
		t.Error(err.Error())
		return
	}
	if err := checkSigAtIdx(op, 1, sig2); err != nil {
		t.Error(err.Error())
		return
	}

	if err := checkSigInMap(op, 1, sig1); err != nil {
		t.Error(err.Error())
		return
	}

	if err := checkSigInMap(op, 2, sig2); err != nil {
		t.Error(err.Error())
		return
	}

	if err := checkKeyAtIdx(op, 0, pk1); err != nil {
		t.Error(err.Error())
		return
	}
	if err := checkKeyAtIdx(op, 1, pk2); err != nil {
		t.Error(err.Error())
		return
	}
	if err := checkKeyAtIdx(op, 2, pk3); err != nil {
		t.Error(err.Error())
		return
	}
}
func checkSigInMap(op *signOpCode, idxKeyOp int, sig string) error {
	if op.keyOp[idxKeyOp] == nil {
		return fmt.Errorf("KeyOp idx %d cannot be null", idxKeyOp)
	}
	rawSig := op.keyOp[idxKeyOp].sig.Serialize()
	serializedSig := append(rawSig, byte(op.keyOp[idxKeyOp].hashType))
	if hex.EncodeToString(serializedSig) != sig {
		return fmt.Errorf("Signature wrong, expected %s but got %s", sig, hex.EncodeToString(op.keyOp[idxKeyOp].sig.Serialize()))
	}

	return nil
}
func checkSigAtIdx(op *signOpCode, idx int, sig string) error {
	if hex.EncodeToString(op.uncheckedSigs[idx]) != sig {
		return fmt.Errorf("`uncheckedSig`[%d] is wrong: %s != %s", idx, hex.EncodeToString(op.uncheckedSigs[idx]), sig)
	}
	return nil
}
func checkKeyAtIdx(op *signOpCode, idx int, pk string) error {
	if hex.EncodeToString(op.uncheckedKeys[idx]) != pk {
		return fmt.Errorf("`uncheckedKey`[%d] is wrong: %s != %s", idx, hex.EncodeToString(op.uncheckedKeys[idx]), pk)

	}
	if hex.EncodeToString(op.keys[idx].SerializeUncompressed()) != pk {
		return fmt.Errorf("`key`[%d] is wrong: %s != %s", idx, hex.EncodeToString(op.keys[idx].SerializeUncompressed()), pk)
	}
	if op.keyOp[idx] != nil {
		if hex.EncodeToString(op.keyOp[idx].pubKey.SerializeUncompressed()) != pk {
			return fmt.Errorf("`key`[%d] is wrong: %s != %s", idx, hex.EncodeToString(op.keys[idx].SerializeUncompressed()), pk)
		}
	}

	return nil
}
