package txscript

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"testing"
)

func rsToPkScript(rs []byte, params *chaincfg.Params) ([]byte, error) {
	addr, err := btcutil.NewAddressScriptHash(rs, params)
	if err != nil {
		return nil, err
	}

	scriptPubKey, _ := PayToAddrScript(addr)
	return scriptPubKey, nil
}

// SignOpCacheFixture contains the necessary data to test signOpCache
// over a single txin script.
type SignOpCacheFixture struct {
	tx         *wire.MsgTx
	txIdx      int
	flags      ScriptFlags
	txOut      *wire.TxOut
	expectedOp []*signOpCode
}

func (f *SignOpCacheFixture) AllowIncomplete() bool {
	if len(f.expectedOp) < 2 {
		return true
	}

	for i := 0; i < len(f.expectedOp)-2; i++ {
		if !f.expectedOp[i].HasAllSignatures() {
			return false
		}
	}

	return true
}

func (f *SignOpCacheFixture) Init(tx *wire.MsgTx, txIdx int, flags ScriptFlags, txOut *wire.TxOut) error {
	if txIdx < 0 || txIdx > len(tx.TxIn) {
		return fmt.Errorf("Invalid txIdx(%d) for transaction (has %d inputs)", txIdx, len(tx.TxIn))
	}

	f.tx = tx
	f.txIdx = txIdx
	f.flags = flags
	f.txOut = txOut
	f.expectedOp = make([]*signOpCode, 0)

	return nil
}

func parseSignSections(script []byte) ([][]byte, error) {

	pops, err := parseScript(script)
	if err != nil {
		return nil, err
	}

	sectionStart := 0
	sections := make([][]byte, 0)
	for i := 0; i < len(pops); i++ {
		opcode := int(pops[i].opcode.value)
		if opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY || opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
			section, err := unparseScript(pops[sectionStart : i+1])
			if err != nil {
				return nil, err
			}
			sections = append(sections, section)
			sectionStart = i + 1
		}
	}

	return sections, nil
}

func makeP2shFixture(params *chaincfg.Params, txHex string, txIdx int, txValue int64, rsHex string, sigHexes []map[int][]byte, keyHexes []map[int][]byte) *SignOpCacheFixture {
	serializedTx, _ := hex.DecodeString(txHex)
	tx, _ := btcutil.NewTxFromBytes(serializedTx)
	flags := ScriptFlags(ScriptVerifySigPushOnly | ScriptBip16 | ScriptVerifyCleanStack)

	rs, _ := hex.DecodeString(rsHex)
	sections, _ := parseSignSections(rs)

	rawScript, _ := parseScript(rs)
	scriptPubKey, _ := rsToPkScript(rs, params)

	fixture := &SignOpCacheFixture{}
	fixture.Init(tx.MsgTx(), txIdx, flags, wire.NewTxOut(txValue, scriptPubKey))

	for i := 0; i < len(sigHexes); i++ {
		section := sections[i]

		keys := make([]*btcec.PublicKey, 0, len(keyHexes[i]))
		uncheckedKeys := make([][]byte, 0, len(keyHexes[i]))
		for k := len(keyHexes[i]) - 1; k > -1; k-- {
			uncheckedKeys = append(uncheckedKeys, keyHexes[i][k])
			pubkey, _ := btcec.ParsePubKey(keyHexes[i][k], btcec.S256())
			keys = append(keys, pubkey)
		}

		sigs := make(map[int]*signOp, len(sigHexes))
		forUnchecked := 0
		for i, sigHex := range sigHexes[i] {
			signature, err := btcec.ParseDERSignature(sigHex, btcec.S256())
			if err != nil {
				panic(err)
			}
			hashType := SigHashType(sigHex[len(sigHex)-1])
			sigs[i] = &signOp{
				hashType: hashType,
				sig:      signature,
				pubKey:   keys[i],
			}
			if i > forUnchecked {
				forUnchecked = i
			}
		}

		uncheckedSigs := make([][]byte, 0, len(sigHexes))
		for u := 0; u <= forUnchecked; u++ {
			if unchecked, ok := sigHexes[i][u]; ok {
				uncheckedSigs = append(uncheckedSigs, unchecked)
			}
		}

		fixture.expectedOp = append(fixture.expectedOp, &signOpCode{
			opcode:        int(section[len(section)-1]),
			rawScript:     rawScript,
			signScript:    rawScript,
			keys:          keys,
			keyOp:         sigs,
			uncheckedSigs: uncheckedSigs,
			uncheckedKeys: uncheckedKeys,
		})
	}

	return fixture
}

func makeTx001Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "0100000001951aefe7968498e74fc5fc52d81009d95a01eb2eaae67cc9fcef61b68ebbc0b800000000fd1401004730440220516b0f747d126b12cdfb891239b3dfc547a719175edfe0309503e76d6f1ea27602205ff41618e5019dcd748ae51b7e4aa43b3d0acb0d3ecff4c05aa43ad87a1e2df9014cc95241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a914221154d32a82ae83f9e75431feae77a37af771a68700000000"
	txIdx := 0
	var txValue int64
	rs := "5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	k1, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k2, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k3, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys1 := make(map[int][]byte, 3)
	keys1[0] = k1
	keys1[1] = k2
	keys1[2] = k3

	s1, _ := hex.DecodeString("30440220516b0f747d126b12cdfb891239b3dfc547a719175edfe0309503e76d6f1ea27602205ff41618e5019dcd748ae51b7e4aa43b3d0acb0d3ecff4c05aa43ad87a1e2df901")

	sigs := make(map[int][]byte, 2)
	sigs[0] = s1

	sigsSet := []map[int][]byte{sigs}
	keysSet := []map[int][]byte{keys1}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}

func makeTx010Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "0100000001951aefe7968498e74fc5fc52d81009d95a01eb2eaae67cc9fcef61b68ebbc0b800000000fd14010047304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd378014cc95241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a914221154d32a82ae83f9e75431feae77a37af771a68700000000"
	txIdx := 0
	var txValue int64
	rs := "5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	k1, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k2, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k3, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys1 := make(map[int][]byte, 3)
	keys1[0] = k1
	keys1[1] = k2
	keys1[2] = k3

	s1, _ := hex.DecodeString("304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd37801")

	sigs := make(map[int][]byte, 2)
	sigs[1] = s1

	sigsSet := []map[int][]byte{sigs}
	keysSet := []map[int][]byte{keys1}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func makeTx100Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "0100000001951aefe7968498e74fc5fc52d81009d95a01eb2eaae67cc9fcef61b68ebbc0b800000000fd14010047304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d74014cc95241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a914221154d32a82ae83f9e75431feae77a37af771a68700000000"
	txIdx := 0
	var txValue int64
	rs := "5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	k1, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k2, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k3, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys1 := make(map[int][]byte, 3)
	keys1[0] = k1
	keys1[1] = k2
	keys1[2] = k3

	s1, _ := hex.DecodeString("304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d7401")

	sigs := make(map[int][]byte, 2)
	sigs[2] = s1

	sigsSet := []map[int][]byte{sigs}
	keysSet := []map[int][]byte{keys1}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func makeTx011Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "0100000001951aefe7968498e74fc5fc52d81009d95a01eb2eaae67cc9fcef61b68ebbc0b800000000fd5c01004730440220516b0f747d126b12cdfb891239b3dfc547a719175edfe0309503e76d6f1ea27602205ff41618e5019dcd748ae51b7e4aa43b3d0acb0d3ecff4c05aa43ad87a1e2df90147304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd378014cc95241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a914221154d32a82ae83f9e75431feae77a37af771a68700000000"
	txIdx := 0
	var txValue int64
	rs := "5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	k1, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k2, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k3, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys1 := make(map[int][]byte, 3)
	keys1[0] = k1
	keys1[1] = k2
	keys1[2] = k3

	s1, _ := hex.DecodeString("30440220516b0f747d126b12cdfb891239b3dfc547a719175edfe0309503e76d6f1ea27602205ff41618e5019dcd748ae51b7e4aa43b3d0acb0d3ecff4c05aa43ad87a1e2df901")
	s2, _ := hex.DecodeString("304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd37801")

	sigs := make(map[int][]byte, 2)
	sigs[0] = s1
	sigs[1] = s2

	sigsSet := []map[int][]byte{sigs}
	keysSet := []map[int][]byte{keys1}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func makeTx110Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "0100000001951aefe7968498e74fc5fc52d81009d95a01eb2eaae67cc9fcef61b68ebbc0b800000000fd5c010047304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd3780147304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d74014cc95241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a914221154d32a82ae83f9e75431feae77a37af771a68700000000"
	txIdx := 0
	var txValue int64
	rs := "5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	k1, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k2, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k3, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys1 := make(map[int][]byte, 3)
	keys1[0] = k1
	keys1[1] = k2
	keys1[2] = k3

	s1, _ := hex.DecodeString("304402207335ff2de2b32168ec9ea26752bfe1c34b53ad15cc2904cb570e62a4cc851db2022045575bce2cf374ab0d7091003a418c20bc05fcea52f632762b6691c1aedcd37801")
	s2, _ := hex.DecodeString("304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d7401")

	sigs := make(map[int][]byte, 2)
	sigs[1] = s1
	sigs[2] = s2

	sigsSet := []map[int][]byte{sigs}
	keysSet := []map[int][]byte{keys1}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func makeTx101Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "0100000001951aefe7968498e74fc5fc52d81009d95a01eb2eaae67cc9fcef61b68ebbc0b800000000fd5c01004730440220516b0f747d126b12cdfb891239b3dfc547a719175edfe0309503e76d6f1ea27602205ff41618e5019dcd748ae51b7e4aa43b3d0acb0d3ecff4c05aa43ad87a1e2df90147304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d74014cc95241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a914221154d32a82ae83f9e75431feae77a37af771a68700000000"
	txIdx := 0
	var txValue int64
	rs := "5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	k1, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k2, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k3, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys1 := make(map[int][]byte, 3)
	keys1[0] = k1
	keys1[1] = k2
	keys1[2] = k3

	s1, _ := hex.DecodeString("30440220516b0f747d126b12cdfb891239b3dfc547a719175edfe0309503e76d6f1ea27602205ff41618e5019dcd748ae51b7e4aa43b3d0acb0d3ecff4c05aa43ad87a1e2df901")
	s2, _ := hex.DecodeString("304402202478513599ca49bec6de0751d36fdc47ffe697a25d3ada64694b08040782983d02201915074336baf3d9bca7f7751aa81605c2a8013c221c88e1fefc76ea1cd68d7401")

	sigs := make(map[int][]byte, 2)
	sigs[0] = s1
	sigs[2] = s2

	sigsSet := []map[int][]byte{sigs}
	keysSet := []map[int][]byte{keys1}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}

func makeTxChecksigCheckMultisigA1B110Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "01000000012cf3d2573f21c293c9fed880e4a4e654fa7b660df2c0e0c698790c4eeb2c328700000000fdc70100483045022100a0de99c4e19afcdc0247f459703f3b88ae96858eb7147fc767159fd27a37e4b102201bf9e7b4781ae19902ffe69ed2300289ad7fb797a45d257771542c2377290adf01473044022010030a967c58b4b96bb368772eb959921f4b30a1df8425041e32175426011d560220741143c6fce2c9b18084978c183e19fafa5c597d1300431e4269071525ab124d01463043021f6f6a5467bcde8a7838d5ce509b1fc82c57d873a41321c17a3ad26b9b4c1bdd022033ace1fdaa012a273531a4ae52e0e4dcb2b669e792fa811e422636cb6899c7f2014cec2103b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcbaad5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a9142fadd65f8f46a80384eb8db4886890df6b94d4d78700000000"
	txIdx := 0
	var txValue int64

	rs := "2103b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcbaad5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	s1, _ := hex.DecodeString("3043021f6f6a5467bcde8a7838d5ce509b1fc82c57d873a41321c17a3ad26b9b4c1bdd022033ace1fdaa012a273531a4ae52e0e4dcb2b669e792fa811e422636cb6899c7f201")
	sigs1 := make(map[int][]byte, 1)
	sigs1[0] = s1

	k1, _ := hex.DecodeString("03b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcba")
	keys1 := make(map[int][]byte, 1)
	keys1[0] = k1

	s2, _ := hex.DecodeString("3045022100a0de99c4e19afcdc0247f459703f3b88ae96858eb7147fc767159fd27a37e4b102201bf9e7b4781ae19902ffe69ed2300289ad7fb797a45d257771542c2377290adf01")
	s3, _ := hex.DecodeString("3044022010030a967c58b4b96bb368772eb959921f4b30a1df8425041e32175426011d560220741143c6fce2c9b18084978c183e19fafa5c597d1300431e4269071525ab124d01")
	sigs2 := make(map[int][]byte, 2)
	sigs2[0] = s2
	sigs2[1] = s3

	k2, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k3, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k4, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys2 := make(map[int][]byte, 1)
	keys2[1] = k2
	keys2[2] = k3
	keys2[3] = k4

	sigsSet := []map[int][]byte{sigs1, sigs2}
	keysSet := []map[int][]byte{keys1, keys2}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func makeTxChecksigCheckMultisigA1B011Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "01000000012cf3d2573f21c293c9fed880e4a4e654fa7b660df2c0e0c698790c4eeb2c328700000000fdc70100473044022010030a967c58b4b96bb368772eb959921f4b30a1df8425041e32175426011d560220741143c6fce2c9b18084978c183e19fafa5c597d1300431e4269071525ab124d0148304502210081090d4d91c7ef88c9bb505271817dab52efc9d09286eef297c517bd2cdcfacc02204ef88ab9bdb40759abbd82ad119a8265fee2e680219dfa5ecafb9617067de3f901463043021f6f6a5467bcde8a7838d5ce509b1fc82c57d873a41321c17a3ad26b9b4c1bdd022033ace1fdaa012a273531a4ae52e0e4dcb2b669e792fa811e422636cb6899c7f2014cec2103b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcbaad5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a9142fadd65f8f46a80384eb8db4886890df6b94d4d78700000000"
	txIdx := 0
	var txValue int64

	rs := "2103b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcbaad5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	s1, _ := hex.DecodeString("3043021f6f6a5467bcde8a7838d5ce509b1fc82c57d873a41321c17a3ad26b9b4c1bdd022033ace1fdaa012a273531a4ae52e0e4dcb2b669e792fa811e422636cb6899c7f201")
	sigs1 := make(map[int][]byte, 1)
	sigs1[0] = s1

	k1, _ := hex.DecodeString("03b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcba")
	keys1 := make(map[int][]byte, 1)
	keys1[0] = k1

	s2, _ := hex.DecodeString("3044022010030a967c58b4b96bb368772eb959921f4b30a1df8425041e32175426011d560220741143c6fce2c9b18084978c183e19fafa5c597d1300431e4269071525ab124d01")
	s3, _ := hex.DecodeString("304502210081090d4d91c7ef88c9bb505271817dab52efc9d09286eef297c517bd2cdcfacc02204ef88ab9bdb40759abbd82ad119a8265fee2e680219dfa5ecafb9617067de3f901")
	sigs2 := make(map[int][]byte, 2)
	sigs2[1] = s2
	sigs2[2] = s3

	k2, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k3, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k4, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys2 := make(map[int][]byte, 1)
	keys2[1] = k2
	keys2[2] = k3
	keys2[3] = k4

	sigsSet := []map[int][]byte{sigs1, sigs2}
	keysSet := []map[int][]byte{keys1, keys2}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func makeTxChecksigCheckMultisigA1B101Fixture(params *chaincfg.Params) *SignOpCacheFixture {
	txHex := "01000000012cf3d2573f21c293c9fed880e4a4e654fa7b660df2c0e0c698790c4eeb2c328700000000fdc80100483045022100a0de99c4e19afcdc0247f459703f3b88ae96858eb7147fc767159fd27a37e4b102201bf9e7b4781ae19902ffe69ed2300289ad7fb797a45d257771542c2377290adf0148304502210081090d4d91c7ef88c9bb505271817dab52efc9d09286eef297c517bd2cdcfacc02204ef88ab9bdb40759abbd82ad119a8265fee2e680219dfa5ecafb9617067de3f901463043021f6f6a5467bcde8a7838d5ce509b1fc82c57d873a41321c17a3ad26b9b4c1bdd022033ace1fdaa012a273531a4ae52e0e4dcb2b669e792fa811e422636cb6899c7f2014cec2103b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcbaad5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53aeffffffff01010000000000000017a9142fadd65f8f46a80384eb8db4886890df6b94d4d78700000000"
	txIdx := 0
	var txValue int64

	rs := "2103b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcbaad5241043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd1864104e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0410473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc53ae"

	s1, _ := hex.DecodeString("3043021f6f6a5467bcde8a7838d5ce509b1fc82c57d873a41321c17a3ad26b9b4c1bdd022033ace1fdaa012a273531a4ae52e0e4dcb2b669e792fa811e422636cb6899c7f201")
	sigs1 := make(map[int][]byte, 1)
	sigs1[0] = s1

	k1, _ := hex.DecodeString("03b08adc2b1f9892aa5e72327ff7e57516e7bbe3b49b23587beb85f0f43f02dcba")
	keys1 := make(map[int][]byte, 1)
	keys1[0] = k1

	s2, _ := hex.DecodeString("3045022100a0de99c4e19afcdc0247f459703f3b88ae96858eb7147fc767159fd27a37e4b102201bf9e7b4781ae19902ffe69ed2300289ad7fb797a45d257771542c2377290adf01")
	s3, _ := hex.DecodeString("304502210081090d4d91c7ef88c9bb505271817dab52efc9d09286eef297c517bd2cdcfacc02204ef88ab9bdb40759abbd82ad119a8265fee2e680219dfa5ecafb9617067de3f901")
	sigs2 := make(map[int][]byte, 2)
	sigs2[0] = s2
	sigs2[2] = s3

	k2, _ := hex.DecodeString("043e49ec68abcf030dfc8ec7dfcb388b17fed99134d5f910c87e947f0cc86a1cf9c29b27ddbd0443b6d40fc5cb35eb13fcb41bf0e4f63d74bea2576e8db07dd186")
	k3, _ := hex.DecodeString("04e38fa9a9dfa216d45d90cfca8ca2566f2d9aa9c1846e6dd6ab0756c07262abe1c7f8a60ff2357bc2ea9fb597bfbcf4d3e4fe605a294171dc32421578125136e0")
	k4, _ := hex.DecodeString("0473682ed776e9d0afee6cd52f4a4b20ad458956ef5567d5747853b689bb44a6a90736b515aa63bc5703c7d1a5662b7e2421b9436597fd8bf8da216f2b1cba01cc")
	keys2 := make(map[int][]byte, 1)
	keys2[1] = k2
	keys2[2] = k3
	keys2[3] = k4

	sigsSet := []map[int][]byte{sigs1, sigs2}
	keysSet := []map[int][]byte{keys1, keys2}

	return makeP2shFixture(params, txHex, txIdx, txValue, rs, sigsSet, keysSet)
}
func TestSignOpCache(t *testing.T) {
	params := &chaincfg.MainNetParams
	fixtures := make([]*SignOpCacheFixture, 0)

	fixtures = append(fixtures, makeTx011Fixture(params))
	fixtures = append(fixtures, makeTx110Fixture(params))
	fixtures = append(fixtures, makeTx101Fixture(params))
	fixtures = append(fixtures, makeTx001Fixture(params))
	fixtures = append(fixtures, makeTx010Fixture(params))
	fixtures = append(fixtures, makeTx100Fixture(params))
	fixtures = append(fixtures, makeTxChecksigCheckMultisigA1B110Fixture(params))
	fixtures = append(fixtures, makeTxChecksigCheckMultisigA1B011Fixture(params))
	fixtures = append(fixtures, makeTxChecksigCheckMultisigA1B101Fixture(params))

	for i := 0; i < len(fixtures); i++ {
		description := fmt.Sprintf("Fixture %d", i)
		t.Run(description, func(t *testing.T) {
			runSignOpTestFixture(t, fixtures[i])
		})
	}
}

func runSignOpTestFixture(t *testing.T, fixture *SignOpCacheFixture) {

	nExpectedSignOps := len(fixture.expectedOp)
	fAllowIncomplete := fixture.AllowIncomplete()

	e, err := NewEngine(fixture.txOut.PkScript, fixture.tx, fixture.txIdx, fixture.flags, nil, nil, fixture.txOut.Value)
	if err != nil {
		t.Errorf("Expected NewEngine to succeed but got error: %s", err.Error())
		return
	}

	// Use fixtures 'AllowComplete' because if execution
	// fails when the think we have all signatures, we've
	// got big problems, (and also, if we know it's incomplete
	// we can test the first few sign ops)
	ops, err := e.ExecuteSignOp(fAllowIncomplete)
	if err != nil {
		t.Errorf("An error occured while parsing signature operations: %s", err.Error())
		return
	}

	// The number of executed signing operations must match
	// the expected value
	if len(ops.ops) != nExpectedSignOps {
		t.Errorf("Found %d values in signOpCache, expecting %d", len(ops.ops), nExpectedSignOps)
		return
	}

	for i := 0; i < nExpectedSignOps; i++ {
		op := ops.getIdx(i)
		if op == nil {
			t.Errorf("Unable to find idx %d after counting results", i)
			return
		}

		opFixture := fixture.expectedOp[i]

		//fExpectedValid := opFixture.ExpectedCheckSignaturesValid()
		//if fExpectedValid && !op.CheckSignaturesOk() {
		//	t.Errorf("Unexpected result for CheckSignaturesOk: expected %s", fExpectedValid)
		//	return
		//}

		fSignOpComplete := op.HasAllSignatures()
		if fSignOpComplete {
			err := checkCompleteSigsFixture(op, opFixture)
			if err != nil {
				t.Error(err)
				return
			}

			err = checkIncompleteSigsFixture(op, ops.verifyData, opFixture)
			if err != nil {
				t.Error(err)
				return
			}
		} else {
			err := checkIncompleteSigsFixture(op, ops.verifyData, opFixture)
			if err != nil {
				t.Error(err)
				return
			}
		}
	}
}

func checkSigsAgainstFixture(sigs map[int]*SignatureInfo, opFixture *signOpCode) error {
	if len(sigs) != len(opFixture.keyOp) {
		return fmt.Errorf("Number of sigs does not match fixture, expected %d, got %d", len(opFixture.keyOp), len(sigs))
	}

	for i := 0; i < len(opFixture.uncheckedKeys); i++ {
		if opFixture.keyOp[i] != nil {
			keyOp := opFixture.keyOp[i]
			if !keyOp.sig.IsEqual(sigs[i].Signature) {
				return fmt.Errorf("bad sig at %d ", i)
			}
		}

	}

	return nil
}

func checkIncompleteSigsFixture(state *signOpCode, txData *txVerifyData, opFixture *signOpCode) error {
	sigs, err := state.IncompleteSigs(txData)
	if err != nil {
		return fmt.Errorf("An error was returned from IncompleteSigs %s", err.Error())
	}

	if len(state.uncheckedSigs) < len(opFixture.keyOp) {
		return fmt.Errorf("Incomplete op's `uncheckedSigs` count didnt match: expected %d got %d", len(opFixture.keyOp), len(state.uncheckedSigs))
	}

	return checkSigsAgainstFixture(sigs, opFixture)
}

func checkCompleteSigsFixture(state *signOpCode, opFixture *signOpCode) error {
	sigs, err := state.Sigs()
	if err != nil {
		return err
	}

	return checkSigsAgainstFixture(sigs, opFixture)

}
