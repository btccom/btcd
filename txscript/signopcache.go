package txscript

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type txVerifyData struct {
	tx          *wire.MsgTx
	txIdx       int
	inputAmount int64
	sigVersion  int
	flags       ScriptFlags
}

// SignOpCache contains information about every executed CHECKSIG-like
// operation during a scripts execution
type SignOpCache struct {
	ops        []*signOpCode
	verifyData *txVerifyData
	pcToIdx    map[int]int
	nextIdx    int
}

// PublicKeyInfo stores the necessary data to reproduce the serialized
// form of a public key parsed during
type PublicKeyInfo struct {
	Format btcutil.PubKeyFormat
	Key    *btcec.PublicKey
}

// Serialize will take the known key format and btcec.PublicKey and
// produce the serialized key.
func (keyInfo *PublicKeyInfo) Serialize() ([]byte, error) {
	switch keyInfo.Format {
	case btcutil.PKFHybrid:
		return keyInfo.Key.SerializeHybrid(), nil
	case btcutil.PKFCompressed:
		return keyInfo.Key.SerializeCompressed(), nil
	case btcutil.PKFUncompressed:
		return keyInfo.Key.SerializeHybrid(), nil
	default:
		return nil, fmt.Errorf("Unsupported public key format")
	}
}

type SignatureInfo struct {
	HashType  SigHashType
	Signature *btcec.Signature
}

// Serialize will take the hashType and *btcec.Signature and
// produce the txin signature
func (sigInfo *SignatureInfo) Serialize() []byte {
	ecSig := sigInfo.Signature.Serialize()
	ecSig = append(ecSig, byte(int(sigInfo.HashType)))
	return ecSig
}

// add associates a signOpCode with a particular script offset.
func (c *SignOpCache) add(scriptOff int, state *signOpCode) {
	c.ops = append(c.ops, state)
	c.pcToIdx[scriptOff] = c.nextIdx
	c.nextIdx++
}

// getIdx returns the checkSigState for the idx'th signature
// operation that was pushed into the cache.
func (c *SignOpCache) getIdx(idx int) *signOpCode {
	if idx < 0 || idx > len(c.ops) {
		return nil
	}

	return c.ops[idx]
}

// IsComplete returns whether the path up to idx, and idx itself
// are fully complete, by return two boolean return values. It's
// third return value is set only if `idx` is out of range.
// For the path to complete, ops[0->idx-1] must be complete.
// For the index to be complete, the path and the final op must
// be complete.
func (c *SignOpCache) IsComplete(idx int) (bool, bool, error) {
	if idx < 0 || idx > len(c.ops) {
		return false, false, fmt.Errorf("no signature operation at index %d", idx)
	}

	if idx > 0 {
		for i := 0; i < idx; i++ {
			if !c.ops[idx].HasAllSignatures() {
				return false, false, nil
			}
		}
	}

	return true, c.ops[idx].HasAllSignatures(), nil
}

func (c *SignOpCache) getSignOps(complete bool, idx int) (map[int]*PublicKeyInfo, map[int]*SignatureInfo, error) {
	op := c.getIdx(idx)
	if op == nil {
		return nil, nil, fmt.Errorf("no signature operation at index %d", idx)
	}

	var sigs map[int]*SignatureInfo
	var err error
	if complete {
		sigs, err = op.Sigs()
	} else {
		sigs, err = op.IncompleteSigs(c.verifyData)
	}
	if err != nil {
		return nil, nil, err
	}

	keys := make(map[int]*PublicKeyInfo, len(op.uncheckedKeys))
	for i := 0; i < len(op.uncheckedKeys); i++ {
		keyBytes := op.uncheckedKeys[0]

		var pubKey *btcec.PublicKey

		if complete {
			keyOp, ok := op.keyOp[i]
			if ok {
				pubKey = keyOp.pubKey
			}
		}

		pkFormat := btcutil.PKFUncompressed
		switch keyBytes[0] {
		case 0x02, 0x03:
			pkFormat = btcutil.PKFCompressed
		case 0x06, 0x07:
			pkFormat = btcutil.PKFHybrid
		}

		if pubKey == nil {
			pubKey, err = btcec.ParsePubKey(keyBytes, btcec.S256())
			if err != nil {
				return nil, nil, err
			}
		}

		keys[len(op.uncheckedKeys)-1-i] = &PublicKeyInfo{pkFormat, pubKey}
	}

	return keys, sigs, nil
}

// GetSignOps returns a map of keyIdx => publicKey, and keyIdx => signature,
// where the signatures were successfully validated in the script. All public
// keys will be returned, so an association between signature & validating public
// key is maintained.

// GetSignOps returns a map of keyIdx => publicKey, and keyIdx => signature,
// where the signatures were successfully validated in the script. All public
// keys will be returned, so an association between signature & validating public
// key is maintained.
func (c *SignOpCache) GetSignOps(idx int) (map[int]*PublicKeyInfo, map[int]*SignatureInfo, error) {
	return c.getSignOps(true, idx)
}

func (c *SignOpCache) GetIncompleteOps(idx int) (map[int]*PublicKeyInfo, map[int]*SignatureInfo, error) {
	return c.getSignOps(false, idx)
}

// NewSignOpCache initializes a new SignOpCache
func NewSignOpCache(data *txVerifyData) *SignOpCache {
	return &SignOpCache{
		verifyData: data,
		nextIdx:    0,
		ops:        make([]*signOpCode, 0),
		pcToIdx:    make(map[int]int),
	}
}

type signOpCode struct {
	opcode        int
	rawScript     []parsedOpcode
	signScript    []parsedOpcode
	keys          []*btcec.PublicKey
	uncheckedKeys [][]byte
	uncheckedSigs [][]byte
	keyOp         map[int]*signOp
}

// InitCheckSig initializes the operation for an op CHECKSIG/CHECKSIGVERIFY
// operation
func (s *signOpCode) InitCheckSig(opcode int, pops []parsedOpcode) error {
	if opcode != OP_CHECKSIG && opcode != OP_CHECKSIGVERIFY {
		return fmt.Errorf("Invalid opcode for signop: %d", opcode)
	}

	s.opcode = opcode
	s.rawScript = pops
	s.keys = make([]*btcec.PublicKey, 0, 1)
	s.keyOp = make(map[int]*signOp, 1)

	return nil
}

// InitCheckMultiSig initializes the operation for an op CHECKMULTISIG/
// CHECKMULTISIGVERIFY operation. It is initialized with the maximum
// number of keys/keyOps
func (s *signOpCode) InitCheckMultiSig(opcode int, pops []parsedOpcode) error {
	if opcode != OP_CHECKMULTISIG && opcode != OP_CHECKMULTISIGVERIFY {
		return fmt.Errorf("Invalid opcode for signop: %d", opcode)
	}

	s.opcode = opcode
	s.rawScript = pops
	s.keys = make([]*btcec.PublicKey, 0, MaxPubKeysPerMultiSig)
	s.keyOp = make(map[int]*signOp, MaxPubKeysPerMultiSig)

	return nil
}

// SigCount returns the number of signing operations observed
// during the opcodes execution
func (s *signOpCode) SigCount() int {
	found := 0
	for _, op := range s.keyOp {
		if op != nil {
			found++
		}
	}
	return found
}

// HasAllSignatures checks that the SigCount matches the number
// of uncheckedSigs.
func (s *signOpCode) HasAllSignatures() bool {
	return s.SigCount() == len(s.uncheckedSigs)
}

// Sigs returns a map of pubKeyIdx => signature. It requires
// that the script successfully executed.
func (s *signOpCode) Sigs() (map[int]*SignatureInfo, error) {
	if !s.HasAllSignatures() {
		return nil, fmt.Errorf("cannot call Sigs when state is still incomplete")
	}

	numKeys := len(s.uncheckedKeys)
	signatures := make(map[int]*SignatureInfo, numKeys)
	for i := 0; i < len(s.uncheckedKeys); i++ {
		if s.keyOp[i] == nil {
			continue
		}

		signatures[numKeys-1-i] = &SignatureInfo{s.keyOp[i].hashType, s.keyOp[i].sig}
	}

	return signatures, nil
}

// IncompleteSigs takes any stackSigs/stackKeys observed during execution,
// and attempts to build of pubkeyIdx => signature. It should only be used
// called for the _first_ incomplete signOpCode, since we can't assert much
// about the stack beyond this point.
func (s *signOpCode) IncompleteSigs(data *txVerifyData) (map[int]*SignatureInfo, error) {
	sigs := s.uncheckedSigs
	signatures := make(map[int]*SignatureInfo, len(s.uncheckedKeys))
	numKeys := len(s.uncheckedKeys)
	for k := 0; k < len(s.uncheckedKeys); k++ {
		var subscript []parsedOpcode
		if len(s.signScript) > 0 {
			subscript = s.signScript
		} else if len(s.rawScript) > 0 {
			subscript = s.rawScript

			if data.sigVersion == 0 {
				// Remove any of the signatures since there is no way for a
				// signature to sign itself.
				for _, sig := range sigs {
					if len(sig) > 0 {
						subscript = removeOpcodeByData(subscript, sig)
					}
				}
			}
		}

		// Parse the pubkey.
		parsedPubKey, err := btcec.ParsePubKey(s.uncheckedKeys[k], btcec.S256())
		if err != nil {
			continue
		}

		for s := 0; s < len(sigs); s++ {
			rawSig := sigs[s]
			if len(rawSig) == 0 {
				continue
			}

			hashType := SigHashType(rawSig[len(rawSig)-1])
			signature := rawSig[:len(rawSig)-1]

			//Parse the signature.
			var err error
			var parsedSig *btcec.Signature
			if data.flags&ScriptVerifyStrictEncoding == ScriptVerifyStrictEncoding ||
				data.flags&ScriptVerifyDERSignatures == ScriptVerifyDERSignatures {
				parsedSig, err = btcec.ParseDERSignature(signature,
					btcec.S256())
			} else {
				parsedSig, err = btcec.ParseSignature(signature,
					btcec.S256())
			}

			if err != nil {
				return nil, err
			}

			var shash []byte // = cs.GetCachedSigHash(hashType)
			//if shash == nil {
			//Generate the signature hash based on the signature hash type.
			if data.sigVersion == 1 {
				sigHashes := NewTxSigHashes(data.tx)

				shash = calcWitnessSignatureHash(subscript, sigHashes, hashType,
					data.tx, data.txIdx, data.inputAmount)
			} else {
				shash = calcSignatureHash(subscript, hashType, data.tx, data.txIdx)
			}
			//}

			valid := parsedSig.Verify(shash, parsedPubKey)

			if valid {
				sigs = removeSig(sigs, s)
				signatures[numKeys-1-k] = &SignatureInfo{hashType, parsedSig}
				continue
			}
		}
	}

	return signatures, nil
}

func removeSig(slice [][]byte, s int) [][]byte {
	return append(slice[:s], slice[s+1:]...)
}

type signOp struct {
	hashType SigHashType
	sig      *btcec.Signature
	pubKey   *btcec.PublicKey
}

func (s *signOpCode) stackKey(key []byte) {
	s.uncheckedKeys = append(s.uncheckedKeys, key)
}
func (s *signOpCode) stackSignature(sig []byte) {
	s.uncheckedSigs = append(s.uncheckedSigs, sig)
}
func (s *signOpCode) hashScript(subscript []parsedOpcode) {
	s.signScript = subscript
}

func (s *signOpCode) signature(op *signOp) {
	s.keys = append(s.keys, op.pubKey)
	idx := len(s.keys) - 1
	s.keyOp[idx] = op
}

func (s *signOpCode) skipKey(key *btcec.PublicKey) {
	s.keys = append(s.keys, key)
	idx := len(s.keys) - 1
	s.keyOp[idx] = nil
}
