package txscript

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"sync"
)

func removeSig(slice [][]byte, s int) [][]byte {
	return append(slice[:s], slice[s+1:]...)
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

// SignatureInfo captures state about the transaction signature
// ie, it's hashType and signature.
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
	sync.RWMutex
	ops        []*signOpCode
	verifyData *txVerifyData
	pcToIdx    map[int]int
	nextIdx    int
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

// add associates a signOpCode with a particular script offset.
func (c *SignOpCache) add(scriptOff int, state *signOpCode) {
	c.Lock()
	defer c.Unlock()

	c.ops = append(c.ops, state)
	c.pcToIdx[scriptOff] = c.nextIdx
	c.nextIdx++
}

// getIdx returns the checkSigState for the idx'th signature
// operation that was pushed into the cache.
func (c *SignOpCache) getIdx(idx int) (*signOpCode, error) {
	c.RLock()
	defer c.RUnlock()

	if idx < 0 || idx > len(c.ops) {
		return nil, fmt.Errorf("no signature operation at idx %d, max is %d", idx, len(c.ops))
	}

	return c.ops[idx], nil
}

// IsComplete returns whether the path up to idx, and idx itself
// are fully complete, by return two boolean return values. It's
// third return value is set only if `idx` is out of range.
// For the path to complete, ops[0->idx-1] must be complete.
// For the index to be complete, the path and the final op must
// be complete.
func (c *SignOpCache) IsComplete(idx int) (bool, bool, error) {
	c.RLock()
	defer c.RUnlock()

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

// getSignOps returns a map of keyIdx => publicKeyInfo, and keyIdx => signatureInfo,
// where the signatures were successfully validated in the script. All public
// keys will be returned, so an association between signature & validating public
// key is maintained.
func (c *SignOpCache) getSignOps(complete bool, idx int) (map[int]*PublicKeyInfo, map[int]*SignatureInfo, error) {
	c.RLock()
	defer c.RUnlock()

	op, err := c.getIdx(idx)
	if err != nil {
		return nil, nil, err
	}

	var sigs map[int]*SignatureInfo
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
		keyBytes := op.uncheckedKeys[i]

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

// GetObservedHashTypes returns the hashtypes observed for operation `idx`
// or an error if the operation does not exist
func (c *SignOpCache) GetObservedHashTypes(idx int) ([]SigHashType, error) {
	c.RLock()
	defer c.RUnlock()

	op, err := c.getIdx(idx)
	if err != nil {
		return nil, err
	}

	return op.GetObservedHashTypes(), nil
}

// GetSigHash returns the sighash for operation idx, if the provided hashType
// was actually used during the operation. Otherwise it will return an error.
func (c *SignOpCache) GetSigHash(idx int, hashType SigHashType) ([]byte, error) {
	c.RLock()
	defer c.RUnlock()

	op, err := c.getIdx(idx)
	if err != nil {
		return nil, err
	}

	hash := op.GetCachedSigHash(hashType)
	if hash == nil {
		return nil, fmt.Errorf("Operation %d did not have the %d sigHash cached", idx, hashType)
	}

	return hash, nil
}

// GetSignOps returns the maps of public key and signature information
// (for signature operation idx) using the completed signature data.
func (c *SignOpCache) GetSignOps(idx int) (map[int]*PublicKeyInfo, map[int]*SignatureInfo, error) {
	return c.getSignOps(true, idx)
}

// GetIncompleteOps returns the maps of public key and signature information
// (for signature operation idx) using uncheckedKeys & uncheckedSigs.
// It will repeatedly attempt ECDSA validation to build the results.
func (c *SignOpCache) GetIncompleteOps(idx int) (map[int]*PublicKeyInfo, map[int]*SignatureInfo, error) {
	return c.getSignOps(false, idx)
}

// GetNumOps returns the number of signature operations for which
// it has data.
func (c *SignOpCache) GetNumOps() int {
	c.RLock()
	defer c.RUnlock()

	return len(c.ops)
}

type signOpCode struct {
	sync.RWMutex
	opcode        int
	rawScript     []parsedOpcode
	signScript    []parsedOpcode
	hashMap       map[SigHashType][]byte
	keys          []*btcec.PublicKey
	uncheckedKeys [][]byte
	uncheckedSigs [][]byte
	keyOp         map[int]*signOp
}

type signOp struct {
	hashType SigHashType
	sig      *btcec.Signature
	pubKey   *btcec.PublicKey
}

// InitCheckSig initializes the operation for an op CHECKSIG/CHECKSIGVERIFY
// operation
func (s *signOpCode) InitCheckSig(opcode int, pops []parsedOpcode) error {
	s.Lock()
	defer s.Unlock()

	if opcode != OP_CHECKSIG && opcode != OP_CHECKSIGVERIFY {
		return fmt.Errorf("Invalid opcode for signop: %d", opcode)
	}

	s.opcode = opcode
	s.rawScript = pops
	s.keys = make([]*btcec.PublicKey, 0, 1)
	s.keyOp = make(map[int]*signOp, 1)
	s.hashMap = make(map[SigHashType][]byte, 1)

	return nil
}

// InitCheckMultiSig initializes the operation for an op CHECKMULTISIG/
// CHECKMULTISIGVERIFY operation. It is initialized with the maximum
// number of keys/keyOps
func (s *signOpCode) InitCheckMultiSig(opcode int, pops []parsedOpcode) error {
	s.Lock()
	defer s.Unlock()

	if opcode != OP_CHECKMULTISIG && opcode != OP_CHECKMULTISIGVERIFY {
		return fmt.Errorf("Invalid opcode for signop: %d", opcode)
	}

	s.opcode = opcode
	s.rawScript = pops
	s.keys = make([]*btcec.PublicKey, 0, MaxPubKeysPerMultiSig)
	s.keyOp = make(map[int]*signOp, MaxPubKeysPerMultiSig)
	s.hashMap = make(map[SigHashType][]byte, 6)

	return nil
}

// SigCount returns the number of signing operations observed
// during the opcodes execution
func (s *signOpCode) SigCount() int {
	s.RLock()
	defer s.RUnlock()

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
	s.RLock()
	defer s.RUnlock()

	return s.SigCount() == len(s.uncheckedSigs)
}

// Sigs returns a map of pubKeyIdx => signature. It requires
// that the script successfully executed.
func (s *signOpCode) Sigs() (map[int]*SignatureInfo, error) {
	s.RLock()
	defer s.RUnlock()

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
	s.RLock()
	defer s.RUnlock()

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

		for i := 0; i < len(sigs); i++ {
			rawSig := sigs[i]
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
				continue
			}

			var shash = s.GetCachedSigHash(hashType)
			if shash == nil {
				//Generate the signature hash based on the signature hash type.
				if data.sigVersion == 1 {
					sigHashes := NewTxSigHashes(data.tx)

					shash = calcWitnessSignatureHash(subscript, sigHashes, hashType,
						data.tx, data.txIdx, data.inputAmount)
				} else {
					shash = calcSignatureHash(subscript, hashType, data.tx, data.txIdx)
				}
			}

			valid := parsedSig.Verify(shash, parsedPubKey)

			if valid {
				sigs = removeSig(sigs, i)
				signatures[numKeys-1-k] = &SignatureInfo{hashType, parsedSig}
				continue
			}
		}
	}

	return signatures, nil
}

// GetCachedSigHash returns the signature hash cached for hashType
// if it is known, otherwise the function returns nil.
func (s *signOpCode) GetCachedSigHash(hashType SigHashType) []byte {
	s.RLock()
	defer s.RUnlock()
	if _, ok := s.hashMap[hashType]; ok {
		return s.hashMap[hashType]
	}
	return nil
}

// GetObservedHashTypes returns the hashTypes requested
// during the execution of the opcode. For a CHECKSIG opcode
// this will only have one value, however a MULTISIG opcodes
// can have several
func (s *signOpCode) GetObservedHashTypes() []SigHashType {
	s.RLock()
	defer s.RUnlock()
	hashTypes := make([]SigHashType, len(s.hashMap))
	i := 0
	for hashType := range s.hashMap {
		hashTypes[i] = hashType
		i++
	}
	return hashTypes
}

// stackKey appends the key to the uncheckedKeys list. This
// is done for each key belonging to the opcode as it is read
// from the stack.
func (s *signOpCode) stackKey(key []byte) {
	s.Lock()
	defer s.Unlock()
	s.uncheckedKeys = append(s.uncheckedKeys, key)
}

// stackSignature appends the signature to the uncheckedSigs list.
// This is done for each 'signature' in case recovery is required.
func (s *signOpCode) stackSignature(sig []byte) {
	s.Lock()
	defer s.Unlock()
	s.uncheckedSigs = append(s.uncheckedSigs, sig)
}

// hashScript is used to set the subscript passed to the signature
// hash generation function. This is only done when the subscript
// is ready, ie, FindAndDelete was called.
func (s *signOpCode) hashScript(subscript []parsedOpcode) {
	s.Lock()
	defer s.Unlock()
	s.signScript = subscript
}

// signature caches the sigHash for this signOp, updates the
// list of keys and key operations.
func (s *signOpCode) signature(hash []byte, op *signOp) {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.hashMap[op.hashType]; !ok {
		s.hashMap[op.hashType] = hash
	}

	s.keys = append(s.keys, op.pubKey)
	idx := len(s.keys) - 1
	s.keyOp[idx] = op
}

// skipKey is called when a public key failed verification, allowing
// other valid signatures to be added to the key operations.
func (s *signOpCode) skipKey(key *btcec.PublicKey) {
	s.keys = append(s.keys, key)
	idx := len(s.keys) - 1
	s.keyOp[idx] = nil
}
