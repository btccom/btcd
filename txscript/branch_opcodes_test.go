package txscript

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

type scriptBranchFixture struct {
	rawScript      []byte
	redeemPaths    [][]bool
	redeemBranch   [][]byte
	strippedBranch [][]byte
}

func mkFixture(scriptStr string, redeemPaths [][]bool, branchStr []string, strippedStr []string) (*scriptBranchFixture, error) {
	s, err := hex.DecodeString(scriptStr)
	if err != nil {
		return nil, err
	}

	nPaths := len(redeemPaths)
	if nPaths != len(branchStr) {
		return nil, fmt.Errorf("Branch count %d did not match path count %d", len(branchStr), nPaths)
	}
	if nPaths != len(strippedStr) {
		return nil, fmt.Errorf("Branch count %d did not match path count %d", len(branchStr), nPaths)
	}

	branches := make([][]byte, nPaths)
	stripped := make([][]byte, nPaths)
	for i := 0; i < nPaths; i++ {
		var err error
		branches[i], err = hex.DecodeString(branchStr[i])
		if err != nil {
			return nil, err
		}
		stripped[i], err = hex.DecodeString(strippedStr[i])
		if err != nil {
			return nil, err
		}
	}

	return &scriptBranchFixture{
		rawScript:      s,
		redeemPaths:    redeemPaths,
		redeemBranch:   branches,
		strippedBranch: stripped,
	}, nil
}

func getMultisigFixture() (*scriptBranchFixture, error) {
	// This fixture has 0 degrees of freedom as far as logical
	// opcodes are concerned, so the only possible pathway
	// is the entire script

	scriptStr := "5221028a3ed3051bc723fc7d6168c2d30ec4e409a2e3e390a17828348b4245f15539272103717ffcf3846543f3dc23f61e8f8267cf67b7d89f204cf9e536642954739ecc6b2103be2f90feaf8060c97542acbe6769f3c6703633515afa37976b37d51314e1ea2f53ae"
	redeemPaths := [][]bool{{}}
	branchStr := []string{scriptStr}
	strippedStr := []string{scriptStr}

	return mkFixture(scriptStr, redeemPaths, branchStr, strippedStr)
}

func getHashLockConditionalScript() (*scriptBranchFixture, error) {
	// Derived from https://github.com/bitcoin/bips/blob/master/bip-0114.mediawiki#hashed-time-lock-contract
	// 1) Alice signs
	// 2) Bob lacks the revocation value, so uses CLTV before signing
	// 3) Bob has the revocation value, so can sign without timeout.

	scriptStr := "a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c876303805101b26d2103846c3da5ae467f9c6e6ea9195da13c95016826ab173086b04e30f6cc96b8481d671466a87e9821c983c50bdc8b5be90e7feb35aa46af87640122b17568210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e1694768ac"
	redeemPaths := [][]bool{
		{true},
		{false, true},
		{false, false},
	}
	branchStr := []string{
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c876303805101b26d2103846c3da5ae467f9c6e6ea9195da13c95016826ab173086b04e30f6cc96b8481d67646868ac",
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c8763671466a87e9821c983c50bdc8b5be90e7feb35aa46af876468210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e1694768ac",
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c8763671466a87e9821c983c50bdc8b5be90e7feb35aa46af87640122b17568210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e1694768ac",
	}
	strippedStr := []string{
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c8703805101b26d2103846c3da5ae467f9c6e6ea9195da13c95016826ab173086b04e30f6cc96b8481dac",
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c871466a87e9821c983c50bdc8b5be90e7feb35aa46af87210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e16947ac",
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c871466a87e9821c983c50bdc8b5be90e7feb35aa46af870122b175210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e16947ac",
	}

	return mkFixture(scriptStr, redeemPaths, branchStr, strippedStr)
}

func getHashlock() (*scriptBranchFixture, error) {
	// https://gist.github.com/stevenroose/a305b89fe8767d769ca5d67ee52a8b93

	// Full Script
	// OP_SHA256 8b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f26 OP_EQUAL
	// OP_IF
	// 	 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	// OP_ELSE
	//   1499597514 OP_CHECKLOCKTIMEVERIFY OP_DROP
	//   02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
	// OP_ENDIF
	// OP_CHECKSIG

	// This script has two possible redeem pathways
	// 1) Bob can sign immediately with the reveal value
	// 2) Bob lacks the reveal, must wait 30 days

	// Branch str - expected output of EvalScriptBranch

	// OP_SHA256 8b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f26 OP_EQUAL
	// OP_IF
	// 	 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	// OP_ELSE
	// OP_ENDIF
	// OP_CHECKSIG

	// OP_SHA256 8b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f26 OP_EQUAL
	// OP_IF
	// OP_ELSE
	//   1499597514 OP_CHECKLOCKTIMEVERIFY OP_DROP
	//   02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
	// OP_ENDIF
	// OP_CHECKSIG

	// StripLogicalOpcodes - expected output

	// OP_SHA256 8b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f26 OP_EQUAL
	// 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	// OP_CHECKSIG

	// OP_SHA256 8b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f26 OP_EQUAL
	// 1499597514 OP_CHECKLOCKTIMEVERIFY OP_DROP
	// 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
	// OP_CHECKSIG
	scriptStr := "a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f268763210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986704ca0a6259b1752102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee568ac"
	redeemPaths := [][]bool{
		{true},
		{false},
	}
	branchStr := []string{
		"a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f268763210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986768ac",
		"a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f2687636704ca0a6259b1752102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee568ac",
	}
	strippedStr := []string{
		"a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f2687210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
		"a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f268704ca0a6259b1752102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
	}

	return mkFixture(scriptStr, redeemPaths, branchStr, strippedStr)
}

// test that we can reproduce the test fixtures logical AST
func tstGetScriptAst(t *testing.T, fixture *scriptBranchFixture) {
	ast, err := GetBranchAst(fixture.rawScript)
	if err != nil {
		t.Error(err)
		return
	}

	found := make(map[int]bool, len(ast))
	for j, desc := range fixture.redeemPaths {
		f := false
		for _, cmp := range ast {
			if len(cmp) == len(desc) {
				ok := true
				for i := 0; i < len(cmp); i++ {
					if cmp[i] != desc[i] {
						ok = false
					}
				}

				if ok {
					f = true
				}
			}
		}
		found[j] = f
	}

	for j, f := range found {
		if !f {
			t.Errorf("Did not find expected fixture in result %d %v", j, fixture.redeemPaths[j])
			return
		}
	}
}

func tstStripLogicalOpcodes(t *testing.T, script []byte, expectedScript []byte) {
	parsedExpectedScript, err := parseScript(expectedScript)
	if err != nil {
		t.Error(err)
		return
	}

	stripped, err := StripLogicalOpcodes(script)
	if err != nil {
		t.Error(err)
		return
	}

	parsedStripped, err := parseScript(stripped)
	if err != nil {
		t.Error(err)
		return
	}

	if len(parsedStripped) != len(parsedExpectedScript) {
		t.Errorf("Invalid count for stripped script, abort")
		return
	}

	for i := 0; i < len(parsedExpectedScript); i++ {
		if parsedExpectedScript[i].opcode != parsedStripped[i].opcode {
			t.Error("Stripped opcode did not match expected opcode at pos %d", i)
			return
		}
	}
}

// test we can produce the same branch as the test fixture
func tstEvalScriptBranch(t *testing.T, idx int, fixture *scriptBranchFixture) {

	script := fixture.rawScript
	path := fixture.redeemPaths[idx]
	branch := fixture.redeemBranch[idx]

	evaledBranch, err := EvalScriptBranch(path, script)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(evaledBranch, branch) {
		t.Error(fmt.Errorf("Produced wrong exclusive branch for test\n(actual)   %s\n != \n(expected) %s", hex.EncodeToString(evaledBranch), hex.EncodeToString(fixture.redeemBranch[idx])))
		return
	}

	_, err = StripLogicalOpcodes(evaledBranch)
	if err != nil {
		t.Error(err)
		return
	}

}

func TestEvalScriptBranch(t *testing.T) {
	fixtures := make([]*scriptBranchFixture, 0)
	fixture1, err := getHashLockConditionalScript()
	if err != nil {
		t.Errorf("invalid fixture: %s", err)
		return
	}

	fixture2, err := getMultisigFixture()
	if err != nil {
		t.Errorf("invalid fixture: %s", err)
		return
	}

	fixture3, err := getHashlock()
	if err != nil {
		t.Errorf("invalid fixture: %s", err)
		return
	}

	fixtures = append(fixtures, fixture1)
	fixtures = append(fixtures, fixture2)
	fixtures = append(fixtures, fixture3)

	for i := 0; i < len(fixtures); i++ {
		descriptionAst := fmt.Sprintf("GetScriptAst fixture %d", i)
		t.Run(descriptionAst, func(t *testing.T) {
			tstGetScriptAst(t, fixtures[i])
		})

		descriptionStrip := fmt.Sprintf("StripLogicalOpcode fixture %d", i)
		for j := 0; j < len(fixtures[i].redeemPaths); j++ {
			t.Run(descriptionStrip, func(t *testing.T) {
				tstStripLogicalOpcodes(t, fixtures[i].redeemBranch[j], fixtures[i].strippedBranch[j])
			})
		}

		for j := 0; j < len(fixtures[i].redeemPaths); j++ {
			description := fmt.Sprintf("EvalScriptCase fixture %d, pathway %d", i, j)
			t.Run(description, func(t *testing.T) {
				tstEvalScriptBranch(t, j, fixtures[i])
			})
		}
	}
}
