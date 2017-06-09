package txscript

import (
	"testing"
	"fmt"
	"encoding/hex"
	"bytes"
)

type scriptBranchFixture struct {
	rawScript []byte
	redeemPaths [][]bool
	redeemBranch [][]byte
}

func getMultisigFixture() (*scriptBranchFixture, error) {
	// This fixture has 0 degrees of freedom as far as logical
	// opcodes are concerned, so the only possible pathway
	// is the entire script

	scriptStr := "5221028a3ed3051bc723fc7d6168c2d30ec4e409a2e3e390a17828348b4245f15539272103717ffcf3846543f3dc23f61e8f8267cf67b7d89f204cf9e536642954739ecc6b2103be2f90feaf8060c97542acbe6769f3c6703633515afa37976b37d51314e1ea2f53ae"
	s, err := hex.DecodeString(scriptStr)
	if err != nil {
		return nil, err
	}

	redeemPaths := [][]bool{{}}
	branchStr := []string{scriptStr}

	branches := make([][]byte, len(branchStr))
	for i := 0; i < len(branchStr); i++ {
		var err error
		branches[i], err = hex.DecodeString(branchStr[i])
		if err != nil {
			return nil, err
		}
	}

	return &scriptBranchFixture{
		rawScript: s,
		redeemPaths: redeemPaths,
		redeemBranch: branches,
	}, nil
}

func getHashLockConditionalScript() (*scriptBranchFixture, error) {
	// Derived from https://github.com/bitcoin/bips/blob/master/bip-0114.mediawiki#hashed-time-lock-contract
	// This script has three degrees of freedom:
	// 1) Alice signs
	// 2) Bob lacks the revocation value, so uses CLTV before signing
	// 3) Bob has the revocation value, so can sign without timeout.

	s, err := hex.DecodeString("a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c876303805101b26d2103846c3da5ae467f9c6e6ea9195da13c95016826ab173086b04e30f6cc96b8481d671466a87e9821c983c50bdc8b5be90e7feb35aa46af87640122b17568210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e1694768ac")
	if err != nil {
		return nil, err
	}

	redeemPaths := [][]bool{
		{true},
		{true,false},
		{false,false},
	}

	branchStr := []string{
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c876303805101b26d2103846c3da5ae467f9c6e6ea9195da13c95016826ab173086b04e30f6cc96b8481d67646868ac",
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c8763671466a87e9821c983c50bdc8b5be90e7feb35aa46af876468210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e1694768ac",
		"a976149ec83aca9c5c4b41ff2bbed4b70615502fe28e6c8763671466a87e9821c983c50bdc8b5be90e7feb35aa46af87640122b17568210374586816d201ee6b5a0df3dc2216375cff348a65e447d1ec83dd6aad98e1694768ac",
	}

	branches := make([][]byte, len(branchStr))
	for i := 0; i < len(branchStr); i++ {
		var err error
		branches[i], err = hex.DecodeString(branchStr[i])
		if err != nil {
			return nil, err
		}
	}

	return &scriptBranchFixture{
		rawScript: s,
		redeemPaths: redeemPaths,
		redeemBranch: branches,
	}, nil
}

func getHashlock() (*scriptBranchFixture, error) {
	// Derived from https://github.com/bitcoin/bips/blob/master/bip-0114.mediawiki#hashed-time-lock-contract
	// This script has two possible redeem pathways
	// 1) Alice has the reveal value and signs
	// 2) Bob lacks the reveal

	s, err := hex.DecodeString("a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f268763210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986704ca0a6259b1752102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee568ac")
	if err != nil {
		return nil, err
	}

	redeemPaths := [][]bool{
		{true},
		{false},
	}

	branchStr := []string{
		"a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f268763210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986768ac",
		"a8208b783f47c7626ddcb571c7f2c2c948f30d0ee5bc7b8de0b870d0210df9ce9f2687636704ca0a6259b1752102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee568ac",
	}

	branches := make([][]byte, len(branchStr))
	for i := 0; i < len(branchStr); i++ {
		var err error
		branches[i], err = hex.DecodeString(branchStr[i])
		if err != nil {
			return nil, err
		}
	}

	return &scriptBranchFixture{
		rawScript: s,
		redeemPaths: redeemPaths,
		redeemBranch: branches,
	}, nil
}

func tstEvalScriptBranch(t *testing.T, idx int, fixture *scriptBranchFixture) {

	branch1, err := EvalScriptBranch(fixture.redeemPaths[idx], fixture.rawScript)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(branch1, fixture.redeemBranch[idx]) {
		t.Error(fmt.Errorf("Produced wrong exclusive branch for test\n(actual)   %s\n != \n(expected) %s", hex.EncodeToString(branch1), hex.EncodeToString(fixture.redeemBranch[idx])))
		return
	}
}

func TestEvalScriptBranch(t *testing.T) {
	fixtures := make([]*scriptBranchFixture, 0)
	fixture1, err := getHashLockConditionalScript()
	if err != nil {
		t.Errorf("invalid fixture: %s", err)
		return;
	}

	fixture2, err := getMultisigFixture()
	if err != nil {
		t.Errorf("invalid fixture: %s", err)
		return;
	}

	fixture3, err := getHashlock()
	if err != nil {
		t.Errorf("invalid fixture: %s", err)
		return;
	}

	fixtures = append(fixtures, fixture1)
	fixtures = append(fixtures, fixture2)
	fixtures = append(fixtures, fixture3)

	for i := 0; i < len(fixtures); i++ {
		for j := 0; j < len(fixtures[i].redeemPaths); j++ {
			description := fmt.Sprintf("EvalScriptCase fixture %d, pathway %d", i, j)
			t.Run(description, func (t *testing.T) {
				tstEvalScriptBranch(t, j, fixtures[i])
			})
		}
	}
}
