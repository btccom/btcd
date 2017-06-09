package txscript

import "fmt"

func isExecuting(condStack []bool) bool {
	ret := 0
	for i := 0; i < len(condStack); i++ {
		if condStack[i] == false {
			ret++
		}
	}
	return ret == 0
}

type branchTrace struct {
	opcodes []parsedOpcode
	current []parsedOpcode
	segments []byte
}

func (bt *branchTrace) init(maxSize int) {
	bt.opcodes = make([]parsedOpcode, 0, maxSize);
	bt.current = make([]parsedOpcode, 0)
	bt.segments = make([]byte, 0)
}
func (bt *branchTrace) nextSegment() error {
	if len(bt.current) > 0 {
		segment, err := unparseScript(bt.current)
		if err != nil {
			return err
		}

		bt.segments = append(bt.segments, segment...)
		bt.current = make([]parsedOpcode, 0)
	}
	return nil
}
func (bt *branchTrace) opcode(pop parsedOpcode) {
	if pop.isConditional() {
		if len(bt.current) > 0 {
			bt.nextSegment()
		}
		bt.current = append(bt.current, pop)
		bt.nextSegment()
	} else {
		bt.current = append(bt.current, pop)
	}
}
func (bt *branchTrace) end() []byte {
	bt.nextSegment()
	return bt.segments
}

func EvalScriptBranch(vfInput []bool, script []byte) ([]byte, error) {
	pops, err := parseScript(script);
	if err != nil {
		return nil, err
	}

	vfStack := make([]bool, 0)
	nOpCount := 0
	trace := &branchTrace{}
	trace.init(len(pops))

	var pop parsedOpcode

	for i := 0; i < len(pops); i++ {
		fExec := isExecuting(vfStack)

		pop = pops[i]
		opcode := int(pop.opcode.value)

		if (opcode > OP_16) {
			nOpCount += 1
		 	if (nOpCount > MaxOpsPerScript) {
				err := fmt.Errorf("exceeded max operation limit of %d",
					MaxOpsPerScript)
				return nil, err
			}
		}

		if (pop.isDisabled()) {
			err := fmt.Errorf("attempt to execute disabled opcode %s",
				pop.opcode.name)
			return nil, err
		}

		if OP_IF <= opcode && opcode <= OP_ENDIF {
			switch (opcode) {
			case OP_IF, OP_NOTIF:
				fValue := false
				if fExec {
					if len(vfInput) < 1 {
						err := fmt.Errorf("encountered opcode %s with no matching "+
							"opcode to begin conditional execution", pop.opcode.name)
						return nil, err
					}
					fValue = vfInput[len(vfInput) - 1]
					if opcode == OP_NOTIF {
						fValue = !fValue
					} else {
					}
					sz := int32(len(vfInput))
					vfInput = vfInput[:sz-1]
				}
				vfStack = append(vfStack, fValue)
			case OP_ELSE:
				if len(vfStack) < 1 {
					err := fmt.Errorf("encountered opcode %s with no matching "+
						"opcode to begin conditional execution", pop.opcode.name)
					return nil, err
				}
				sz := int32(len(vfStack))
				vfStack[sz - 1] = !vfStack[sz - 1]
			case OP_ENDIF:
				if len(vfStack) < 1 {
					err := fmt.Errorf("encountered opcode %s with no matching "+
						"opcode to begin conditional execution", pop.opcode.name)
					return nil, err
				}
				sz := int32(len(vfStack))
				vfStack = vfStack[:sz-1]
			}
			trace.opcode(pop)
		} else if fExec {
			trace.opcode(pop)
		}
	}

	if len(vfStack) > 0 {
		err := fmt.Errorf("unbalanced conditional at end of script")
		return nil, err
	}

	if len(vfInput) > 0 {
		err := fmt.Errorf("unexpected value remaining on input stack")
		return nil, err
	}

	scriptBranch := trace.end()
	return scriptBranch, nil
}