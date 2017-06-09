package txscript

import (
	"fmt"
)

// GetBranchAst produces a list of booleans describing
// the path of script execution over a sequence of logical
// operators. This can then be used to by EvalScriptBranch
// to control execution flow and determine a branches
// mututally exclusive opcodes.
func GetBranchAst(script []byte) ([][]bool, error) {
	pops, err := parseScript(script)
	if err != nil {
		return nil, err
	}

	current := &astNode{parent: nil}
	var opcode int
	for i := 0; i < len(pops); i++ {
		opcode = int(pops[i].opcode.value)
		switch opcode {
		case OP_IF, OP_NOTIF:
			left, right, err := current.split()
			if err != nil {
				return nil, err
			}

			if opcode == OP_IF {
				current = right
			} else {
				current = left
			}
		case OP_ELSE:
			if current.depth() < 1 {
				return nil, fmt.Errorf("Unexpected OP_ENDIF")
			}
			if current.value {
				current = current.parent.left
			} else {
				current = current.parent.right
			}
		case OP_ENDIF:
			if current.depth() < 1 {
				return nil, fmt.Errorf("Unexpected OP_ENDIF")
			}
			current = current.parent
		}
	}

	desc, err := current.descriptors()
	if err != nil {
		return nil, err
	}

	return desc, nil
}

// astNode represents a node in the sequence of logical
// operations
type astNode struct {
	parent *astNode
	value  bool
	left   *astNode
	right  *astNode
}

// depth returns the nesting level of this node
func (a *astNode) depth() int {
	ctr := 0
	for ptr := a; ptr != nil; ptr = ptr.parent {
		ctr += 1
	}
	return ctr
}

// returns whether the node has children
func (a *astNode) hasChildren() bool {
	return a.left != nil || a.right != nil
}

// split forks creates a new level descending from this node,
// returning both the newly created children. Returns an error
// if the node was already split.
func (a *astNode) split() (*astNode, *astNode, error) {
	if a.hasChildren() {
		return nil, nil, fmt.Errorf("Node was already split - shouldn't do this twice")
	}

	a.left = &astNode{parent: a, value: false}
	a.right = &astNode{parent: a, value: true}

	return a.left, a.right, nil
}

// descriptors traverses the tree and returns all the
// possible 'paths' for script branches, ie, returns
// the values which control EvalScriptBranch
func (a *astNode) descriptors() ([][]bool, error) {
	var values [][]bool
	if a.hasChildren() {
		values = make([][]bool, 0)
		children := make([]*astNode, 2)
		children[0] = a.left
		children[1] = a.right
		for i := 0; i < len(children); i++ {
			child := children[i]
			childDesc, err := child.descriptors()
			if err != nil {
				return nil, err
			}

			for j := 0; j < len(childDesc); j++ {
				var lot []bool
				if a.parent == nil {
					lot = make([]bool, 0)
				} else {
					lot = make([]bool, 1)
					lot[0] = a.value
				}

				lot = append(lot, childDesc[j]...)
				values = append(values, lot)
			}
		}
	} else {
		values = make([][]bool, 1)
		if a.parent == nil {
			// parent with no children, so 0 degrees of freedom
			values[0] = make([]bool, 0)
		} else {
			// tip
			values[0] = make([]bool, 1)
			values[0][0] = a.value
		}
	}

	return values, nil
}

// reverseBools reverses of a slice of booleans. used to convert
// from e
func reverseBools(bools []bool) []bool {
	for i, j := 0, len(bools)-1; i < j; i, j = i+1, j-1 {
		bools[i], bools[j] = bools[j], bools[i]
	}
	return bools
}

func isExecuting(condStack []bool) bool {
	ret := 0
	for i := 0; i < len(condStack); i++ {
		if !condStack[i] {
			ret++
		}
	}
	return ret == 0
}

// EvalScriptBranch takes a candidate vfInput to control execution flow
// and returns a list of mutually exclusive opcodes for that branch.
func EvalScriptBranch(vfInput []bool, script []byte) ([]byte, error) {
	vfInput = reverseBools(vfInput)
	pops, err := parseScript(script)
	if err != nil {
		return nil, err
	}

	vfStack := make([]bool, 0)
	nOpCount := 0
	trace := &branchTrace{}
	trace.init()

	var pop parsedOpcode

	for i := 0; i < len(pops); i++ {
		fExec := isExecuting(vfStack)

		pop = pops[i]
		opcode := int(pop.opcode.value)

		if opcode > OP_16 {
			nOpCount += 1
			if nOpCount > MaxOpsPerScript {
				err := fmt.Errorf("exceeded max operation limit of %d",
					MaxOpsPerScript)
				return nil, err
			}
		}

		if pop.isDisabled() {
			err := fmt.Errorf("attempt to execute disabled opcode %s",
				pop.opcode.name)
			return nil, err
		}

		if OP_IF <= opcode && opcode <= OP_ENDIF {
			switch opcode {
			case OP_IF, OP_NOTIF:
				fValue := false
				if fExec {
					if len(vfInput) < 1 {
						err := fmt.Errorf("encountered opcode %s with no matching "+
							"opcode to begin conditional execution", pop.opcode.name)
						return nil, err
					}
					fValue = vfInput[len(vfInput)-1]
					if opcode == OP_NOTIF {
						fValue = !fValue
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
				vfStack[sz-1] = !vfStack[sz-1]
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

// branchTrace is used to build up information about regions
// of the script that are executed. `current` builds up the
// opcodes run at the current level, and is appended to the
// accumulated script whenever the nexting level changes.
type branchTrace struct {
	current    []parsedOpcode
	scriptCode []byte
}

// init initializes a clean branchTrace
func (bt *branchTrace) init() {
	bt.current = make([]parsedOpcode, 0)
	bt.scriptCode = make([]byte, 0)
}

// nextSegment appends the current levels opcodes into the
// accumulated script
func (bt *branchTrace) nextSegment() error {
	if len(bt.current) > 0 {
		segment, err := unparseScript(bt.current)
		if err != nil {
			return err
		}

		bt.scriptCode = append(bt.scriptCode, segment...)
		bt.current = make([]parsedOpcode, 0)
	}
	return nil
}

// opcode takes a parsedOpcode and appends it to the current
// list. If it is conditional, we create a new segment before
// and after.
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

// end is called upon completion to append any outstanding 'current'
// opcodes to the script
func (bt *branchTrace) end() []byte {
	bt.nextSegment()
	return bt.scriptCode
}

// StripLogicalOpcodes removes all logical opcodes from a script.
// It should only be run on a branch trace, since it already has
// stripped the opcodes outside the branch we are considering exclusively.
func StripLogicalOpcodes(script []byte) ([]byte, error) {
	pops, err := parseScript(script)
	if err != nil {
		return nil, err
	}

	max := len(pops)
	result := make([]parsedOpcode, 0, max)
	for i := 0; i < max; i++ {
		if !pops[i].isConditional() {
			result = append(result, pops[i])
		}
	}

	stripped, err := unparseScript(result)
	if err != nil {
		return nil, err
	}

	return stripped, nil
}
