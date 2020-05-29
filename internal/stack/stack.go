package stack

// Stack is a stack of XML namespace declarations.
type Stack []map[string]string

// Push pushes a set of names and their corresponding URIs to the top of the
// stack.
func (s *Stack) Push(names map[string]string) {
	*s = append(*s, names)
}

// Pop pops the top of the name stack.
func (s *Stack) Pop() {
	*s = (*s)[:len(*s)-1]
}

// Len returns depth of the stack.
func (s *Stack) Len() int {
	return len(*s)
}

// Get fetches the URI for a name, or the empty string if one is not found.
// Definitions closer to the top of the stack take predence over values further
// from the top.
func (s *Stack) Get(k string) string {
	for i := len(*s) - 1; i >= 0; i-- {
		if v, ok := (*s)[i][k]; ok {
			return v
		}
	}

	return ""
}
