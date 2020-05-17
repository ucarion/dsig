package stack

type Stack []map[string]string

func (s *Stack) Push(names map[string]string) {
	*s = append(*s, names)
}

func (s *Stack) Pop() {
	*s = (*s)[:len(*s)-1]
}

func (s *Stack) Len() int {
	return len(*s)
}

func (s *Stack) Get(k string) string {
	for i := len(*s) - 1; i >= 0; i-- {
		if v, ok := (*s)[i][k]; ok {
			return v
		}
	}

	return ""
}
