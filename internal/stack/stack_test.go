package stack_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/dsig/internal/stack"
)

func TestStack(t *testing.T) {
	var s stack.Stack
	assert.Equal(t, "", s.Get("foo"))
	assert.Equal(t, 0, s.Len())

	s.Push(map[string]string{"foo": "bar"})
	assert.Equal(t, "bar", s.Get("foo"))
	assert.Equal(t, 1, s.Len())

	s.Push(map[string]string{"foo": "baz"})
	assert.Equal(t, "baz", s.Get("foo"))
	assert.Equal(t, 2, s.Len())

	s.Pop()
	assert.Equal(t, "bar", s.Get("foo"))
	assert.Equal(t, 1, s.Len())

	s.Pop()
	assert.Equal(t, "", s.Get("foo"))
	assert.Equal(t, 0, s.Len())
}
