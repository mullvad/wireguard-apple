package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test functions for maintaining handle mappings
func TestHandleInsertion(t *testing.T) {
	handles := make(map[int32]string)

	h1 := insertHandle(handles, "foo")
	assert.Equal(t, len(handles), 1)
	h2 := insertHandle(handles, "bar")
	assert.Equal(t, len(handles), 2)
	assert.Equal(t, handles[h1], "foo")
	assert.Equal(t, handles[h2], "bar")
	delete(handles, h2)
	_, ok := handles[h2]
	assert.False(t, ok)
}
