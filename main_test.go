package main

import (
	"src/github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestExample(t *testing.T) {
	//Test example
	actual := strings.ToUpper("hello")
	expected := "HELLO"

	assert.Equal(t, expected, actual)
}
