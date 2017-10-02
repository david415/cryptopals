package main

import (
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHammingDistance(t *testing.T) {
	require := require.New(t)

	a := "this is a test"
	b := "wokka wokka!!!"
	distance := hammingDistance([]byte(a), []byte(b))
	require.Equal(distance, 37, "fail")
}

func combineBlocks(blocks [][]byte) []byte {
	out := []byte{}
	for _, block := range blocks {
		out = append(out, block...)
	}
	return out
}

func TestGetBlocks(t *testing.T) {
	require := require.New(t)

	b, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic(err)
	}
	ciphertext1, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		panic(err)
	}
	blocks := getBlocks(ciphertext1, 5)
	ciphertext2 := combineBlocks(blocks)
	require.Equal(ciphertext1, ciphertext2, "fail")
}

func TestEnglishScore(t *testing.T) {
	require := require.New(t)

	plaintext, err := ioutil.ReadFile("1984.txt")
	if err != nil {
		panic(err)
	}

	blockSize := 7
	blocks := getBlocks(plaintext, blockSize)
	transposed := transposeBlocks(blocks)
	for _, b := range transposed {
		score := englishScore(string(b))
		require.NotEqual(score, 0, "fail")
		t.Logf("block size is %d\n", len(b))
		//t.Logf("scored %v of string %s\n", score, string(b))
	}
}
