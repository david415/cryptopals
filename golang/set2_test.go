package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/david415/cryptopals/golang/cbc"
	"github.com/david415/cryptopals/golang/challenge11"
	"github.com/david415/cryptopals/golang/challenge12"
	"github.com/david415/cryptopals/golang/ecb"
	"github.com/david415/cryptopals/golang/utils"
	"github.com/stretchr/testify/require"
)

// TestChallenge9 is my solution to https://cryptopals.com/sets/2/challenges/9
func TestChallenge9(t *testing.T) {
	require := require.New(t)

	input := "YELLOW SUBMARINE"
	padded, err := utils.PKCS7Pad([]byte(input), 20)
	require.NoError(err, "wtf")
	t.Logf("padded: %x\n", padded)
	unpadded, err := utils.PKCS7Unpad([]byte(padded), 20)
	require.NoError(err, "wtf")
	require.True(bytes.Equal([]byte(input), unpadded), "wtf")
}

// TestChallenge10 is my solution to https://cryptopals.com/sets/2/challenges/10
func TestChallenge10(t *testing.T) {
	require := require.New(t)

	b, err := ioutil.ReadFile("vectors/10.txt")
	require.NoError(err, "wtf")
	ciphertext, err := base64.StdEncoding.DecodeString(string(b))
	require.NoError(err, "wtf")
	key := "YELLOW SUBMARINE"
	iv := [16]byte{}
	output, err := cbc.CBCDecrypt(iv[:], ciphertext, []byte(key))
	require.NoError(err, "wtf")
	t.Log(string(output))
	require.True(strings.Contains(string(output), "funky music"), "wtf")
}

// TestChallenge11 is my solution to https://cryptopals.com/sets/2/challenges/11
func TestChallenge11(t *testing.T) {
	require := require.New(t)

	plaintext := bytes.Repeat([]byte("A"), 1000)
	ciphertext, err := challenge11.EncryptOracle(plaintext)
	require.NoError(err, "wtf")
	if ecb.IsECB(ciphertext) {
		t.Log("ECB mode detected")
	} else {
		t.Log("ECB mode NOT detected")
	}
}

// TestChallenge12 is my solution to https://cryptopals.com/sets/2/challenges/12
func TestChallenge12(t *testing.T) {
	require := require.New(t)

	key := [16]byte{}
	_, err := rand.Reader.Read(key[:])
	require.NoError(err, "wtf")
	oracle, err := challenge12.NewECBOracle()
	require.NoError(err, "wtf")
	blockSize, err := oracle.FindBlockSize()
	require.NoError(err, "wtf")
	t.Logf("block size %d\n", blockSize)
	input := bytes.Repeat([]byte("A"), 32)
	output, err := oracle.Query(input)
	require.NoError(err, "wtf")
	require.True(ecb.IsECB(output), "wtf")
	t.Log("ECB detected")

	// get number of blocks in unknown ciphertext output
	input = []byte{}
	ciphertext, err := oracle.Query(input)
	require.NoError(err, "wtf")
	t.Logf("oracle ciphertext length is %d\n", len(ciphertext))
	blocks := utils.GetBlocks(ciphertext, blockSize)
	maxBlocks := len(blocks)
	t.Logf("%d ciphertext blocks\n", maxBlocks)

	// use oracle to decrypt unknown section of ciphertext
	plaintext, err := challenge12.BreakOracleString(maxBlocks, blockSize, oracle)
	require.NoError(err, "wtf")
	t.Log(string(plaintext))
	require.True(strings.Contains(string(plaintext), "I just drove by"), "wtf")
}

// TestChallenge13 is my solution to https://cryptopals.com/sets/2/challenges/13
// func TestChallenge13(t *testing.T) {
// 	require := require.New(t)

// 	require.True(true, "wtf")
// }
