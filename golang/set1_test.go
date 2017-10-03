package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/david415/cryptopals/golang/ecb"
	"github.com/david415/cryptopals/golang/utils"
	"github.com/stretchr/testify/require"
)

// TestChallenge1 is my solution to https://cryptopals.com/sets/1/challenges/1
func TestChallenge1(t *testing.T) {
	require := require.New(t)

	str := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	str2 := base64.StdEncoding.EncodeToString(b)
	require.Equal(str2, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	t.Log(str2)
}

// TestChallenge2 is my solution to https://cryptopals.com/sets/1/challenges/2
func TestChallenge2(t *testing.T) {
	require := require.New(t)

	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	input1Bytes, err := hex.DecodeString(input1)
	if err != nil {
		panic(err)
	}
	input2Bytes, err := hex.DecodeString(input2)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(input1Bytes))
	utils.XorBytes(out, input1Bytes, input2Bytes)
	hexOut := fmt.Sprintf("%x", out)
	t.Log(hexOut)
	require.Equal(hexOut, "746865206b696420646f6e277420706c6179")
}

// TestChallenge3 is my solution to https://cryptopals.com/sets/1/challenges/3
func TestChallenge3(t *testing.T) {
	require := require.New(t)

	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	score, key := utils.GetSingleXorScore(inputBytes)
	plaintext := make([]byte, len(inputBytes))
	utils.XorWithOne(plaintext, inputBytes, key)
	t.Logf("score %d key %c", score, key)
	t.Logf("plaintext:%s", plaintext)
	require.Equal("Cooking MC's like a pound of bacon", string(plaintext), "wtf")
}

// TestChallenge4 is my solution to https://cryptopals.com/sets/1/challenges/4
func TestChallenge4(t *testing.T) {
	require := require.New(t)

	fh, err := os.Open("vectors/4.txt")
	require.NoError(err, "wtf")
	reader := bufio.NewReader(fh)
	highScore := 0
	plaintext := []byte{}
	for {
		line, err := reader.ReadString(byte('\n'))
		if err != nil {
			break
		}
		truncatedLine := line[:len(line)-1]
		inputBytes, err := hex.DecodeString(truncatedLine)
		require.NoError(err, "wtf")
		score, key := utils.GetSingleXorScore(inputBytes)
		if score != 0 {
			out := make([]byte, len(inputBytes))
			utils.XorWithOne(out, inputBytes, key)
			if score > highScore {
				highScore = score
				plaintext = out
			}
		}
	}
	t.Logf("score %d plaintext:%s", highScore, string(plaintext))
	ifIce := strings.Contains(string(plaintext), "party")
	require.Equal(true, ifIce, "wtf")
}

// TestChallenge5 is my solution to https://cryptopals.com/sets/1/challenges/5
func TestChallenge5(t *testing.T) {
	require := require.New(t)

	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	output := utils.RepeatXor([]byte(key), []byte(input))
	hexVector := fmt.Sprintf("%x", output)
	require.Equal("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", hexVector, "wtf")
}

// TestChallenge6 is my solution to https://cryptopals.com/sets/1/challenges/6
func TestChallenge6(t *testing.T) {
	require := require.New(t)

	b, err := ioutil.ReadFile("vectors/6.txt")
	require.NoError(err, "wtf")
	ciphertext, err := base64.StdEncoding.DecodeString(string(b))
	require.NoError(err, "wtf")
	keySize := utils.EstimateKeySize(ciphertext)
	blocks := utils.GetBlocks(ciphertext, keySize)
	transposed := utils.TransposeBlocks(blocks)
	key := []byte{}
	for _, b := range transposed {
		_, singleKey := utils.GetSingleXorScore(b)
		key = append(key, singleKey)
	}
	plaintext := utils.RepeatXor(key, ciphertext)
	t.Log(string(plaintext))
	ifIce := strings.Contains(string(plaintext), "Let the witch doctor")
	require.Equal(true, ifIce, "wtf")
}

// TestChallenge7 is my solution to https://cryptopals.com/sets/1/challenges/7
func TestChallenge7(t *testing.T) {
	require := require.New(t)

	b, err := ioutil.ReadFile("vectors/7.txt")
	require.NoError(err, "wtf")
	ciphertext, err := base64.StdEncoding.DecodeString(string(b))
	require.NoError(err, "wtf")
	key := "YELLOW SUBMARINE"
	output, err := ecb.ECBDecrypt(ciphertext, []byte(key))
	require.NoError(err, "wtf")
	t.Log(string(output))
	require.True(strings.Contains(string(output), "funky music"), "wtf")
}

// TestChallenge8 is my solution to https://cryptopals.com/sets/1/challenges/8
func TestChallenge8(t *testing.T) {
	require := require.New(t)

	blockSize := 16
	fh, err := os.Open("vectors/8.txt")
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(fh)
	hasDupBlocks := false
	for {
		blockMap := make(map[[16]byte]bool)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		truncatedLine := line[:len(line)-1]
		rawBytes, err := hex.DecodeString(truncatedLine)
		if err != nil {
			panic(err)
		}
		blocks := utils.GetBlocks(rawBytes, blockSize)
		for _, block := range blocks {
			blockArr := [16]byte{}
			copy(blockArr[:], block)
			_, ok := blockMap[blockArr]
			if ok {
				hasDupBlocks = true
				fmt.Println("duplicate blocks detected!")
			} else {
				blockMap[blockArr] = true
			}
		}
	}
	require.True(hasDupBlocks, "wtf")
}
