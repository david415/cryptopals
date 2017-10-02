package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

func getBlocks(ciphertext []byte, blockSize int) [][]byte {
	blocks := [][]byte{}
	for i := 0; i < len(ciphertext); i += blockSize {
		if i+blockSize > len(ciphertext) {
			blocks = append(blocks, ciphertext[i:])
		} else {
			blocks = append(blocks, ciphertext[i:i+blockSize])
		}
	}
	return blocks
}

func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

func cbcDecrypt(iv []byte, input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := getBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	prevBlock := iv
	currentBlock := make([]byte, len(key))
	for _, block := range blocks {
		cipher.Decrypt(currentBlock, block)
		xorBlock := make([]byte, len(key))
		xorBytes(xorBlock, prevBlock, currentBlock)
		prevBlock = block
		output = append(output, xorBlock...)
	}
	return output, nil
}

func cbcEncrypt(iv []byte, input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := getBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	prevBlock := iv
	ciphertextBlock := make([]byte, len(key))
	for _, block := range blocks {
		xorBlock := make([]byte, len(key))
		xorBytes(xorBlock, block, prevBlock)
		cipher.Encrypt(ciphertextBlock, xorBlock)
		prevBlock = ciphertextBlock
		output = append(output, ciphertextBlock...)
	}
	return output, nil
}

func main() {
	b, err := ioutil.ReadFile("10.txt")
	if err != nil {
		panic(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		panic(err)
	}
	key := "YELLOW SUBMARINE"
	iv := [16]byte{}
	output, err := cbcDecrypt(iv[:], ciphertext, []byte(key))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(output))
}
