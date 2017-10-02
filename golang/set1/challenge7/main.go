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

func ecbDecrypt(input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := getBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	for _, block := range blocks {
		dst := make([]byte, len(key))
		cipher.Decrypt(dst, block)
		output = append(output, dst...)
	}
	return output, nil
}

func main() {
	b, err := ioutil.ReadFile("7.txt")
	if err != nil {
		panic(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		panic(err)
	}
	key := "YELLOW SUBMARINE"
	output, err := ecbDecrypt(ciphertext, []byte(key))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(output))
}
