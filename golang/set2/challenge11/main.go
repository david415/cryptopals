package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

func pkcs7Pad(input []byte, blockSize int) ([]byte, error) {
	if blockSize >= 256 || blockSize <= 0 {
		return nil, errors.New("specified block size is invalid")
	}
	if len(input) > blockSize || len(input) == 0 {
		// XXX should we return an error if input is bigger than block size?
		return nil, errors.New("input block size is invalid")
	}
	padlen := 1
	for ((len(input) + padlen) % blockSize) != 0 {
		padlen = padlen + 1
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(input, pad...), nil
}

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
		if len(block) < 16 {
			block, err = pkcs7Pad(block, 16)
		}
		xorBlock := make([]byte, len(key))
		xorBytes(xorBlock, block, prevBlock)
		cipher.Encrypt(ciphertextBlock, xorBlock)
		prevBlock = ciphertextBlock
		output = append(output, ciphertextBlock...)
	}
	return output, nil
}

func ecbEncrypt(input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := getBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	for _, block := range blocks {
		dst := make([]byte, len(key))
		if len(block) < 16 {
			block, err = pkcs7Pad(block, 16)
		}
		cipher.Encrypt(dst, block)
		output = append(output, dst...)
	}
	return output, nil
}

func genRandMinMax(max, min int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func entropicEncrypt(input []byte) ([]byte, error) {
	key := [16]byte{}
	_, err := rand.Reader.Read(key[:])
	if err != nil {
		return nil, err
	}
	mode, err := rand.Int(rand.Reader, big.NewInt(int64(2)))
	if err != nil {
		return nil, err
	}
	output := []byte{}
	if mode.Int64() == int64(0) {
		output, err = ecbEncrypt(input, key[:])
		if err != nil {
			return nil, err
		}
	} else {
		iv := [16]byte{}
		_, err := rand.Reader.Read(iv[:])
		if err != nil {
			return nil, err
		}
		output, err = cbcEncrypt(iv[:], input, key[:])
		if err != nil {
			return nil, err
		}
	}
	prefixLen, err := genRandMinMax(10, 5)
	if err != nil {
		return nil, err
	}
	suffixLen, err := genRandMinMax(10, 5)
	if err != nil {
		return nil, err
	}
	output = append(bytes.Repeat([]byte("B"), prefixLen), output...)
	output = append(output, bytes.Repeat([]byte("B"), suffixLen)...)
	return output, nil
}

func isECB(input []byte) bool {
	blockMap := make(map[[16]byte]bool)
	blocks := getBlocks(input, 16)
	for _, block := range blocks {
		blockArr := [16]byte{}
		copy(blockArr[:], block)
		_, ok := blockMap[blockArr]
		if ok {
			return true
		} else {
			blockMap[blockArr] = true
		}
	}
	return false
}

func main() {
	plaintext := bytes.Repeat([]byte("A"), 1000)
	ciphertext, err := entropicEncrypt(plaintext)
	if err != nil {
		panic(err)
	}
	if isECB(ciphertext) {
		fmt.Println("ECB mode detected")
	} else {
		fmt.Println("ECB mode NOT detected")
	}
}
