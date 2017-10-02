package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

func genRandMinMax(max, min int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func pkcs7Pad(input []byte, blockSize int) ([]byte, error) {
	if blockSize >= 256 || blockSize <= 0 {
		return nil, errors.New("specified block size is invalid")
	}
	if len(input) >= blockSize || len(input) == 0 {
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
		if i+blockSize > len(ciphertext)-1 {
			blocks = append(blocks, ciphertext[i:])
		} else {
			blocks = append(blocks, ciphertext[i:i+blockSize])
		}
	}
	return blocks
}

type ECBOracle struct {
	blockSize int
	key       []byte
	cipher    cipher.Block
	Debug     bool
}

func NewECBOracle() (*ECBOracle, error) {
	key := [16]byte{}
	_, err := rand.Reader.Read(key[:])
	if err != nil {
		return nil, err
	}
	aesCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	o := ECBOracle{
		blockSize: 16,
		key:       key[:],
		cipher:    aesCipher,
		Debug:     false,
	}
	return &o, nil
}

func (o *ECBOracle) encrypt(input []byte) ([]byte, error) {
	output := []byte{}
	blocks := getBlocks(input, o.blockSize)
	for i := 0; i < len(blocks); i++ {

		if i == len(blocks)-1 {
			// always apply padding to the last block
			if len(blocks[i]) < o.blockSize {
				padded, err := pkcs7Pad(blocks[i], o.blockSize)
				if err != nil {
					return nil, err
				}
				dst := make([]byte, o.blockSize)
				o.cipher.Encrypt(dst, padded)
				output = append(output, dst...)
			} else {
				dst := make([]byte, o.blockSize)
				o.cipher.Encrypt(dst, blocks[i])
				output = append(output, dst...)
				lastBlock := bytes.Repeat([]byte{byte(o.blockSize)}, o.blockSize)
				output = append(output, lastBlock...)
			}
		} else {
			dst := make([]byte, o.blockSize)
			o.cipher.Encrypt(dst, blocks[i])
			output = append(output, dst...)
		}
	}
	return output, nil
}

func (o *ECBOracle) Query(input []byte) ([]byte, error) {
	suffixStr := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	suffix, err := base64.StdEncoding.DecodeString(suffixStr)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(input)+len(suffix))
	if len(input) > 0 {
		copy(plaintext, input)
	}
	copy(plaintext[len(input):], suffix)
	output, err := o.encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (o *ECBOracle) FindBlockSize() (int, error) {
	prevDelta := 0
	for i := 0; i < 100; i++ {
		input := bytes.Repeat([]byte("A"), i)
		output, err := o.Query(input)
		if err != nil {
			return 0, err
		}
		delta := len(output) - len(input)
		offset := delta - prevDelta
		if offset != 144 && offset+1 != 0 {
			return offset + 1, nil
		}
		prevDelta = delta
	}
	return 0, errors.New("blocksize not detected")
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

func createTrialData(blockSize, blockIndex, blockOffset, maxBlocks int, plaintext []byte, currentBlockPlaintext []byte, lastByte byte) []byte {
	output := []byte{}
	if blockSize-(blockOffset+1) != 0 {
		output = bytes.Repeat([]byte("A"), blockSize-(blockOffset+1))
	}
	if len(plaintext) > 0 {
		output = append(output, plaintext...)
	}
	if len(currentBlockPlaintext) > 0 {
		output = append(output, currentBlockPlaintext...)
	}
	output = append(output, lastByte)
	if blockIndex == maxBlocks-1 {
		blocks := getBlocks(output, blockSize)
		if len(blocks[blockIndex]) < blockSize {
			unpadded, err := pkcs7Pad(blocks[blockIndex], blockSize)
			if err != nil {
				panic(err)
			}
			output = append(output, unpadded...)
		}
	}
	return output
}

func createRetrievalData(blockSize, blockNum, blockOffset int) []byte {
	output := bytes.Repeat([]byte("A"), (blockSize - (blockOffset + 1)))
	return output
}

func main() {
	key := [16]byte{}
	_, err := rand.Reader.Read(key[:])
	if err != nil {
		panic(err)
	}
	oracle, err := NewECBOracle()
	if err != nil {
		panic(err)
	}
	blockSize, err := oracle.FindBlockSize()
	if err != nil {
		panic(err)
	}
	fmt.Printf("block size %d\n", blockSize)

	input := bytes.Repeat([]byte("A"), 32)
	output, err := oracle.Query(input)
	if err != nil {
		panic(err)
	}

	if isECB(output) {
		fmt.Println("ECB detected")
	} else {
		panic("wtf, not ECB")
	}

	// use oracle to decrypt unknown section of ciphertext

	// get number of blocks in unknown ciphertext output
	input = []byte{}
	ciphertext, err := oracle.Query(input)
	if err != nil {
		panic(err)
	}
	fmt.Printf("oracle ciphertext length is %d\n", len(ciphertext))
	blocks := getBlocks(ciphertext, blockSize)
	maxBlocks := len(blocks)
	fmt.Printf("%d ciphertext blocks\n", maxBlocks)

	plaintext := []byte{}
	for blockIndex := 0; blockIndex < maxBlocks; blockIndex++ {
		blockPlaintext := []byte{}
		for blockOffset := 0; blockOffset < blockSize; blockOffset++ {
			lastMap := make(map[[16]byte]byte)
			for val := 0; val < 256; val++ {
				input = createTrialData(blockSize, blockIndex, blockOffset, maxBlocks, plaintext, blockPlaintext, byte(val))
				ciphertext, err = oracle.Query(input)
				if err != nil {
					panic(err)
				}
				blocks = getBlocks(ciphertext, blockSize)
				blockSlice := blocks[blockIndex]
				block := [16]byte{} // XXX
				copy(block[:], blockSlice)
				_, ok := lastMap[block]
				if ok {
					panic("wtf duplicate map keys")
				}
				lastMap[block] = byte(val)
			}
			if len(lastMap) != 256 {
				panic("wtf oracle map is invalid")
			}
			input = createRetrievalData(blockSize, blockIndex, blockOffset)
			oracle.Debug = true
			ciphertext, err = oracle.Query(input)
			if err != nil {
				panic(err)
			}
			blocks := getBlocks(ciphertext, blockSize)
			block := [16]byte{} // XXX
			copy(block[:], blocks[blockIndex])
			_, ok := lastMap[block]
			if !ok {
				continue
			}
			blockPlaintext = append(blockPlaintext, lastMap[block])
		}
		fmt.Print(string(blockPlaintext))
		plaintext = append(plaintext, blockPlaintext...)
	}
}
