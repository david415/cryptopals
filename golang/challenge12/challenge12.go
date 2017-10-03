package challenge12

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/david415/cryptopals/golang/utils"
)

type ECBOracle struct {
	blockSize int
	key       []byte
	cipher    cipher.Block
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
	}
	return &o, nil
}

func (o *ECBOracle) encrypt(input []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, o.blockSize)
	for i := 0; i < len(blocks); i++ {

		if i == len(blocks)-1 {
			// always apply padding to the last block
			if len(blocks[i]) < o.blockSize {
				padded, err := utils.PKCS7Pad(blocks[i], o.blockSize)
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

func CreateTrialData(blockSize, blockIndex, blockOffset, maxBlocks int, plaintext []byte, currentBlockPlaintext []byte, lastByte byte) ([]byte, error) {
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
		blocks := utils.GetBlocks(output, blockSize)
		if len(blocks[blockIndex]) < blockSize {
			unpadded, err := utils.PKCS7Pad(blocks[blockIndex], blockSize)
			if err != nil {
				return nil, err
			}
			output = append(output, unpadded...)
		}
	}
	return output, nil
}

func CreateRetrievalData(blockSize, blockNum, blockOffset int) []byte {
	output := bytes.Repeat([]byte("A"), (blockSize - (blockOffset + 1)))
	return output
}

func BreakOracleString(maxBlocks, blockSize int, oracle *ECBOracle) ([]byte, error) {
	var err error
	plaintext := []byte{}
	input := []byte{}
	ciphertext, err := oracle.Query(input)
	if err != nil {
		return nil, err
	}
	blocks := utils.GetBlocks(ciphertext, blockSize)

	for blockIndex := 0; blockIndex < maxBlocks; blockIndex++ {
		blockPlaintext := []byte{}
		for blockOffset := 0; blockOffset < blockSize; blockOffset++ {
			lastMap := make(map[[16]byte]byte)
			for val := 0; val < 256; val++ {
				input, err = CreateTrialData(blockSize, blockIndex, blockOffset, maxBlocks, plaintext, blockPlaintext, byte(val))
				if err != nil {
					return nil, err
				}
				ciphertext, err = oracle.Query(input)
				if err != nil {
					return nil, err
				}
				blocks = utils.GetBlocks(ciphertext, blockSize)
				blockSlice := blocks[blockIndex]
				block := [16]byte{} // XXX
				copy(block[:], blockSlice)
				_, ok := lastMap[block]
				if ok {
					return nil, errors.New("wtf duplicate map keys")
				}
				lastMap[block] = byte(val)
			}
			if len(lastMap) != 256 {
				return nil, errors.New("wtf oracle map is invalid")
			}
			input = CreateRetrievalData(blockSize, blockIndex, blockOffset)
			ciphertext, err = oracle.Query(input)
			if err != nil {
				return nil, err
			}
			blocks := utils.GetBlocks(ciphertext, blockSize)
			block := [16]byte{} // XXX
			copy(block[:], blocks[blockIndex])
			_, ok := lastMap[block]
			if !ok {
				continue
			}
			blockPlaintext = append(blockPlaintext, lastMap[block])
		}
		plaintext = append(plaintext, blockPlaintext...)
	}
	return plaintext, nil
}
