package ecb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"

	"github.com/david415/cryptopals/golang/utils"
)

// ECBAESCipher is AES-128 in ECB mode
type ECBAESCipher struct {
	key       [16]byte
	cipher    cipher.Block
	blockSize int
}

func New(key [16]byte) (*ECBAESCipher, error) {
	aesCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	c := ECBAESCipher{
		key:       key,
		cipher:    aesCipher,
		blockSize: 16,
	}
	return &c, nil
}

func (c *ECBAESCipher) Encrypt(input []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, c.blockSize)
	for i := 0; i < len(blocks); i++ {
		if i == len(blocks)-1 {
			// always apply padding to the last block
			if len(blocks[i]) < c.blockSize {
				padded, err := utils.PKCS7Pad(blocks[i], c.blockSize)
				if err != nil {
					return nil, err
				}
				dst := make([]byte, c.blockSize)
				c.cipher.Encrypt(dst, padded)
				output = append(output, dst...)
			} else {
				dst := make([]byte, c.blockSize)
				c.cipher.Encrypt(dst, blocks[i])
				output = append(output, dst...)
				lastBlock := bytes.Repeat([]byte{byte(c.blockSize)}, c.blockSize)
				output = append(output, lastBlock...)
			}
		} else {
			dst := make([]byte, c.blockSize)
			c.cipher.Encrypt(dst, blocks[i])
			output = append(output, dst...)
		}
	}
	return output, nil
}

func (c *ECBAESCipher) Decrypt(input []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, c.blockSize)
	for _, block := range blocks {
		dst := make([]byte, c.blockSize)
		c.cipher.Decrypt(dst, block)
		output = append(output, dst...)
	}
	return output, nil
}

func IsECB(input []byte) bool {
	blockMap := make(map[[16]byte]bool)
	blocks := utils.GetBlocks(input, 16)
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
