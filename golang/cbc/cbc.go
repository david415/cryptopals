package cbc

import (
	"crypto/aes"

	"github.com/david415/cryptopals/golang/utils"
)

func CBCDecrypt(iv []byte, input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	prevBlock := iv
	currentBlock := make([]byte, len(key))
	for _, block := range blocks {
		cipher.Decrypt(currentBlock, block)
		xorBlock := make([]byte, len(key))
		utils.XorBytes(xorBlock, prevBlock, currentBlock)
		prevBlock = block
		output = append(output, xorBlock...)
	}
	return output, nil
}

func CBCEncrypt(iv []byte, input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	prevBlock := iv
	ciphertextBlock := make([]byte, len(key))
	for _, block := range blocks {
		xorBlock := make([]byte, len(key))
		utils.XorBytes(xorBlock, block, prevBlock)
		cipher.Encrypt(ciphertextBlock, xorBlock)
		prevBlock = ciphertextBlock
		output = append(output, ciphertextBlock...)
	}
	return output, nil
}
