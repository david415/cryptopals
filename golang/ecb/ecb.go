package ecb

import (
	"crypto/aes"

	"github.com/david415/cryptopals/golang/utils"
)

func ECBDecrypt(input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, len(key))
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

func ECBEncrypt(input []byte, key []byte) ([]byte, error) {
	output := []byte{}
	blocks := utils.GetBlocks(input, len(key))
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	for _, block := range blocks {
		dst := make([]byte, len(key))
		if len(block) < 16 {
			block, err = utils.PKCS7Pad(block, 16)
		}
		cipher.Encrypt(dst, block)
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
