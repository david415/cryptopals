package utils

import (
	"bytes"
	"errors"
)

func PKCS7Pad(input []byte, blockSize int) ([]byte, error) {
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

func PKCS7Unpad(input []byte, blockSize int) ([]byte, error) {
	if blockSize >= 256 || blockSize <= 0 {
		return nil, errors.New("specified block size is invalid")
	}
	if len(input) > blockSize || len(input) == 0 {
		// XXX should we return an error if input is bigger than block size?
		return nil, errors.New("input block size is invalid")
	}
	padlen := int(input[len(input)-1])
	if padlen > blockSize || padlen == 0 {
		return nil, errors.New("invalid padding")
	}
	pad := input[len(input)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}
	return input[0 : len(input)-padlen], nil
}
