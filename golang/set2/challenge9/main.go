package main

import (
	"bytes"
	"errors"
	"fmt"
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

func pkcs7Unpad(input []byte, blockSize int) ([]byte, error) {
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
	return input[:len(input)-padlen], nil
}

func main() {
	input := "YELLOW SUBMARINE"
	padded, err := pkcs7Pad([]byte(input), 20)
	if err != nil {
		panic(err)
	}
	fmt.Printf("padded: %x\n", padded)
	unpadded, err := pkcs7Unpad([]byte(padded), 20)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal([]byte(input), unpadded) {
		panic("padding failure")
	}
}
