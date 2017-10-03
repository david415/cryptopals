package challenge11

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/david415/cryptopals/golang/cbc"
	"github.com/david415/cryptopals/golang/ecb"
)

func genRandMinMax(max, min int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func EncryptOracle(input []byte) ([]byte, error) {
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
		output, err = ecb.ECBEncrypt(input, key[:])
		if err != nil {
			return nil, err
		}
	} else {
		iv := [16]byte{}
		_, err := rand.Reader.Read(iv[:])
		if err != nil {
			return nil, err
		}
		output, err = cbc.CBCEncrypt(iv[:], input, key[:])
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
