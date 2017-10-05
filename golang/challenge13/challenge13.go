package challenge13

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"github.com/david415/cryptopals/golang/ecb"
)

func clean(input string) string {
	output := ""
	output = strings.Replace(input, "&", "", -1)
	output = strings.Replace(input, "=", "", -1)
	return output
}

type Role struct {
	email string
	role  string
	uid   int
}

func (r *Role) IsAdmin() bool {
	if r.role == "admin" {
		return true
	}
	return false
}

type ECBOracle struct {
	blockSize int
	key       []byte
	cipher    *ecb.ECBAESCipher
}

func NewECBOracle() (*ECBOracle, error) {
	key := [16]byte{}
	_, err := rand.Reader.Read(key[:])
	if err != nil {
		return nil, err
	}
	cipher, err := ecb.New(key)
	if err != nil {
		return nil, err
	}
	o := ECBOracle{
		blockSize: 16,
		key:       key[:],
		cipher:    cipher,
	}
	return &o, nil
}

func (o *ECBOracle) ProfileFor(email string) string {
	email = clean(email)
	email = strings.TrimSpace(email)
	encoded := fmt.Sprintf("email=%s&uid=10&role=user", email)
	return encoded
}

func (o *ECBOracle) Decrypt(input []byte) ([]byte, error) {
	output, err := o.cipher.Decrypt(input)
	return output, err
}

func (o *ECBOracle) Encrypt(input []byte) ([]byte, error) {
	output, err := o.cipher.Encrypt(input)
	return output, err
}

func (o *ECBOracle) DecryptAndParse(ciphertext []byte) (*Role, error) {
	encoding, err := o.cipher.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	role := Role{}
	args := strings.Split(string(encoding), "&")
	for _, arg := range args {
		fields := strings.Split(arg, "=")
		if fields[0] == "email" {
			role.email = fields[1]
		}
		if fields[0] == "uid" {
			role.uid, err = strconv.Atoi(fields[1])
			if err != nil {
				return nil, err
			}
		}
		if fields[0] == "role" {
			role.role = fields[1]
		}
	}
	return &role, nil
}
