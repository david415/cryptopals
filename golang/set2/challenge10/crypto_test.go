package main

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCBC(t *testing.T) {
	require := require.New(t)

	plaintext1, err := ioutil.ReadFile("1984.txt")
	require.NoError(err, "fail")
	iv := [16]byte{}
	key := "the quick red fo"
	ciphertext, err := cbcEncrypt(iv[:], plaintext1, []byte(key))
	require.NoError(err, "fail")
	plaintext2, err := cbcDecrypt(iv[:], ciphertext, []byte(key))
	t.Logf("decrypted: %s", string(plaintext2))
	//require.Equal(plaintext1, plaintext2, "fail")
}
