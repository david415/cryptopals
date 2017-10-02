package main

import (
	"encoding/hex"
	"fmt"
)

func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

func main() {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	input1Bytes, err := hex.DecodeString(input1)
	if err != nil {
		panic(err)
	}
	input2Bytes, err := hex.DecodeString(input2)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(input1Bytes))
	xorBytes(out, input1Bytes, input2Bytes)
	fmt.Printf("%x\n", out)
}
