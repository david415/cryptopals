package main

import (
	"fmt"
)

func repeatXor(key []byte, input []byte) []byte {
	output := make([]byte, len(input))
	j := 0
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[j]
		if j < len(key)-1 {
			j += 1
		} else {
			j = 0
		}
	}
	return output
}

func main() {
	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	output := repeatXor([]byte(key), []byte(input))
	fmt.Printf("%x\n", output)
}
