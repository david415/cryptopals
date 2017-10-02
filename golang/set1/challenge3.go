package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func xorWithOne(dst []byte, a []byte, b byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b
	}
}

func percentChar(s, a string) float64 {
	count := strings.Count(s, a)
	if count != 0 {
		return float64(100) / float64(len(s)) / float64(count)
	}
	return 0
}

// func isFit(s string) bool {
// 	fitCount := 0
// 	if !strings.ContainsAny(s, " ") {
// 		return false
// 	}
// 	if percentChar(s, "a") >= 8 {
// 		fitCount += 1
// 	}
// 	if percentChar(s, "e") >= 12 {
// 		fitCount += 1
// 	}
// 	if percentChar(s, "i") >= 6 {
// 		fitCount += 1
// 	}
// 	if percentChar(s, "o") >= 7 {
// 		fitCount += 1
// 	}
// 	if percentChar(s, "u") >= 2 {
// 		fitCount += 1
// 	}
// 	if percentChar(s, "y") >= 1 {
// 		fitCount += 1
// 	}
// 	if fitCount >= 1 {
// 		return true
// 	}
// 	return false
// }

func isFit(s string) bool {
	fitCount := 0
	if !strings.ContainsAny(s, " ") {
		return false
	}
	if percentChar(s, "a") >= 8 {
		fitCount += 1
	}
	if percentChar(s, "e") >= 12 {
		fitCount += 1
	}
	if percentChar(s, "i") >= 6 {
		fitCount += 1
	}
	if percentChar(s, "o") >= 7 {
		fitCount += 1
	}
	if percentChar(s, "u") >= 2 {
		fitCount += 1
	}
	if percentChar(s, "y") >= 1 {
		fitCount += 1
	}
	if percentChar(s, "t") >= 9 {
		fitCount += 1
	}
	if percentChar(s, "n") >= 6 {
		fitCount += 1
	}
	if percentChar(s, "s") >= 6 {
		fitCount += 1
	}
	if percentChar(s, "r") >= 6 {
		fitCount += 1
	}
	if percentChar(s, "h") >= 5 {
		fitCount += 1
	}
	if percentChar(s, "d") >= 4 {
		fitCount += 1
	}
	if percentChar(s, "l") >= 3 {
		fitCount += 1
	}
	if percentChar(s, "c") >= 2 {
		fitCount += 1
	}
	if fitCount >= 2 {
		return true
	}
	return false
}

func getSingleXor(input []byte) ([]byte, byte, error) {
	out := make([]byte, len(input))
	for i := 0; i < 256; i++ {
		xorWithOne(out, input, byte(i))
		if isFit(string(out)) {
			return out, byte(i), nil
		}
	}
	return []byte{}, byte(0), errors.New("fit XORed value not found")
}

func main() {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	newLine, _, _ := getSingleXor(inputBytes)
	fmt.Println(string(newLine))
}
