package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func xorWithOne(dst []byte, a []byte, b byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b
	}
}

func percentSubstring(s, a string) float64 {
	count := strings.Count(s, a)
	if count != 0 {
		return float64(100) / (float64(len(s)) / float64(count))
	}
	return 0
}

func isAscii(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func removeSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

func near(n, exact float64) bool {
	slop := float64(3)
	if n > 5 {
		if n > exact-slop {
			return true
		}
		return false
	} else {
		if n > exact-0.25 {
			return true
		}
	}
	return false
}

func englishScore(s string) int {
	if !isAscii(s) {
		return 0
	}
	letterFreq := map[string]float64{
		"a": 8.167,
		"b": 1.492,
		"c": 2.782,
		"d": 4.253,
		"e": 12.702,
		"f": 2.228,
		"g": 2.015,
		"h": 6.094,
		"i": 7.294,
		"j": 0.511,
		"k": 0.456,
		"l": 2.415,
		"m": 3.826,
		"n": 2.284,
		"o": 7.631,
		"p": 4.319,
		"q": 0.222,
		"r": 2.826,
		"s": 6.686,
		"t": 15.978,
		"u": 1.183,
		"v": 0.824,
		"w": 5.497,
		"x": 0.045,
		"y": 0.763,
		"z": 0.045,
	}
	fitCount := 0
	if near(percentSubstring(s, " "), 15) {
		fitCount += 1
	} else {
		return 0
	}
	lowered := strings.ToLower(s)
	washed := removeSpace(lowered)
	for key, val := range letterFreq {
		if near(percentSubstring(washed, key), val) {
			fitCount += 1
		}
	}
	return fitCount
}

func getSingleXorScore(input []byte) (int, byte) {
	out := make([]byte, len(input))
	key := byte(0)
	highScore := 0
	for i := 0; i < 256; i++ {
		xorWithOne(out, input, byte(i))
		score := englishScore(string(out))
		if highScore < score {
			highScore = score
			key = byte(i)
		}
	}
	return highScore, key
}

func main() {
	fh, err := os.Open("4.txt")
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(fh)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		truncatedLine := line[:len(line)-1]
		inputBytes, err := hex.DecodeString(truncatedLine)
		if err != nil {
			panic(err)
		}
		score, key := getSingleXorScore(inputBytes)
		if score != 0 {
			out := make([]byte, len(inputBytes))
			xorWithOne(out, inputBytes, key)
			fmt.Printf("score %d, potential plaintext: %s\n", score, out)
		}
	}
}
