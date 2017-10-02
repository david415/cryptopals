package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"unicode"
)

const ()

func bitSetCount(v byte) byte {
	v = (v & 0x55) + ((v >> 1) & 0x55)
	v = (v & 0x33) + ((v >> 2) & 0x33)
	return (v + (v >> 4)) & 0xF
}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("hammingDistance: input strings must be equal length")
	}
	count := 0
	for i := 0; i < len(b); i++ {
		count += int(bitSetCount(a[i] ^ b[i]))
	}
	return count
}

type potentialKeySize struct {
	distance float32
	keySize  int
}

type byDistance []potentialKeySize

func (d byDistance) Len() int { return len(d) }

func (d byDistance) Swap(i, j int) { d[i], d[j] = d[j], d[i] }

func (d byDistance) Less(i, j int) bool { return d[i].distance < d[j].distance }

func estimateKeySize(ciphertext []byte) int {
	potentials := []potentialKeySize{}
	for keySize := 2; keySize < 40; keySize++ {
		distances := []float32{}
		for j := 0; j < len(ciphertext); j += keySize {
			if keySize*(j+3) > len(ciphertext) {
				break
			}
			a := ciphertext[keySize*j : keySize*(j+1)]
			b := ciphertext[keySize*(j+2) : keySize*(j+3)]
			distance := float32(hammingDistance(a, b))
			distances = append(distances, distance)
		}
		sum := float32(0)
		for _, d := range distances {
			sum += d
		}
		average := (sum / float32(len(distances))) / float32(keySize)
		p := potentialKeySize{
			distance: average,
			keySize:  keySize,
		}
		potentials = append(potentials, p)
	}
	sort.Sort(byDistance(potentials))
	return potentials[0].keySize
}

func getBlocks(ciphertext []byte, blockSize int) [][]byte {
	blocks := [][]byte{}
	for i := 0; i < len(ciphertext); i += blockSize {
		if i+blockSize > len(ciphertext) {
			blocks = append(blocks, ciphertext[i:])
		} else {
			blocks = append(blocks, ciphertext[i:i+blockSize])
		}
	}
	return blocks
}

func transposeBlocks(blocks [][]byte) [][]byte {
	output := make([][]byte, len(blocks[0]))
	for j := 0; j < len(blocks[0]); j++ {
		for i := 0; i < len(blocks); i++ {
			if j < len(blocks[i]) {
				output[j] = append(output[j], blocks[i][j])
			} else {
				break
			}
		}
	}
	return output
}

func percentSubstring(s, a string) float32 {
	count := strings.Count(s, a)
	if count != 0 {
		return float32(100) / (float32(len(s)) / float32(count))
	}
	return 0
}

func xorWithOne(dst []byte, a []byte, b byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b
	}
}

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

func removeSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

func near(n, exact float32) bool {
	slop := float32(3)
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
	letterFreq := map[string]float32{
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
	b, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		panic(err)
	}
	keySize := estimateKeySize(ciphertext)
	blocks := getBlocks(ciphertext, keySize)
	transposed := transposeBlocks(blocks)
	key := []byte{}
	for _, b := range transposed {
		_, singleKey := getSingleXorScore(b)
		key = append(key, singleKey)
	}
	fmt.Printf("key_size is %v key is %s\nplaintext is:\n", keySize, key)
	plaintext := repeatXor(key, ciphertext)
	fmt.Println(string(plaintext))
}
