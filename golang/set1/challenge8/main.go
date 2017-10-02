package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
)

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

func main() {
	blockSize := 16
	fh, err := os.Open("8.txt")
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(fh)
	for {
		blockMap := make(map[[16]byte]bool)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		truncatedLine := line[:len(line)-1]
		rawBytes, err := hex.DecodeString(truncatedLine)
		if err != nil {
			panic(err)
		}
		blocks := getBlocks(rawBytes, blockSize)
		//fmt.Printf("number of blocks %d\n", len(blocks))
		for _, block := range blocks {
			blockArr := [16]byte{}
			copy(blockArr[:], block)
			_, ok := blockMap[blockArr]
			if ok {
				fmt.Println("duplicate blocks detected!")
			} else {
				blockMap[blockArr] = true
			}
		}
	}
}
