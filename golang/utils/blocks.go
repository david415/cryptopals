package utils

func GetBlocks(ciphertext []byte, blockSize int) [][]byte {
	blocks := [][]byte{}
	for i := 0; i < len(ciphertext); i += blockSize {
		if i+blockSize > len(ciphertext)-1 {
			blocks = append(blocks, ciphertext[i:])
		} else {
			blocks = append(blocks, ciphertext[i:i+blockSize])
		}
	}
	return blocks
}

func TransposeBlocks(blocks [][]byte) [][]byte {
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
