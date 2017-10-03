package utils

func bitSetCount(v byte) byte {
	v = (v & 0x55) + ((v >> 1) & 0x55)
	v = (v & 0x33) + ((v >> 2) & 0x33)
	return (v + (v >> 4)) & 0xF
}

func HammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("hammingDistance: input strings must be equal length")
	}
	count := 0
	for i := 0; i < len(b); i++ {
		count += int(bitSetCount(a[i] ^ b[i]))
	}
	return count
}
