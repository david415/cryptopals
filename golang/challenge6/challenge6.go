package challenge6

type potentialKeySize struct {
	distance float32
	keySize  int
}

type byDistance []potentialKeySize

func (d byDistance) Len() int { return len(d) }

func (d byDistance) Swap(i, j int) { d[i], d[j] = d[j], d[i] }

func (d byDistance) Less(i, j int) bool { return d[i].distance < d[j].distance }

func EstimateKeySize(ciphertext []byte) int {
	potentials := []potentialKeySize{}
	for keySize := 2; keySize < 40; keySize++ {
		distances := []float32{}
		for j := 0; j < len(ciphertext); j += keySize {
			if keySize*(j+3) > len(ciphertext) {
				break
			}
			a := ciphertext[keySize*j : keySize*(j+1)]
			b := ciphertext[keySize*(j+2) : keySize*(j+3)]
			distance := float32(HammingDistance(a, b))
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
