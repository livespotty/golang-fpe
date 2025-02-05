package ff3

import "os"

var (
	ff3Key         = "2DE79D232DF5585D68CE47882AE256D6"
	ff3Tweak       = "2e3ddd0afd1d09"
	ff3Alphabet    = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	runesAlpha = []rune(ff3Alphabet)
	ff3AlphabetLen = len(runesAlpha)
)

func init() {
	//	Get the FF3 cipher key and tweak from the environment
	var key = os.Getenv("FF3_CIPHER_KEY")
	var tweak = os.Getenv("FF3_CIPHER_TWEAK")
	var alphabet = os.Getenv("FF3_CIPHER_ALPHABET")
	if key != "" {
		ff3Key = key
	}
	if tweak != "" {
		ff3Tweak = tweak
	}
	if alphabet != "" {
		ff3Alphabet = alphabet
		runesAlpha = []rune(ff3Alphabet)
		ff3AlphabetLen = len(runesAlpha)
	}
}
