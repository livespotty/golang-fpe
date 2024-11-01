package ff3

import "os"

var (
	ff3Key   = "2DE79D232DF5585D68CE47882AE256D6"
	ff3Tweak = "2e3ddd0afd1d09"
)

func init() {
	//	Get the FF3 cipher key and tweak from the environment
	var key = os.Getenv("FF3_CIPHER_KEY")
	var tweak = os.Getenv("FF3_CIPHER_TWEAK")
	if key != "" {
		ff3Key = key
	}
	if tweak != "" {
		ff3Tweak = tweak
	}
}
