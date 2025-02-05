// Package algorithm refer: https://github.com/mysto/python-fpe
package ff3

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const (
	NUM_ROUNDS     = 8
	BLOCK_SIZE     = 16
	TWEAK_LEN      = 8
	TWEAK_LEN_NEW  = 7
	HALF_TWEAK_LEN = TWEAK_LEN / 2
	DOMAIN_MIN     = 1000000
	RADIX_MAX      = 256
)

type FF3Cipher struct {
	key       []byte
	tweak     string
	radix     int
	alphabet  string
	minLen    int
	maxLen    int
	aesCipher cipher.Block
}

func GetFF3Cipher(radix int) (*FF3Cipher, error) {
	return NewFF3Cipher(ff3Key, ff3Tweak, radix)
}

func NewFF3Cipher(key, tweak string, radix int) (*FF3Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	if radix < 2 || radix > RADIX_MAX {
		return nil, errors.New("radix must be between 2 and 256, inclusive")
	}

	minLen := int(math.Ceil(math.Log(DOMAIN_MIN) / math.Log(float64(radix))))
	maxLen := 2 * int(math.Floor(96/math.Log2(float64(radix))))

	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return nil, errors.New("key length must be 128, 192, or 256 bits")
	}

	aesCipher, err := aes.NewCipher(reverseBytes(keyBytes))
	if err != nil {
		return nil, err
	}

	alphabet := ff3Alphabet[:radix]
	if radix > ff3AlphabetLen {
		alphabet = ""
	}

	return &FF3Cipher{
		key:       keyBytes,
		tweak:     tweak,
		radix:     radix,
		alphabet:  alphabet,
		minLen:    minLen,
		maxLen:    maxLen,
		aesCipher: aesCipher,
	}, nil
}

func NewFF3CipherCustomAlphabet(key, tweak string, customalpha string) (*FF3Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// Handle customalpha as a UTF-8-safe string (rune slice)
	runesAlpha := []rune(customalpha)
	radix := len(runesAlpha)

	if radix < 2 || radix > RADIX_MAX {
		return nil, errors.New("radix must be between 2 and 256, inclusive")
	}

	// Calculate the min and max length based on the radix
	minLen := int(math.Ceil(math.Log(DOMAIN_MIN) / math.Log(float64(radix))))
	maxLen := 2 * int(math.Floor(96 / math.Log2(float64(radix))))

	// Ensure the key length is valid (128, 192, or 256 bits)
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return nil, errors.New("key length must be 128, 192, or 256 bits")
	}

	// Reverse the key bytes for AES cipher (UTF-8 safe)
	aesCipher, err := aes.NewCipher(reverseBytes(keyBytes))
	if err != nil {
		return nil, err
	}

	// Use only the first 'radix' runes of the custom alphabet
	alphabet := string(runesAlpha[:radix])

	// Set the alphabet length
	ff3AlphabetLen := len(alphabet)
	if radix > ff3AlphabetLen {
		alphabet = ""
	}

	// Return a new FF3Cipher with the given parameters
	return &FF3Cipher{
		key:       keyBytes,
		tweak:     tweak,
		radix:     radix,
		alphabet:  alphabet,
		minLen:    minLen,
		maxLen:    maxLen,
		aesCipher: aesCipher,
	}, nil
}


func (c *FF3Cipher) Encrypt(plaintext string) (string, error) {
	return c.encryptWithTweak(plaintext, c.tweak)
}

func (c *FF3Cipher) encryptWithTweak(plaintext, tweak string) (string, error) {
	tweakBytes, err := hex.DecodeString(tweak)
	if err != nil {
		return "", err
	}

	runes := []rune(plaintext) // Convert to runes for UTF-8 safety
	n := len(runes)            // Count runes instead of bytes

	if n < c.minLen || n > c.maxLen {
		return "", errors.New("message length is not within min and max bounds")
	}

	if len(tweakBytes) != TWEAK_LEN && len(tweakBytes) != TWEAK_LEN_NEW {
		return "", errors.New("tweak length must be 56 or 64 bits")
	}

	u := (n + 1) / 2
	v := n - u
	A := runes[:u] // Slice runes instead of bytes
	B := runes[u:]

	if len(tweakBytes) == TWEAK_LEN_NEW {
		tweakBytes = calculateTweak64FF31(tweakBytes)
	}

	Tl := tweakBytes[:HALF_TWEAK_LEN]
	Tr := tweakBytes[HALF_TWEAK_LEN:]

	modU := new(big.Int).Exp(big.NewInt(int64(c.radix)), big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(big.NewInt(int64(c.radix)), big.NewInt(int64(v)), nil)

	for i := 0; i < NUM_ROUNDS; i++ {
		var m int
		var W []byte
		if i%2 == 0 {
			m = u
			W = Tr
		} else {
			m = v
			W = Tl
		}

		P := calculateP(i, c.alphabet, W, string(B)) // Convert runes to string
		revP := reverseBytes([]byte(P))

		S := make([]byte, BLOCK_SIZE)
		c.aesCipher.Encrypt(S, revP)

		y := new(big.Int).SetBytes(reverseBytes(S))

		cInt := decodeBigInt(string(A), c.alphabet) // Convert runes to string
		cInt.Add(cInt, y)
		if i%2 == 0 {
			cInt.Mod(cInt, modU)
		} else {
			cInt.Mod(cInt, modV)
		}

		C := encodeBigInt(cInt, c.alphabet, m)
		A = B
		B = []rune(C) // Convert string to runes for UTF-8 safety
	}

	return string(A) + string(B), nil // Convert runes back to string
}

func reverseBytes(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func calculateTweak64FF31(tweak56 []byte) []byte {
	tweak64 := make([]byte, 8)
	tweak64[0] = tweak56[0]
	tweak64[1] = tweak56[1]
	tweak64[2] = tweak56[2]
	tweak64[3] = tweak56[3] & 0xF0
	tweak64[4] = tweak56[4]
	tweak64[5] = tweak56[5]
	tweak64[6] = tweak56[6]
	tweak64[7] = (tweak56[3] & 0x0F) << 4
	return tweak64
}


func calculateP(i int, alphabet string, W []byte, B string) string {
	P := make([]byte, BLOCK_SIZE)
	P[0] = W[0]
	P[1] = W[1]
	P[2] = W[2]
	P[3] = W[3] ^ byte(i)

	// Ensure B is handled as a UTF-8 safe rune-based string
	BBytes := decodeBigInt(B, alphabet).FillBytes(make([]byte, BLOCK_SIZE-4)) // Adjust to fit remaining bytes
	copy(P[len(P)-len(BBytes):], BBytes)

	return string(P)
}

func encodeBigInt(n *big.Int, alphabet string, length int) string {
	runes := []rune(alphabet) // Convert alphabet to runes for UTF-8 safety
	base := big.NewInt(int64(len(runes)))
	var builder strings.Builder

	for n.Cmp(base) >= 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		builder.WriteRune(runes[mod.Int64()])
	}
	builder.WriteRune(runes[n.Int64()])

	// Pad if necessary
	for builder.Len() < length {
		builder.WriteRune(runes[0])
	}

	return builder.String()
}

// decodeBigInt converts a string to a big.Int using a custom alphabet (UTF-8 friendly)
func decodeBigInt(s, alphabet string) *big.Int {
	runes := []rune(s)           // Convert input string to runes
	runesAlpha := []rune(alphabet) // Convert alphabet to runes
	base := len(runesAlpha)
	num := new(big.Int)

	// Reverse the runes to process from least to most significant
	reversedRunes := reverseRunes(runes)
	strlen := len(reversedRunes)

	for idx, char := range reversedRunes {
		power := strlen - (idx + 1)

		// Find the index of the character in the alphabet (UTF-8 safe)
		charIndex := indexRune(runesAlpha, char)
		if charIndex == -1 {
			panic(fmt.Errorf("char '%c' not found in alphabet", char))
		}

		// Calculate the value and add it to num
		multiplier := new(big.Int).Exp(big.NewInt(int64(base)), big.NewInt(int64(power)), nil)
		value := new(big.Int).Mul(big.NewInt(int64(charIndex)), multiplier)
		num.Add(num, value)
	}

	return num
}

// reverseRunes reverses a slice of runes (UTF-8 safe)
func reverseRunes(runes []rune) []rune {
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return runes
}

// indexRune finds the index of a rune in a slice of runes (UTF-8 safe)
func indexRune(alphabet []rune, char rune) int {
	for i, a := range alphabet {
		if a == char {
			return i
		}
	}
	return -1
}


func (c *FF3Cipher) Decrypt(ciphertext string) (string, error) {
	return c.decryptWithTweak(ciphertext, c.tweak)
}

func (c *FF3Cipher) decryptWithTweak(ciphertext, tweak string) (string, error) {
	tweakBytes, err := hex.DecodeString(tweak)
	if err != nil {
		return "", err
	}

	runes := []rune(ciphertext) // Convert to runes for UTF-8 safety
	n := len(runes) // Use length of runes instead of bytes

	if n < c.minLen || n > c.maxLen {
		return "", fmt.Errorf("message length %d is not within min %d and max %d bounds", n, c.minLen, c.maxLen)
	}

	if len(tweakBytes) != TWEAK_LEN && len(tweakBytes) != TWEAK_LEN_NEW {
		return "", fmt.Errorf("tweak length %d invalid: tweak must be 8 bytes, or 64 bits", len(tweakBytes))
	}

	u := (n + 1) / 2
	v := n - u
	A := runes[:u] // Slice using runes to preserve multibyte characters
	B := runes[u:]

	if len(tweakBytes) == TWEAK_LEN_NEW {
		tweakBytes = calculateTweak64FF31(tweakBytes)
	}

	Tl := tweakBytes[:HALF_TWEAK_LEN]
	Tr := tweakBytes[HALF_TWEAK_LEN:]

	modU := new(big.Int).Exp(big.NewInt(int64(c.radix)), big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(big.NewInt(int64(c.radix)), big.NewInt(int64(v)), nil)

	for i := NUM_ROUNDS - 1; i >= 0; i-- {
		var m int
		var W []byte
		if i%2 == 0 {
			m = u
			W = Tr
		} else {
			m = v
			W = Tl
		}

		P := calculateP(i, c.alphabet, W, string(A)) // Convert runes to string
		revP := reverseBytes([]byte(P))

		S := make([]byte, BLOCK_SIZE)
		c.aesCipher.Encrypt(S, revP)
		S = reverseBytes(S)

		y := new(big.Int).SetBytes(S)

		cInt := decodeBigInt(string(B), c.alphabet) // Convert runes to string
		cInt.Sub(cInt, y)
		if i%2 == 0 {
			cInt.Mod(cInt, modU)
		} else {
			cInt.Mod(cInt, modV)
		}

		C := encodeBigInt(cInt, c.alphabet, m)
		B = A
		A = []rune(C) // Convert string to runes for safe indexing
	}

	return string(A) + string(B), nil // Convert runes back to string
}

func FF3EncryptInt(c *FF3Cipher, val int64, length int) (string, error) {
	plaintext := encodeBigInt(big.NewInt(val), c.alphabet, length)
	return c.Encrypt(plaintext)
}

func FF3DecryptInt(c *FF3Cipher, ciphertext string) (int64, error) {
	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		return 0, err
	}
	return decodeBigInt(plaintext, c.alphabet).Int64(), nil
}
