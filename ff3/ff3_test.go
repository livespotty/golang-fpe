package ff3

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestFF3Cipher_Encrypt_Decrypt(t *testing.T) {
	var key = "2b7e151628aed2a6abf7158809cf4f3c"
	var tweak = "abcdef1234567890"
	var testSet = []struct {
		radix     int
		plaintext string
	}{
		{10, "123456"},
		{11, "38a947"},
		{16, "032afb"},
		{62, "1a2b3c"},
		{61, "1a2b3c4d5e6f7g8h9i0j"},
		{60, "klmnopqrstu894y7gttuh8974"},
	}

	for _, test := range testSet {
		cipher, err := NewFF3Cipher(key, tweak, test.radix)
		assert.NoError(t, err)

		result, err := cipher.Encrypt(test.plaintext)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		t.Logf("radix=%d got encrypted data: %v -> %v", test.radix, test.plaintext, result)

		decrypted, err := cipher.Decrypt(result)
		assert.NoError(t, err)
		assert.NotEmpty(t, decrypted)
		assert.Equal(t, test.plaintext, decrypted)
	}
}

func Test_DecodeBigInt(t *testing.T) {
	astring := "456"
	alphabet := "0123456789"
	num := decodeBigInt(astring, alphabet)
	fmt.Printf("Decoded number: %s\n", num)
}

func TestIntToBytes_ValidInput(t *testing.T) {
	num := big.NewInt(654)
	fmt.Printf("Number: %s %X\n", num.String(), num.FillBytes(make([]byte, 12)))
}

func Test_Encrypt_ValidInput(t *testing.T) {
	cipher, err := NewFF3Cipher("2b7e151628aed2a6abf7158809cf4f3c", "abcdef1234567890", 10)
	assert.NoError(t, err)

	plaintext := "123456"
	result, err := cipher.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	t.Logf("got encrypted data: %v -> %v", plaintext, result)
}

func Test_Encrypt_InvalidKey(t *testing.T) {
	_, err := NewFF3Cipher("invalidkey", "abcdef1234567890", 10)
	assert.Error(t, err)
}

func Test_Encrypt_InvalidTweak(t *testing.T) {
	cipher, err := NewFF3Cipher("2b7e151628aed2a6abf7158809cf4f3c", "invalidtweak", 10)
	assert.NoError(t, err)

	_, err = cipher.Encrypt("123456")
	assert.Error(t, err)
}

func Test_Encrypt_InvalidRadix(t *testing.T) {
	_, err := NewFF3Cipher("2b7e151628aed2a6abf7158809cf4f3c", "abcdef1234567890", 300)
	assert.Error(t, err)
}

func Test_Decrypt_ValidInput(t *testing.T) {
	cipher, err := NewFF3Cipher("2b7e151628aed2a6abf7158809cf4f3c", "abcdef1234567890", 10)
	assert.NoError(t, err)

	ciphertext := "878006"
	result, err := cipher.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	t.Logf("got decrypted data: %v -> %v", ciphertext, result)
}

func Test_Decrypt_InvalidKey(t *testing.T) {
	_, err := NewFF3Cipher("invalidkey", "abcdef1234567890", 10)
	assert.Error(t, err)
}

func Test_Decrypt_InvalidTweak(t *testing.T) {
	cipher, err := NewFF3Cipher("2b7e151628aed2a6abf7158809cf4f3c", "invalidtweak", 10)
	assert.NoError(t, err)

	_, err = cipher.Decrypt("878006")
	assert.Error(t, err)
}

func Test_Decrypt_InvalidRadix(t *testing.T) {
	_, err := NewFF3Cipher("2b7e151628aed2a6abf7158809cf4f3c", "abcdef1234567890", 300)
	assert.Error(t, err)
}

func Test_Encrypt_Int(t *testing.T) {
	ff3, err := GetFF3Cipher()
	assert.NoError(t, err)

	result, err := FF3EncryptInt(ff3, 123456, 6)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	t.Logf("got encrypted data: %v -> %v", 123456, result)

	val, err := FF3DecryptInt(ff3, result)
	assert.NoError(t, err)
	assert.Equal(t, int64(123456), val)
}
