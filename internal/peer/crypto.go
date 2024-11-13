package peer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/zenazn/pkcs7pad"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const AESKeySize = 32

func AesEncrypt(plaintext []byte, key []byte) ([]byte, []byte, []byte, error) {
	// encrypt
	// create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	// generate iv
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, nil, nil, err
	}
	paddedText := pkcs7pad.Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)
	hash := getHash(ciphertext)

	return ciphertext, iv, hash, nil
}

func getHash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	return hash
}

func AesDecrypt(ciphertext []byte, key []byte, iv []byte, hash []byte) ([]byte, error) {
	if hash != nil {
		h := getHash(ciphertext)
		if !bytes.Equal(h, hash) {
			return nil, errors.New("hash mismatch")
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext, err := pkcs7pad.Unpad(ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func KDFKeygen(password string) []byte {
	salt := make([]byte, 8)
	w, _ := scrypt.Key([]byte(password), salt, 32768, 8, 1, AESKeySize)
	return w
}

func EcdhKeygen() (*ecdh.PrivateKey, []byte, error) {
	// generate a new private key
	curve := ecdh.P256()
	privk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubk := privk.PublicKey()
	return privk, pubk.Bytes(), nil
}

func MasterKeyAndHash(salt []byte, password string) ([]byte, []byte) {
	mk := pbkdf2.Key([]byte(password), salt, 4096, 32, sha1.New)
	hash := pbkdf2.Key(mk, []byte(password), 4096, 32, sha1.New)
	return mk, hash
}
