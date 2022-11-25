package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func pkcs7Padding(plaintext []byte, blockSize int) []byte {
	paddingCount := blockSize - len(plaintext)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingCount)}, paddingCount)
	return append(plaintext, paddingText...)
}

func pkcs7UnPadding(paddingPlaintext []byte) []byte {
	length := len(paddingPlaintext)
	unPadding := int(paddingPlaintext[length-1])
	return paddingPlaintext[:(length - unPadding)]
}

func EncryptCBC(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = pkcs7Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	encrypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(encrypted, plaintext)
	return encrypted, nil
}

func DecryptCBC(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	decrypted := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(decrypted, ciphertext)
	decrypted = pkcs7UnPadding(decrypted)
	return decrypted, nil
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

func EncryptECB(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return nil, err
	}
	length := (len(plaintext) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, plaintext)
	pad := byte(len(plain) - len(plaintext))
	for i := len(plaintext); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted := make([]byte, len(plain))
	for bs, be := 0, block.BlockSize(); bs <= len(plaintext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted, nil
}

func DecryptECB(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(ciphertext))
	for bs, be := 0, block.BlockSize(); bs < len(ciphertext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(decrypted[bs:be], ciphertext[bs:be])
	}
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}
	return decrypted[:trim], nil
}

func EncryptCFB(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, aes.BlockSize+len(plaintext))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], plaintext)
	return encrypted, nil
}

func DecryptCFB(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}
