package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func EncryptWithPKCS1(plaintext []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	content, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func DecryptWithPKCS1(ciphertext []byte, privateKey []byte, args ...[]byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	if x509.IsEncryptedPEMBlock(block) && len(args) > 0 {
		der, err := x509.DecryptPEMBlock(block, args[0])
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: block.Type, Bytes: der}
	}
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priKey, ciphertext)
}

func EncryptWithPKCS8(plaintext []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	content, err := rsa.EncryptPKCS1v15(rand.Reader, pubInterface.(*rsa.PublicKey), plaintext)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func DecryptWithPKCS8(ciphertext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priKey.(*rsa.PrivateKey), ciphertext)
}

func SignatureWithPKCS1SHA256(plaintext []byte, privateKey []byte, args ...[]byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	if x509.IsEncryptedPEMBlock(block) && len(args) > 0 {
		der, err := x509.DecryptPEMBlock(block, args[0])
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: block.Type, Bytes: der}
	}
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	myHash := sha256.New()
	myHash.Write(plaintext)
	dataHashText := myHash.Sum(nil)
	cipher, err := rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA256, dataHashText)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func VerifyWithPKCS1SHA256(plaintext []byte, ciphertext []byte, publicKey []byte) bool {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return false
	}
	myHash := sha256.New()
	myHash.Write(plaintext)
	dataHashText := myHash.Sum(nil)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, dataHashText, ciphertext) == nil
}

func SignatureWithPKCS8SHA256(plaintext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	myHash := sha256.New()
	myHash.Write(plaintext)
	dataHashText := myHash.Sum(nil)
	cipher, err := rsa.SignPKCS1v15(rand.Reader, priKey.(*rsa.PrivateKey), crypto.SHA256, dataHashText)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func VerifyWithPKCS8SHA256(plaintext []byte, ciphertext []byte, publicKey []byte) bool {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	myHash := sha256.New()
	myHash.Write(plaintext)
	dataHashText := myHash.Sum(nil)
	return rsa.VerifyPKCS1v15(pubInterface.(*rsa.PublicKey), crypto.SHA256, dataHashText, ciphertext) == nil
}
