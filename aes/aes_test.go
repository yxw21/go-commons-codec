package aes

import (
	"fmt"
	"testing"
)

func TestAESCBC(t *testing.T) {
	// key length: 16, 24, 32 -> AES-128，AES-192，AES-256
	key := []byte("ABCDABCDABCDABCD")
	data := []byte("123456")
	fmt.Println("key: ", key)
	fmt.Println("data: ", data)

	encData, err := EncryptCBC(data, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("EncryptCBC result: ", encData)

	decData, err := DecryptCBC(encData, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("DecryptCBC result: ", decData)
}

func TestAESECB(t *testing.T) {
	// key length: 16, 24, 32 -> AES-128，AES-192，AES-256
	key := []byte("ABCDABCDABCDABCD")
	data := []byte("123456")
	fmt.Println("key: ", key)
	fmt.Println("data: ", data)

	encData, err := EncryptECB(data, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("EncryptECB result: ", encData)

	decData, err := DecryptECB(encData, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("DecryptECB result: ", decData)
}

func TestAESCFB(t *testing.T) {
	// key length: 16, 24, 32 -> AES-128，AES-192，AES-256
	key := []byte("ABCDABCDABCDABCD")
	data := []byte("123456")
	fmt.Println("key: ", key)
	fmt.Println("data: ", data)

	encData, err := EncryptCFB(data, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("EncryptCFB result: ", encData)

	decData, err := DecryptCFB(encData, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("DecryptCFB result: ", decData)
}
