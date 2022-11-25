package rsa

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestRSAPKCS1WithPassword(t *testing.T) {
	publicKey := []byte(`-----BEGIN RSA PUBLIC KEY-----
MEgCQQCzVyKqiM1S66bTwv79u26l1Or8hezeCHO3x8OwoAzcYZvHwdl+3pJEMJ8L
0+Mq35B72LVu5vYoEAnBVT91ye2pAgMBAAE=
-----END RSA PUBLIC KEY-----
`)
	privateKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,B5D74581C8FD2EF7

m7quYtGLyuarFSTn6ZMX6LEwipTZMv/AOB65jneUdJrWLRbBiiyLO9zYRMyz93V6
ND/TNJDRKpff3UfFdrn78kGG6zLAFdchsNRNQhCzTiuQ8z3WgwwaV7fPn9hxMa5y
3P5kpySv2/V2T9tBax+Y4B44cbofrhyCgu25L1SlpQEwo9iY2yRE1EKcw4dHPhuB
TkXFv8PFFXhpPvBFHy130z5H0DvkC2fPC/OIoYG4FzEfN40QowmFVrX6X0UBLruU
vGhj6GBiO2hw+aYCkEr9fFgYo1ODavHcO3+khc5NquVT3Rdl/h9qNk3vB2kYQ2Ep
N+3jNHLHIneOvpGOPJoAmuFIwVe+uAtPemdbyzf70Gu+Q4zAxF4XXf4VwmadFBKC
yjNvDV8yjL6BLtAkcX3mEHeLxYY28qOukAM/h9qFTpZgl7oLGyb4tA==
-----END RSA PRIVATE KEY-----
`)

	data := []byte("123456")
	password := []byte("123456")
	fmt.Println("password: ", password)
	fmt.Println("data: ", data)

	encData, err := EncryptWithPKCS1(data, publicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("EncryptWithPKCS1 result: ", encData)

	desData, err := DecryptWithPKCS1(encData, privateKey, password)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("DecryptWithPKCS1 result: ", desData)

	signData, err := SignatureWithPKCS1SHA256(data, privateKey, password)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("SignatureWithPKCS1SHA256 result: ", signData)
	fmt.Println("SignatureWithPKCS1SHA256 base64 encoding result: ", base64.StdEncoding.EncodeToString(signData))

	fmt.Println("VerifyWithPKCS1SHA256 result: ", VerifyWithPKCS1SHA256(data, signData, publicKey))
}

func TestRSAPKCS1(t *testing.T) {
	publicKey := []byte(`-----BEGIN RSA PUBLIC KEY-----
MEgCQQDWB/hMe4dsMMKfWEUxEgp6wp7BbrTn8HFagAX4LHBVRLybOKBylS2r5Xbu
znIOTF8VWSRISyRBbuoak4jpLKrtAgMBAAE=
-----END RSA PUBLIC KEY-----
`)
	privateKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANYH+Ex7h2wwwp9YRTESCnrCnsFutOfwcVqABfgscFVEvJs4oHKV
Lavldu7Ocg5MXxVZJEhLJEFu6hqTiOksqu0CAwEAAQJAUSvuoFsNDhwkA7i/bQ/R
h6M+AFBTLc/DvbXmDawU4lEgwavs591OKcIc2q41P/whxDqZDljTtRCUQeqoIqAg
QQIhAO0zDE7o5xU8/ea0hP7gc3o7Asij9VH3AIdpRrcWb8oRAiEA5v7SA8bmR71A
duR4BqtbHbltCPoPqLjcrp39K9RnVx0CIQDapZKz7naMmkNFdaOeulFYG6tOPey1
2GTRbZa00GbNsQIhAN/Y7oH0fHHmxxKwAlRMOAcNCsmZMhWJ12lr9sxDkEVNAiAl
COPeZIeJezSn6czvGhHzhQzqjEliHdzi2pm+O3akvA==
-----END RSA PRIVATE KEY-----
`)

	data := []byte("123456")
	fmt.Println("data: ", data)

	encData, err := EncryptWithPKCS1(data, publicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("EncryptWithPKCS1 result: ", encData)

	desData, err := DecryptWithPKCS1(encData, privateKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("DecryptWithPKCS1 result: ", desData)

	signData, err := SignatureWithPKCS1SHA256(data, privateKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("SignatureWithPKCS1SHA256 result: ", signData)
	fmt.Println("SignatureWithPKCS1SHA256 base64 encoding result: ", base64.StdEncoding.EncodeToString(signData))

	fmt.Println("VerifyWithPKCS1SHA256 result: ", VerifyWithPKCS1SHA256(data, signData, publicKey))
}

func TestRSAPKCS8(t *testing.T) {
	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL4qvRs7dlw2+sQClgVXKKJq96J9z8i+
iRPFQ4T9OHF/UOYpzs2TbCT71Eu2ZMC/I39/2GzYhgDQMuEDlI5zfaUCAwEAAQ==
-----END PUBLIC KEY-----
`)
	privateKey := []byte(`-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAviq9Gzt2XDb6xAKW
BVcoomr3on3PyL6JE8VDhP04cX9Q5inOzZNsJPvUS7ZkwL8jf3/YbNiGANAy4QOU
jnN9pQIDAQABAkA5C0L8x0KC+O8SGyB7a6DBz8qG0KyisB0YdCUD4J2s1Zq48lDD
LGPNUA7G92n5Um4fhyYv3C1959+ZTg6AMJPFAiEA4nVnInios4mttynQn7hux2g2
u5k26j8nbbM5DSs7Gt8CIQDW+V+/pmgfoLYKmgydeZmq/fDxtexdAJOxq2f0ZEl7
+wIhAOALEvwxr4XgonLh9brvNvolinDTRlc+H/4SIFF9Ab61AiBGNmrEcLhfZCEw
80GdiWLcS1aPy6hoc9DJXb91PfAWUwIhAMirjup9Bpk53rUHWUmgo5Cy5sQWmsPB
JyKdw8Yp1mqE
-----END PRIVATE KEY-----
`)

	data := []byte("123456")
	fmt.Println("data: ", data)

	encData, err := EncryptWithPKCS8(data, publicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("EncryptWithPKCS8 result: ", encData)

	desData, err := DecryptWithPKCS8(encData, privateKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("DecryptWithPKCS8 result: ", desData)

	signData, err := SignatureWithPKCS8SHA256(data, privateKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("SignatureWithPKCS8SHA256 result: ", signData)
	fmt.Println("SignatureWithPKCS8SHA256 base64 encoding result: ", base64.StdEncoding.EncodeToString(signData))

	fmt.Println("VerifyWithPKCS8SHA256 result: ", VerifyWithPKCS8SHA256(data, signData, publicKey))
}
