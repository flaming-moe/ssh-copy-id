package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

/*
var rawPubKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtjdLkS+FP+0fPC09j25\ny/PiuYDDivIT86COVedvlElk99BBYTrqNaJybxjXbIZ1Q6xFNhOY+iTcBr4E1zJu\ntizF3Xi0V9tOuP/M8Wn4Y/1lCWbQKlWrNQuqNBmhovF4K3mDCYswVbpgTmp+JQYu\nBm9QMdieZMNry5s6aiMA9aSjDlNyedvSENYo18F+NYg1J0C0JiPYTxheCb4optr1\n5xNzFKhAkuGs4XTOA5C7Q06GCKtDNf44s/CVE30KODUxBi0MCKaxiXw/yy55zxX2\n/YdGphIyQiA5iO1986ZmZCLLW8udz9uhW5jUr3Jlp9LbmphAC61bVSf4ou2YsJaN\n0QIDAQAB\n-----END PUBLIC KEY-----"
var rawSignature = "c2pkYWpuY2sgZmphbm9panF3b2lqYWRvbmFzbWQgc2EsbWMgc2FuZHBvZHA5cTN1cjA5M3Vyajg4OUoocHEqaDlIUkZKU0ZLQkZPSDk4"
var message = "authenticmessage"
*/

func CheckPEM(rawPubKey string, rawSignature string, message string) error {

	block, _ := pem.Decode([]byte(rawPubKey))
	if block == nil {
		return fmt.Errorf("invalid PEM Block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	pubKey := key.(*rsa.PublicKey)

	signature, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		return err
	}

	hash := sha1.Sum([]byte(message))

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash[:], signature)
	if err != nil {
		return err
	}
	return nil
}
