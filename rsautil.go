package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func RsaConfigSetup(rsaPrivateKeyLocation, rsaPublicKeyLocation string) (*rsa.PrivateKey, error) {
	if rsaPrivateKeyLocation == "" {
		log.Print("No RSA Key given, generating temp one")
		return generatePrivateKey(4096)
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.Print("No RSA private key found, generating temp one")
		return generatePrivateKey(4096)
	}

	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		log.Printf("RSA private key is of the wrong type :%s", privPem.Type)
	}
	privPemBytes = privPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			log.Printf("Unable to parse RSA private key, generating a temp one :%s", err.Error())
			return generatePrivateKey(4096)
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Printf("Unable to parse RSA private key, generating a temp one : %s", err.Error())
		return generatePrivateKey(4096)
	}

	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.Print("No RSA public key found, generating temp one")
		return generatePrivateKey(4096)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		log.Printf("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public :rsa public key not in pem format: %s", rsaPublicKeyLocation)
		return generatePrivateKey(4096)
	}
	if pubPem.Type != "RSA PUBLIC KEY" {
		log.Printf("RSA public key is of the wrong type, Pem Type :%s", pubPem.Type)
		return generatePrivateKey(4096)
	}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		log.Printf("Unable to parse RSA public key, generating a temp one: %s", err.Error())
		return generatePrivateKey(4096)
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		log.Printf("Unable to parse RSA public key, generating a temp one: %s", err.Error())
		return generatePrivateKey(4096)
	}

	privateKey.PublicKey = *pubKey

	return privateKey, nil
}

// generatePrivateKey returns a new RSA key of bits length
func generatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	log.Printf("Failed to generate signing key :%s", err.Error())
	return key, err
}
