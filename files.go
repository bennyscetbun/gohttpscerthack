package gohttpscerthack

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

var ErCertFileNotCertificateFile = fmt.Errorf("the Certificate file seems to be a non pem certificate file")
var ErrCertFileMultipleBlockDetected = fmt.Errorf("the Certificate file contains multiple blocks")
var ErrRSANotRSAPrivateKey = fmt.Errorf("The Private Key file doesn't seem to be a RSA Private key file")
var ErrRSAMultipleBlockDetected = fmt.Errorf("The Private Key file contains multiple blocks")

// ReadCertificate is a helper to read CERTIFICATE files
func ReadCertificate(filepath string) (*x509.Certificate, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block.Type != "CERTIFICATE" {
		return nil, ErCertFileNotCertificateFile
	}
	if len(rest) > 0 {
		if b, _ := pem.Decode(rest); b != nil {
			return nil, ErrCertFileMultipleBlockDetected
		}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// ReadPrivateKey is a helper to read RSA PRIVATE KEY files
func ReadPrivateKey(filepath string, password []byte) (*rsa.PrivateKey, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block.Type != "RSA PRIVATE KEY" {
		return nil, ErrRSANotRSAPrivateKey
	}
	if len(rest) > 0 {
		if b, _ := pem.Decode(rest); b != nil {
			return nil, ErrRSAMultipleBlockDetected
		}
	}
	var decryptedData []byte
	if password != nil {
		decryptedData, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}
	} else {
		decryptedData = block.Bytes
	}
	privKey, err := x509.ParsePKCS1PrivateKey(decryptedData)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}
