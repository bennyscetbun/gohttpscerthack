package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s ouput_cert_file output_rsa_private_key_file [output_client_cert]\n", os.Args[0])
	os.Exit(2)
}

func exitWithError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s\n%+v\n", msg, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Fake Certificate Corporation"},
			Country:      []string{"FR"},
			Province:     []string{""},
			Locality:     []string{"montcuq"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		exitWithError("Cant generate RSA KEY", err)
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		exitWithError("Cant generate CERTIFICATE", err)
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	{
		f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			exitWithError(fmt.Sprint("Cant Open file", os.Args[1]), err)
		}
		if _, err := f.Write(caPEM.Bytes()); err != nil {
			exitWithError(fmt.Sprint("Cant Write to file", os.Args[1]), err)
		}
		f.Close()
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	{
		f, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			exitWithError(fmt.Sprint("Cant Open file", os.Args[2]), err)
		}
		if _, err := f.Write(caPrivKeyPEM.Bytes()); err != nil {
			exitWithError(fmt.Sprint("Cant Write to file", os.Args[2]), err)
		}
		f.Close()
	}

	if len(os.Args) > 3 {
		// create the CA
		caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			panic(err)
		}

		// pem encode
		caPEM := new(bytes.Buffer)
		pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		{
			f, err := os.OpenFile(os.Args[3], os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				exitWithError(fmt.Sprint("Cant Open file", os.Args[3]), err)
			}
			if _, err := f.Write(caPEM.Bytes()); err != nil {
				exitWithError(fmt.Sprint("Cant Write to file", os.Args[3]), err)
			}
			f.Close()
		}
	}
}
