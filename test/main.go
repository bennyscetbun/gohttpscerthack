package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/bennyscetbun/gohttpscerthack"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s cert_file private_rsa_key_file\n", os.Args[0])
	os.Exit(2)
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	serverTLSConf, err := gohttpscerthack.GetTLSConfigWithIPs(os.Args[1], os.Args[2], nil)
	// set up the httptest.Server using our certificate signed by our CA
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success!")
	}))
	server.TLS = serverTLSConf
	server.StartTLS()
	defer server.Close()

	// communicate with the server using an http.Client configured to trust our CA
	transport := &http.Transport{
		TLSClientConfig: getClientConf(),
	}
	http := http.Client{
		Transport: transport,
	}
	//resp, err := http.Get("https://localhost" + server.URL[strings.LastIndex(server.URL, ":"):])
	resp, err := http.Get(server.URL)
	if err != nil {
		panic(err)
	}

	// verify the response
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body == "success!" {
		fmt.Println(body)
	} else {
		panic("not successful!")
	}
}

func getClientConf() *tls.Config {
	ca, err := gohttpscerthack.ReadCertificate(os.Args[1])
	if err != nil {
		panic(err)
	}

	caPrivKey, err := gohttpscerthack.ReadPrivateKey(os.Args[2], nil)
	if err != nil {
		panic(err)
	}

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

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	return &tls.Config{
		RootCAs: certpool,
	}
}
