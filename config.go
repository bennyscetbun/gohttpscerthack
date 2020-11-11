package gohttpscerthack

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
)

// GetTLSConfig returns a tls.Config with the GetCertificate and Certificate set to generate signed certificate for any host with the certificate in argument
// BEWARE that if you use an ip to contact your server and not a FQDM, it will fail
func GetTLSConfig(caCertificatePath, caRSAPrivateKeyPath string, password []byte) (*tls.Config, error) {
	return GetTLSConfigWithManualIPs(caCertificatePath, caRSAPrivateKeyPath, password)
}

// GetTLSConfigFromMemory same as GetTLSConfig but use already in memory certificate and private rsa key
// BEWARE that if you use an ip to contact your server and not a FQDM, it will fail
func GetTLSConfigFromMemory(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) (*tls.Config, error) {
	return GetTLSConfigFromMemoryWithManualIPs(ca, caPrivKey)
}

// GetTLSConfigWithIPs same as GetTLSConfig but it will automatically find the current host IPS and will generate also a signed certificate for your IPs
func GetTLSConfigWithIPs(caCertificatePath, caRSAPrivateKeyPath string, password []byte) (*tls.Config, error) {
	ips, err := GetLocalIPs()
	if err != nil {
		return nil, err
	}
	return GetTLSConfigWithManualIPs(caCertificatePath, caRSAPrivateKeyPath, password, ips...)
}

// GetTLSConfigFromMemoryWithIPs same as GetTLSConfigFromMemory but it will automatically find the current host IPS and will generate also a signed certificate for your IPs
func GetTLSConfigFromMemoryWithIPs(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) (*tls.Config, error) {
	ips, err := GetLocalIPs()
	if err != nil {
		return nil, err
	}
	return GetTLSConfigFromMemoryWithManualIPs(ca, caPrivKey, ips...)
}

// GetTLSConfigWithManualIPs same as GetTLSConfigWithIPs but you will need to provide the IP you want the a signed certificate for.
// not giving any ip is equal to call GetTLSConfig
func GetTLSConfigWithManualIPs(caCertificatePath, caRSAPrivateKeyPath string, password []byte, ips ...net.IP) (*tls.Config, error) {
	cert, err := ReadCertificate(caCertificatePath)
	if err != nil {
		return nil, err
	}
	key, err := ReadPrivateKey(caRSAPrivateKeyPath, password)
	if err != nil {
		return nil, err
	}
	return GetTLSConfigFromMemoryWithManualIPs(cert, key, ips...)
}

// GetTLSConfigFromMemoryWithManualIPs same as GetTLSConfigFromMemoryWithIPs but you will need to provide the IP you want the a signed certificate for.
// not giving any ip is equal to call GetTLSConfigFromMemory
func GetTLSConfigFromMemoryWithManualIPs(ca *x509.Certificate, caPrivKey *rsa.PrivateKey, ips ...net.IP) (*tls.Config, error) {
	certCache := map[string]*tls.Certificate{}
	mut := sync.RWMutex{}
	certGenerator := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mut.RLock()
		if cert, ok := certCache[info.ServerName]; ok {
			mut.RUnlock()
			return cert, nil
		}
		mut.Lock()
		defer mut.Unlock()
		if cert, ok := certCache[info.ServerName]; ok {
			return cert, nil
		}
		// set up our server certificate
		cert := getDefaultCert()
		cert.DNSNames = []string{info.ServerName}
		signedCert, err := generateSignedCert(cert, ca, caPrivKey)
		if err != nil {
			return nil, err
		}
		certCache[info.ServerName] = signedCert
		return signedCert, nil
	}
	serverTLSConf := &tls.Config{
		GetCertificate: certGenerator,
	}

	if len(ips) > 0 {
		cert := getDefaultCert()
		cert.IPAddresses = ips
		signedCert, err := generateSignedCert(cert, ca, caPrivKey)
		if err != nil {
			return nil, err
		}
		serverTLSConf.Certificates = []tls.Certificate{*signedCert}
	}
	return serverTLSConf, nil
}
