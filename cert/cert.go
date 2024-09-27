package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"time"
)

type CertificateWithPrivate struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func CreateCA(folder string) (CertificateWithPrivate, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:  []string{"Artem Zhuk"},
			Country:       []string{"RU"},
			Province:      []string{""},
			Locality:      []string{"Moscow"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
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
		return CertificateWithPrivate{}, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return CertificateWithPrivate{}, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	caFile, err := os.Create(folder + "/ca.crt")
	defer caFile.Close()
	if err != nil {
		return CertificateWithPrivate{}, err
	}
	caPEM.WriteTo(caFile)

	caPrivFile, err := os.Create(folder + "/ca-PRIVATE.key")
	defer caPrivFile.Close()
	if err != nil {
		return CertificateWithPrivate{}, err
	}
	caPrivKeyPEM.WriteTo(caPrivFile)

	cert := CertificateWithPrivate{
		Certificate: ca,
		PrivateKey:  caPrivKey,
	}

	return cert, nil
}

func OpenCert(path string) (CertificateWithPrivate, error) {
	caByte, err := os.ReadFile(path + ".crt")
	if err != nil {
		return CertificateWithPrivate{}, err
	}
	pemCA, _ := pem.Decode(caByte)

	ca, err := x509.ParseCertificate(pemCA.Bytes)
	if err != nil {
		return CertificateWithPrivate{}, err
	}

	privateByte, err := os.ReadFile(path + "-PRIVATE.key")
	if err != nil {
		return CertificateWithPrivate{}, err
	}
	pemPrivate, _ := pem.Decode(privateByte)
	key, err := x509.ParsePKCS1PrivateKey(pemPrivate.Bytes)
	if err != nil {
		return CertificateWithPrivate{}, err
	}
	return CertificateWithPrivate{
		Certificate: ca,
		PrivateKey:  key,
	}, nil

}

func CreateCert(host string, ca CertificateWithPrivate, folder string) (CertificateWithPrivate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			CommonName: strings.ReplaceAll(host, "-", "."),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return CertificateWithPrivate{}, nil
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Certificate, &certPrivKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return CertificateWithPrivate{}, nil
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	nameReplaced := strings.ReplaceAll(host, ".", "-")
	certFile, err := os.Create(folder + "/" + nameReplaced + ".crt")
	defer certFile.Close()
	if err != nil {
		return CertificateWithPrivate{}, nil
	}
	certPEM.WriteTo(certFile)

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	certPrivFile, err := os.Create(folder + "/" + nameReplaced + "-PRIVATE.key")
	defer certPrivFile.Close()
	if err != nil {
		return CertificateWithPrivate{}, nil
	}
	certPrivKeyPEM.WriteTo(certPrivFile)

	/*serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs: certpool,
	}*/

	return CertificateWithPrivate{
		Certificate: cert,
		PrivateKey:  certPrivKey,
	}, nil
}

/*func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
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
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs: certpool,
	}

	return
}
*/
