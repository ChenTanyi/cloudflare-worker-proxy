package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	RSA_PRIVATE_KEY_HEADER = "RSA PRIVATE KEY"
	CERTIFICATE_KEY_HEADER = "CERTIFICATE"
)

var (
	CommonName       = "mitmproxy"
	Organization     = "mitmproxy"
	RSABits          = 2048
	ErrNoPrivateKey  = errors.New("No RSA PRIVATE KEY found in ca file")
	ErrNoCertificate = errors.New("No CERTIFICATE found in ca file")

	log = logrus.WithField("at", "cert")
)

type CA struct {
	Cert         *x509.Certificate
	PrivateKey   *rsa.PrivateKey
	SerialNumber int64

	// define signed domain or ip
	mu     *sync.RWMutex
	signed *tls.Certificate
	names  map[string]struct{}
	dns    []string
	ip     []net.IP
}

func NewCA(caFile string) (*CA, error) {
	_, err := os.Stat(caFile)
	if err == nil {
		return loadCA(caFile)
	}
	if os.IsNotExist(err) {
		return createCA(caFile)
	}
	return nil, err
}

func (ca *CA) Save(w io.Writer) error {
	key := x509.MarshalPKCS1PrivateKey(ca.PrivateKey)
	err := pem.Encode(w, &pem.Block{Type: RSA_PRIVATE_KEY_HEADER, Bytes: key})
	if err != nil {
		return err
	}
	return ca.ExportCert(w)
}

func (ca *CA) SaveToFile(file string) error {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return ca.Save(f)
}

func (ca *CA) ExportCert(w io.Writer) error {
	return pem.Encode(w, &pem.Block{Type: CERTIFICATE_KEY_HEADER, Bytes: ca.Cert.Raw})
}

func (ca *CA) ExportCertToFile(file string) error {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return ca.ExportCert(f)
}

func (ca *CA) Sign(commonName string) (*tls.Certificate, error) {
	commonName = ca.calcCommonName(commonName)
	if cert := ca.getSignedCert(commonName, true); cert != nil {
		return cert, nil
	}
	return ca.signCert(commonName)
}

func (ca *CA) calcCommonName(commonName string) string {
	if ip := net.ParseIP(commonName); ip != nil {
		return commonName
	}
	dot := strings.IndexByte(commonName, '.')
	if dot > 0 {
		return "*" + commonName[dot:]
	}
	return commonName
}

func (ca *CA) signCert(commonName string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert := ca.getSignedCert(commonName, false); cert != nil {
		return cert, nil
	}

	if ip := net.ParseIP(commonName); ip == nil {
		ca.dns = append(ca.dns, commonName)
	} else {
		ca.ip = append(ca.ip, ip)
	}
	ca.names[commonName] = struct{}{}

	ca.SerialNumber++
	cert := &x509.Certificate{
		SerialNumber: (&big.Int{}).Add(ca.Cert.SerialNumber, big.NewInt(ca.SerialNumber)),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().AddDate(0, 0, -1),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:    ca.dns,
		IPAddresses: ca.ip,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &ca.PrivateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	ca.signed = &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  ca.PrivateKey,
	}
	return ca.signed, nil
}

func (ca *CA) getSignedCert(commonName string, lock bool) *tls.Certificate {
	if lock {
		ca.mu.RLock()
		defer ca.mu.RUnlock()
	}
	if _, ok := ca.names[commonName]; ok {
		return ca.signed
	}
	return nil
}

func loadCA(caFile string) (*CA, error) {
	content, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	ca := &CA{}
	for {
		var block *pem.Block
		block, content = pem.Decode(content)
		if block == nil {
			break
		}
		switch block.Type {
		case RSA_PRIVATE_KEY_HEADER:
			ca.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		case CERTIFICATE_KEY_HEADER:
			ca.Cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
		}
	}

	if ca.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}
	if ca.Cert == nil {
		return nil, ErrNoCertificate
	}
	return ca, nil
}

func createCA(caFile string) (*CA, error) {
	err := os.MkdirAll(filepath.Dir(caFile), 0755)
	if err != nil {
		return nil, err
	}

	ca := &CA{}
	privateKey, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		return nil, err
	}
	ca.PrivateKey = privateKey

	SerialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: SerialNumber,
		Subject: pkix.Name{
			CommonName:   CommonName,
			Organization: []string{Organization},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	ca.Cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return ca, ca.SaveToFile(caFile)
}
