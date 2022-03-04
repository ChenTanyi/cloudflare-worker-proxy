package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"
)

func TestNewCA(t *testing.T) {
	f, err := ioutil.TempFile("", "ca*.pem")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(f.Name())
	defer os.Remove(f.Name())

	ca1, err := NewCA(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := NewCA(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(ca1.Cert.Raw) != sha256.Sum256(ca2.Cert.Raw) {
		t.Fatal("Certificate fingerprint of two ca are different")
	}
	if sha256.Sum256(x509.MarshalPKCS1PrivateKey(ca1.PrivateKey)) != sha256.Sum256(x509.MarshalPKCS1PrivateKey(ca2.PrivateKey)) {
		t.Fatal("PrivateKey fingerprint of two ca are different")
	}
}

func TestSignCert(t *testing.T) {
	f, err := ioutil.TempFile("", "ca*.pem")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(f.Name())
	defer os.Remove(f.Name())

	ca, err := NewCA(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	dns := "github.com"
	tlsCert, err := ca.Sign(dns)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.DNSNames[0] != dns {
		t.Fatalf("Unexpected cert dns %s", dns)
	}

	dns = "1.1.1.1"
	tlsCert, err = ca.Sign(dns)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if (cert.IPAddresses[0]).String() != dns {
		t.Fatalf("Unexpected cert ip %s", dns)
	}

	dns = "www.google.com"
	tlsCert, err = ca.Sign(dns)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	dns = "*.google.com"
	if cert.DNSNames[1] != dns {
		t.Fatalf("Unexpected cert dns %s", dns)
	}
}
