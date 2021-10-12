package main

import (
	"crypto/x509"
	"fmt"
	"errors"
	"io/ioutil"
	"syscall"
	"unsafe"
)
const CRYPT_E_NOT_FOUND = 0x80092004

// This code adapted from https://github.com/golang/go/issues/16736#issuecomment-540373689.
func WindowsSystemRoots() (*x509.CertPool, error) {
	storeHandle, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("Root"))
	if err != nil {
		return nil, fmt.Errorf("could not open system cert store: %w", syscall.GetLastError())
	}

	certPool := x509.NewCertPool()
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(storeHandle, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == CRYPT_E_NOT_FOUND {
					break
				}
			}
			return nil, fmt.Errorf("could not enumerate certificates: %w", syscall.GetLastError())
		}
		if cert == nil {
			break
		}
		// Copy the buf, since ParseCertificate does not create its own copy.
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			certPool.AddCert(c)
		}
	}
	return certPool, nil
}

// loadRootCertPool builds a trust store (cert pool) containing our CA's root
// certificate.
func loadRootCertPool(rootCertPath string) (*x509.CertPool, error) {

	pool, err := WindowsSystemRoots()
	if err != nil {
		return nil, errors.New("cannot load system certs")
	}

	if rootCertPath != "" {
		root, err := ioutil.ReadFile(rootCertPath)
		if err != nil {
			return nil, err
		}
		if ok := pool.AppendCertsFromPEM(root); !ok {
			return nil, errors.New("missing or invalid root certificate")
		}
	}

	return pool, nil
}

func WritePrivateKeyToFile(outputFileName, privateKeyPEM string) error {

	err := ioutil.WriteFile(outputFileName, []byte(privateKeyPEM), 0600)
	if err != nil{
		return err
	}

	return nil
}