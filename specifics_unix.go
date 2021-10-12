// +build aix darwin dragonfly freebsd js,wasm linux nacl netbsd openbsd solaris

package main

import (
	"crypto/x509"
	"errors"
	"golang.org/x/sys/unix"
	"io/ioutil"
)

// loadRootCertPool builds a trust store (cert pool) containing our CA's root
// certificate.
func loadRootCertPool(rootCertPath string) (*x509.CertPool, error) {

	pool, err := x509.SystemCertPool()
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
	umask := unix.Umask(0)
	defer unix.Umask(umask)

	err := ioutil.WriteFile(outputFileName, []byte(privateKeyPEM), 0600)
	if err != nil{
		return err
	}

	return nil
}


