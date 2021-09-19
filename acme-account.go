package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	legoLogger "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
	"io/ioutil"
	systemLog "log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	outputPrivateKeyFileNameSuffix  = "-private-key.pem"
	outputAccountInfoFileNameSuffix = "-account-info.json"

	directoryURLFlag          = "directoryURL"
	emailFlag                 = "email"
	caCertPathFlag            = "caRootCertPath"
	outputFileNamePrefixFlag  = "outputFilenamePrefix"
	privateKeyPathFlag        = "privateKeyPath"
	eabKeyIDFlag              = "eabKeyIDFlag"
	eabHMACKeyFlag            = "eabHMACKeyFlag"
	keyTypeToGenerateFlag     = "keyTypeToGenerate"

	rsa2048                   = "rsa2048"
	rsa3072                   = "rsa3072"
	rsa4096                   = "rsa4096"
	ec256                     = "ec256"
	ec384                     = "ec384"
)

var directoryAlias  = map[string]string {
	"letsencrypt-stage": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"letsencrypt-prod": "https://acme-v02.api.letsencrypt.org/directory",
}

type KeyType string

const (
	EC256   = KeyType("P256")
	EC384   = KeyType("P384")
	RSA2048 = KeyType("2048")
	RSA3072 = KeyType("3072")
	RSA4096 = KeyType("4096")
)

type AccountConfig struct {
	Email                   string
	CARootCertPath          string
	DirectoryURL            string
	Registration            *registration.Resource
	key                     crypto.PrivateKey
	isKeyGenerated          bool
	Provider                string
	TermsOfServiceAgreed    bool
	EabKeyID             	string
	EabHMACKey           	string
}

type OutputDataFormat struct {
	Email            string       `json:"email"`
	RegistrationURI  string       `json:"registration_uri"`
	RegistrationBody acme.Account `json:"registration_body"`
}

func (c *AccountConfig) GetEmail() string {
	return c.Email
}

func (c *AccountConfig) GetRegistration() *registration.Resource {
	return c.Registration
}

func (c *AccountConfig) GetPrivateKey() crypto.PrivateKey {
	return c.key
}

func GetKeyTypeFromString(keyType string) (KeyType, error) {
	switch keyType {
	case rsa2048:
		return RSA2048, nil
	case rsa3072:
		return RSA3072, nil
	case rsa4096:
		return RSA4096, nil
	case ec256:
		return EC256, nil
	case ec384:
		return EC384, nil
	default:
		return "", errors.New(fmt.Sprintf("invalid key type %s",keyType))
	}
}

func GeneratePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	switch keyType {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}

	return nil, fmt.Errorf("invalid KeyType: %s", keyType)
}

func DecodePrivateKey(pemEncoded string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, fmt.Errorf("nil block when decoding private key PEM")
	}
	x509Encoded := block.Bytes

	var privateKey crypto.PrivateKey
	var err error

	if block.Type == "PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS8PrivateKey(x509Encoded)
		if err == nil {
			switch privateKey.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
			default:
				err = fmt.Errorf("unknown private key type in PKCS#8 wrapping")
			}
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(x509Encoded)
	} else if  block.Type == "EC PRIVATE KEY" {
		privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	} else {
		err = fmt.Errorf("private key should be in unencrypted PKCS#1 or PKCS#8 format")
	}

	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func EncodePrivateKeyToPKCS8PEM(privateKey crypto.PrivateKey) (string, error){
	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})
	return string(pemEncoded), nil
}

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

// ImportOrGeneratePrivateKey will construct a private key from the importKeyPath if it is not empty
// Otherwise, it will generate a private key of type keyTypeString
func ImportOrGeneratePrivateKey(importKeyPath , keyTypeString string) (crypto.PrivateKey, bool, error){
	var privateKey crypto.PrivateKey
	var isKeyGenerated bool

	if importKeyPath != "" {
		privateKeyPEM, err := ReadPrivateKeyPEMFromFile(importKeyPath)
		if err != nil {
			return nil, false, err
		}
		privateKey, err = DecodePrivateKey(privateKeyPEM)
		if err != nil {
			return nil, false, err
		}
		isKeyGenerated = false

	} else {
		keyType, err := GetKeyTypeFromString(keyTypeString)
		if err != nil {
			return nil, false, err
		}
		privateKey, err = GeneratePrivateKey(keyType)
		if err != nil {
			return nil, false, err
		}
		isKeyGenerated = true
	}

	return privateKey, isKeyGenerated, nil
}

// getHTTPSClient gets an HTTPS client configured to trust our CA's root
// certificate.
func getHTTPSClient(rootCertPath string) (*http.Client, error) {
	pool, err := loadRootCertPool(rootCertPath)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			RootCAs:                  pool,
		},
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.New("Error configuring transport")
	}
	return &http.Client{
		Transport: tr,
	}, nil
}

type Client struct {
	LegoClient *lego.Client
}

// RegisterAccount This will register a new account.
// From here - https://letsencrypt.org/docs/account-id/
// "If your ACME client does not record the account ID, you can retrieve it by submitting a new registration request with the same key"
// ACME SPEC - https://tools.ietf.org/html/rfc8555#section-7.3
// If the private key does not correspond to an existing account, then a new account will be created!
func (client *Client) RegisterAccount(accountConfig *AccountConfig) error {
	if accountConfig == nil {
		return fmt.Errorf("nil account config")
	}

	var reg *registration.Resource
	var err error

	if accountConfig.EabKeyID == "" || accountConfig.EabHMACKey == "" {
		reg, err = client.LegoClient.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: accountConfig.TermsOfServiceAgreed})
	} else {
		reg, err = client.LegoClient.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: accountConfig.TermsOfServiceAgreed,
			Kid:                  accountConfig.EabKeyID,
			HmacEncoded:          accountConfig.EabHMACKey})
	}
	if err != nil {
		return err
	}
	accountConfig.Registration = reg
	return nil
}

// RetrieveAccount This will retrieve the account information using the private key (passed through account config) registered with the ACME server
// and then set the registration resource to the account config
// https://tools.ietf.org/html/rfc8555#section-7.3
func (client *Client) RetrieveAccount(accountConfig *AccountConfig) error {

	var retrievedAccount *registration.Resource
	var err error

	if accountConfig.EabKeyID == "" || accountConfig.EabHMACKey == "" {
		retrievedAccount, err = client.LegoClient.Registration.ResolveAccountByKey()
	} else {
		retrievedAccount, err = client.LegoClient.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: accountConfig.TermsOfServiceAgreed,
			Kid:                  accountConfig.EabKeyID,
			HmacEncoded:          accountConfig.EabHMACKey})
	}

	if err != nil {
		return err
	}

	email, err := ExtractFirstEmailFromAccount(retrievedAccount)
	if err != nil {
		return err
	}

	accountConfig.Registration = retrievedAccount
	accountConfig.Email = email

	return nil
}

func (client *Client) QueryRegistration() (*registration.Resource, error) {
	return client.LegoClient.Registration.QueryRegistration()
}

func CreateAccountIfNotExists(accountConfig *AccountConfig) error {

	client, err := NewACMEClient(accountConfig)
	if err != nil {
		return err
	}

	if !accountConfig.isKeyGenerated {
		err = client.RetrieveAccount(accountConfig)
		if err != nil {
			log.Printf("An account for the provided private key does not exist with the CA")
		} else {
			log.Printf("An account for the provided private key exists and has been successfully retrieved from the CA")
			return nil
		}
	}
	log.Printf("Registering a new account with the CA")
	err = client.RegisterAccount(accountConfig)
	if err != nil {
		return err
	}

	return nil
}

func NewACMEClient(accountConfig *AccountConfig) (*Client, error){

	if accountConfig == nil {
		return nil, fmt.Errorf("nil account config")
	}

	// Get an HTTPS client configured to trust our root certificate.
	httpClient, err := getHTTPSClient(accountConfig.CARootCertPath)
	if err != nil {
		return nil, err
	}

	legoConfig := &lego.Config{
		CADirURL:   accountConfig.DirectoryURL,
		User:       accountConfig,
		HTTPClient: httpClient,
		Certificate: lego.CertificateConfig {
			KeyType: certcrypto.RSA4096,
			Timeout: 30 * time.Second,
		},
	}
	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}
	return &Client{LegoClient: legoClient}, nil
}


func ExitIfStringFlagNotProvided(flagName string, value string) {
	flagValues := flag.Lookup(flagName)
	if value == ""{
		flag.Usage()
		log.Fatalf("No %s provided \n", flagValues.Name)
	}
}

func IsFileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func ReadPrivateKeyPEMFromFile(filename string) (string, error){
	privateKeyPEMBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	privateKeyPEM := string(privateKeyPEMBytes)
	return privateKeyPEM, nil

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

func GetSerializedAccountInfo(email string, registrationInfo *registration.Resource )  (string, error) {
	outputDataFormat := OutputDataFormat{
		Email:            email,
		RegistrationURI:  registrationInfo.URI,
		RegistrationBody: registrationInfo.Body,
	}

	outputData, err := json.MarshalIndent(outputDataFormat, "", "\t")
	if err != nil {
		return "", err
	}

	return string(outputData),nil
}

func WriteAccountInfoToFile(outputFileName, serializedAccountInfo string) error {
	f, err := os.Create(outputFileName)
	if err != nil {
		return err
	}

	accountInfoBytes := []byte(serializedAccountInfo)

	_, err = f.Write(accountInfoBytes)
	if err != nil {
		_ = f.Close()
		return err
	}

	return f.Close()
}

func UsageString (shortname, name, usage, defaultValue string, optional bool) string{
	if optional {
		if len(defaultValue) > 0 {
			return fmt.Sprintf("[-%s], [--%s]  %s (default %s)", shortname, name, usage, defaultValue)
		} else {
			return fmt.Sprintf("[-%s], [--%s]  %s ", shortname, name, usage)
		}
	} else {
		return fmt.Sprintf("-%s, --%s   %s ", shortname, name, usage)
	}
}

func ExtractFirstEmailFromAccount(retrievedAccount *registration.Resource) (string, error) {
	if retrievedAccount == nil {
		return "", fmt.Errorf("retrieved account is nil")
	}
	for _, contact := range retrievedAccount.Body.Contact {
		if strings.HasPrefix(contact, "mailto:") {
			email := strings.TrimPrefix(contact, "mailto:")
			return email, nil
		}
	}
	return "", nil
}

func ConfigureUsage(){
	directoryURLFlagInternal := flag.Lookup(directoryURLFlag)
	emailFlagInternal := flag.Lookup(emailFlag)
	caCertPathFlagInternal := flag.Lookup(caCertPathFlag)
	outputFileNamePrefixFlagInternal := flag.Lookup(outputFileNamePrefixFlag)
	privateKeyPathFlagInternal := flag.Lookup(privateKeyPathFlag)
	eabKeyIDFlagInternal := flag.Lookup(eabKeyIDFlag)
	eabHMACKeyFlagInternal := flag.Lookup(eabHMACKeyFlag)
	keyTypeToGenerateFlagInternal := flag.Lookup(keyTypeToGenerateFlag)

	flag.Usage = func() {

		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			outputFileNamePrefixFlagInternal.Shorthand,
			outputFileNamePrefixFlagInternal.Name,
			outputFileNamePrefixFlagInternal.Usage,
			outputFileNamePrefixFlagInternal.DefValue,
			false) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			emailFlagInternal.Shorthand,
			emailFlagInternal.Name,
			emailFlagInternal.Usage,
			emailFlagInternal.DefValue,
			true) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			directoryURLFlagInternal.Shorthand,
			directoryURLFlagInternal.Name,
			directoryURLFlagInternal.Usage,
			directoryURLFlagInternal.DefValue,
			true) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			keyTypeToGenerateFlagInternal.Shorthand,
			keyTypeToGenerateFlagInternal.Name,
			keyTypeToGenerateFlagInternal.Usage,
			keyTypeToGenerateFlagInternal.DefValue,
			true) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			privateKeyPathFlagInternal.Shorthand,
			privateKeyPathFlagInternal.Name,
			privateKeyPathFlagInternal.Usage,
			privateKeyPathFlagInternal.DefValue,
			true) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			caCertPathFlagInternal.Shorthand,
			caCertPathFlagInternal.Name,
			caCertPathFlagInternal.Usage,
			caCertPathFlagInternal.DefValue,
			true) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			eabKeyIDFlagInternal.Shorthand,
			eabKeyIDFlagInternal.Name,
			eabKeyIDFlagInternal.Usage,
			eabKeyIDFlagInternal.DefValue,
			true) )

		fmt.Fprintf(os.Stderr, "%s \n\n", UsageString(
			eabHMACKeyFlagInternal.Shorthand,
			eabHMACKeyFlagInternal.Name,
			eabHMACKeyFlagInternal.Usage,
			eabHMACKeyFlagInternal.DefValue,
			true) )

	}
}

func main() {
	// Disable lego logger
	legoLogger.Logger = systemLog.New(ioutil.Discard,"", systemLog.LstdFlags)

	log.SetFormatter(&log.TextFormatter{DisableColors: false, FullTimestamp: true})

	directoryURL := flag.StringP(directoryURLFlag, "d" ,"letsencrypt-prod", "acme directory URL of the CA. Following alias are defined: \"letsencrypt-prod\", \"letsencrypt-stage\" " )
	email := flag.StringP(emailFlag,"e","", "email to be registered for the account" )
	privateKeyPath := flag.StringP(privateKeyPathFlag, "k", "", "path to the private key in PKCS1/PKCS8 PEM format to be used. If an account with this private key exists, the account will be retrieved. This flag overrides the -g flag")
	//caRootCertPath := flag.StringP(caCertPathFlag, "c", "", "path to a custom CA root certificate. Only required for private/testing ACME CA's like pebble")
	//outputFilenamePrefix := flag.StringP(outputFileNamePrefixFlag, "o", "", "file name prefix to store the account details")
	//eabKeyID :=  flag.StringP(eabKeyIDFlag, "i", "", "key ID for external account binding")
	//eabHMACKey :=  flag.StringP(eabHMACKeyFlag, "h", "", "HMAC key for external account binding")
	keyTypeToGenerate :=  flag.StringP(keyTypeToGenerateFlag, "g", "ec256", fmt.Sprintf("key type to generate. Supported values - %s, %s, %s, %s, %s", rsa2048, rsa3072, rsa4096, ec256, ec384))

	ConfigureUsage()
	flag.Parse()

	ExitIfStringFlagNotProvided(outputFileNamePrefixFlag, *outputFilenamePrefix)

	privateKeyOutputFilename := *outputFilenamePrefix + outputPrivateKeyFileNameSuffix
	if IsFileExists(privateKeyOutputFilename){
		log.Fatalf("File already exists: %s ", privateKeyOutputFilename)
	}
	accountInfoOutputFilename := *outputFilenamePrefix + outputAccountInfoFileNameSuffix
	if IsFileExists(accountInfoOutputFilename){
		log.Fatalf("File already exists: %s", accountInfoOutputFilename)
	}

	if val, ok := directoryAlias[*directoryURL]; ok {
		*directoryURL = val
	}

	privateKey, isKeyGenerated, err := ImportOrGeneratePrivateKey(*privateKeyPath, *keyTypeToGenerate)
	if err != nil {
		log.Fatal(err)
	}

	accountConfig := &AccountConfig{
		Email:                *email,
		DirectoryURL:         *directoryURL,
		CARootCertPath:       *caRootCertPath,
		key:                  privateKey,
		isKeyGenerated:       isKeyGenerated,
		TermsOfServiceAgreed: true,
		EabKeyID: 			  *eabKeyID,
		EabHMACKey: 		  *eabHMACKey,
	}

	err = CreateAccountIfNotExists(accountConfig)
	if err != nil {
		log.Fatal(err)
	}

	outputPrivateKeyPEM, err := EncodePrivateKeyToPKCS8PEM(accountConfig.key)
	if err != nil {
		log.Fatal(err)
	}

	serializedAccountInfo, err := GetSerializedAccountInfo(accountConfig.GetEmail(), accountConfig.GetRegistration())
	if err != nil {
		log.Fatal(err)
	}
	err = WriteAccountInfoToFile(accountInfoOutputFilename, serializedAccountInfo)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Account information written to file : %s", accountInfoOutputFilename)

	err = WritePrivateKeyToFile(privateKeyOutputFilename, outputPrivateKeyPEM)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Private key written to file : %s", privateKeyOutputFilename)

	fmt.Printf("\nAccount Info \n%s", serializedAccountInfo)
}
