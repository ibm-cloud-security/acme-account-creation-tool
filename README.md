# acme-account-creation-tool

Utility to create/retrieve an account with CA's supporting the acme protocol

It supports the following flags:

```
Usage of ./acme-account:
-e, --email   email to be registered for the account  

-o, --outputFilenamePrefix   file name prefix to store the account details  

[-d], [--directoryURL]  acme directory URL of the CA. Following alias are defined: "letsencrypt-prod", "letsencrypt-stage"  (default letsencrypt-prod) 

[-k], [--privateKeyPath]  path to the private key in PKCS8 PEM format to be used. If an account with this private key exists, the account will be retrieved  

[-c], [--caRootCertPath]  path to a custom CA root certificate. Only required for private/testing ACME CA's like pebble  

[-i], [--eabKeyIDFlag]  key ID for external account binding  

[-h], [--eabHMACKeyFlag]  HMAC key for external account binding  

```

The account private key will be stored in `<outputFilenamePrefix>-private-key.pem` &
the account information will be stored in `<outputFilenamePrefix>-account-info.json`


## Different CA examples

### [letsencrypt](https://letsencrypt.org/)
```
./acme-account -d letsencrypt-prod -e <email> -o letsencrypt
```

### [buypass](https://www.buypass.com/)
```
./acme-account -e <email> -d "https://api.buypass.com/acme/directory" -o buypass
```

### [ssl.com](https://www.ssl.com/)
- Follow the instructions [here](https://www.ssl.com/guide/ssl-tls-certificate-issuance-and-revocation-with-acme/#ftoc-heading-2) to get SSL.com ACME/account key and the HMAC key
- Create an account with the following  
```
./acme-account -e <email> -o sslcom -d "https://acme.ssl.com/sslcom-dv-rsa" -i <ACME key> -h <HMAC Key>
```

### [zerossl.com](https://zerossl.com/)
- Follow the instructions [here](https://zerossl.com/documentation/acme/) to generate the EAB Key ID and the EAB HMAC Key
- Create an account with the following
```
./acme-account -e <email> -o zerosslcom -d "https://acme.zerossl.com/v2/DV90" -i <Key ID> -h <HMAC Key>
```
