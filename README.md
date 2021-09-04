# acme-account-creation-tool

Utility to create or retrieve an account with certificate authorities that support the [Automatic Certificate Management Environment (ACME)](https://datatracker.ietf.org/doc/html/rfc8555) protocol. 

If you're working with [IBM Cloud® Secrets Manager](https://cloud.ibm.com/catalog/services/secrets-manager), you can use this tool to help you set up certificate ordering for your service instance. 

![The image shows the example output for this utility.](images/acme-account-example.svg)

To learn more about ordering and managing certificates with Secrets Manager, check out the [IBM Cloud documentation](https://cloud.ibm.com/docs/secrets-manager). 


## Prerequisites

- [Download and install Go](https://golang.org/doc/install).
- Create a private key in PKCS#8 format to provide as the credential for your certificate authority account.

    You can use the `openssl` utility to generate a private key. For example: 

    ```
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
    ```

    For more information, check out the [OpenSSL documentation](https://www.openssl.org/docs/man1.0.2/man1/openssl-pkcs8.html). 

## Installation

1. Clone or download the repository.

    ```
    git clone https://github.com/ibm-cloud-security/acme-account-creation-tool.git
    ```
2. Compile the repository contents.

    ```
    go build
    ```
3. Run the utility to ensure that it was installed successfully.

    ```
    ./acme-account
    ```

## Usage

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
 
A successful request registers a new account and stores the account credentials in `<outputFilenamePrefix>-private-key.pem`. Your account information is stored in  `<outputFilenamePrefix>-account-info.json`.


Use the private key that is generated for your account to [add a certificate authority configuration](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-ca-config) in Secrets Manager.


### Supported certificate authorities

#### [Let's Encrypt](https://letsencrypt.org/)

Create an account that targets the Let's Encrypt production environment.
```
./acme-account -e <email> -o my-letsencrypt -d letsencrypt-prod -k pkcs8.key
```

Create an account that targets the Let's Encrypt staging environment.
```
./acme-account -e <email> -o my-letsencrypt-d letsencrypt-stage -k pkcs8.key
```

## Questions

If you have questions about this project, you can use [Stack Overflow](https://stackoverflow.com/questions/tagged/ibm-secrets-manager). Be sure to include the `ibm-cloud` and `ibm-secrets-manager` tags. You can also check out the [Secrets Manager documentation](https://cloud.ibm.com/docs/secrets-manager) and [API reference](https://cloud.ibm.com/apidocs/secrets-manager) for more information about the service.

## Issues

If you encounter an issue with this project, you're welcome to submit a [bug report](https://github.com/ibm-cloud-security/acme-account-creation-tool/issues) to help us improve. Before you create a new issue, search for similar issues in case someone has already reported the same problem.

## License

This project is released under the Apache 2.0 license. The license's full text can be found in [LICENSE](LICENSE).