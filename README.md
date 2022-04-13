# acme-account-creation-tool

Utility to create or retrieve an account with certificate authorities that support the [Automatic Certificate Management Environment (ACME)](https://datatracker.ietf.org/doc/html/rfc8555) protocol. 

If you're working with [IBM Cloud® Secrets Manager](https://cloud.ibm.com/catalog/services/secrets-manager), you can use this tool to enable your instance to order public TLS certificates from Let's Encrypt. To learn more about ordering and managing certificates with Secrets Manager, check out the [IBM Cloud documentation](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-prepare-order-certificates). 

## Usage
1. Download a binary for your Operating System [from available Releases](https://github.com/ibm-cloud-security/acme-account-creation-tool/releases).
2. Review the following usage guidelines.

```
Usage of ./acme-account-creation-tool:
-o, --outputFilenamePrefix   file name prefix to store the account details  

[-e], [--email]  email to be registered for the account  

[-d], [--directoryURL]  acme directory URL of the CA. Following alias are defined: "letsencrypt-prod", "letsencrypt-stage"  (default letsencrypt-prod) 

[-g], [--keyTypeToGenerate]  key type to generate. Supported values - rsa2048, rsa3072, rsa4096, ec256, ec384 (default ec256) 

[-k], [--privateKeyPath]  path to the private key in PKCS1/PKCS8 PEM format to be used. If an account with this private key exists, the account will be retrieved. This flag overrides the -g flag  
```

A successful request registers a new account and stores the account credentials in `<outputFilenamePrefix>-private-key.pem`. Your account information is stored in  `<outputFilenamePrefix>-account-info.json`.

<details>
<summary><strong>Show example response</strong></summary>

```
./acme-account-creation-tool -e zoe@example.com -o my-letsencrypt -d letsencrypt-prod -k pkcs8.key

INFO[2021-09-03T14:01:34-05:00] An account for the provided private key does not exist with the CA
INFO[2021-09-03T14:01:34-05:00] Registering a new account with the CA
INFO[2021-09-03T14:01:34-05:00] Account information written to file : my-letsencrypt-account-info.json
INFO[2021-09-03T14:01:34-05:00] Private key written to file : my-letsencrypt-acct-private-key.pem

Account Info
{
	"email": "zoe@example.com",
	"registration_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123967230",
	"registration_body": {
		"status": "valid",
		"contact": [
			"mailto:zoe@example.com"
		]
	}
}
```
</details>

#### Notes

- Email address is optional, but recommended so that Let's Encrypt can send expiry notices when your certificates are coming up for renewal.
- You can choose to provide your own private key in PKCS#1 or PKCS#8 format. If a key isn't provided, the tool generates one automatically on your behalf. To specify the key type, use the `-g, --keyTypeToGenerate` flag.
- Use the private key that is generated for your new ACME account to [add a certificate authority configuration](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-add-certificate-authority) in Secrets Manager.

### Supported certificate authorities

#### [Let's Encrypt](https://letsencrypt.org/)

Create an account that targets the Let's Encrypt production environment.
```
./acme-account-creation-tool -e <email> -o my-letsencrypt -d letsencrypt-prod
```

Create an account that targets the Let's Encrypt staging environment.
```
./acme-account-creation-tool -e <email> -o my-letsencrypt -d letsencrypt-stage
```

## Manually building the ACME client

> Prerequisites: [Go version 1.15 or later](https://golang.org/doc/install).

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
    ./acme-account-creation-tool
    ```

## Questions

If you have questions about this project, you can use [Stack Overflow](https://stackoverflow.com/questions/tagged/ibm-secrets-manager). Be sure to include the `ibm-cloud` and `ibm-secrets-manager` tags. You can also check out the [Secrets Manager documentation](https://cloud.ibm.com/docs/secrets-manager) and [API reference](https://cloud.ibm.com/apidocs/secrets-manager) for more information about the service.

## Issues

If you encounter an issue with this project, you're welcome to submit a [bug report](https://github.com/ibm-cloud-security/acme-account-creation-tool/issues) to help us improve. Before you create a new issue, search for similar issues in case someone has already reported the same problem.

## License

This project is released under the Apache 2.0 license. The license's full text can be found in [LICENSE](LICENSE).
