# aws-instance-identity-certificates
## Overview

`aws-instance-identity-certificates` is an npm module that provides utilities for working with AWS instance identity documents and certificates. It helps in verifying the identity of EC2 instances and ensures secure communication between services.

The verification process is taken from the AWS documentation: [Verify the instance identity document for an Amazon EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html#verify-signature)

The certificates are scraped from this [wonderfully user hostile format for supplying certificates](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html)

## Installation

To install the module, use npm:

```bash
npm install aws-instance-identity-certificates
```

## Usage

```javascript
import { verifyInstanceIdentityDocument } from 'aws-instance-identity-certificates';

const document = '...'; // Your instance identity document (JSON string)
const signature = '...'; // The corresponding base64-encoded signature

const isValid = await verifyInstanceIdentityDocument(document, signature);
if (isValid) {
  console.log('The identity document is valid.');
} else {
  console.log('The identity document is invalid.');
}
```

To use RSA 2048 verification instead of standard RSA:

```javascript
const isValid = await verifyInstanceIdentityDocument(document, signature, 'rsa2048');
```

## API

### `verifyInstanceIdentityDocument(document, signature, procedure?)`

Verifies the given instance identity document and its signature.

- `document` (string): The instance identity document as a JSON string.
- `signature` (string): The base64-encoded signature of the document.
- `procedure` (string, optional): `"rsa"` (default), `"rsa2048"`, or `"dsa"`.

> **Note:** `"dsa"` uses DSA with SHA-1, which is deprecated by AWS and considered cryptographically weak. It is included for completeness but `"rsa"` or `"rsa2048"` should be preferred.

Returns a promise that resolves to a boolean indicating whether the document is valid.

### `getCertificateForRegion(region, procedure)`

Retrieves the AWS public certificate for a specific region and procedure.

- `region` (string): The AWS region (e.g. `"us-east-1"`).
- `procedure` (string): `"dsa"`, `"rsa"`, or `"rsa2048"`.

Returns an `X509Certificate` object.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.
