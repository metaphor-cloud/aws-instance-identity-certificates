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

Here is an example of how to use the module:

```javascript
const { verifyIdentityDocument } = require('aws-instance-identity-certificates');

const document = '...'; // Your instance identity document
const signature = '...'; // The corresponding signature

verifyIdentityDocument(document, signature)
  .then(isValid => {
    if (isValid) {
      console.log('The identity document is valid.');
    } else {
      console.log('The identity document is invalid.');
    }
  })
  .catch(error => {
    console.error('Error verifying identity document:', error);
  });
```

## API

### `verifyIdentityDocument(document, signature)`

Verifies the given instance identity document and its signature.

- `document` (string): The instance identity document.
- `signature` (string): The signature of the document.

Returns a promise that resolves to a boolean indicating whether the document is valid.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.