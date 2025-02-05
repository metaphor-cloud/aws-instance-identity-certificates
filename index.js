const fs = require("fs");
const crypto = require("crypto");

const supportedProcedures = ["pkcs7", "base64", "rsa2048"];
const procedureFormatMap = {
  pkcs7: "dsa",
  base64: "rsa",
  rsa2048: "rsa2048",
};

function getCertificateForRegion(region, procedure) {
  if (procedure && !supportedProcedures.includes(procedure)) {
    throw new Error(`Unsupported procedure: ${procedure}`);
  }
  const certFile = `certs/${procedureFormatMap[procedure]}/${region}.pem`;
  if (!fs.existsSync(certFile)) {
    throw new Error(`Certificate not found for region: ${region}`);
  }
  const cert = fs.readFileSync(certFile);
  return new crypto.X509Certificate(cert);
}

function verifyBase64InstanceIdentityDocument(instanceIdentityDocument, signature) {
  const instanceIdentityObject = JSON.parse(instanceIdentityDocument);
  const region = instanceIdentityObject.region;
  const cert = getCertificateForRegion(region, "base64");
  const publicKey = cert.publicKey;
  const verifier = crypto.createVerify("SHA256");
  verifier.update(instanceIdentityDocument);
  return verifier.verify(publicKey, signature);
}

module.exports = {
  getCertificateForRegion,
  verifyBase64InstanceIdentityDocument,
};
