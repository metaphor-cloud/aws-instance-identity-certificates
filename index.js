import { certs } from "./certs.js";
import { X509Certificate } from "crypto";

const supportedProcedures = ["pkcs7", "base64", "rsa2048"];
const procedureFormatMap = {
  pkcs7: "dsa",
  base64: "rsa",
  rsa2048: "rsa2048",
};

/**
 * Retrieve a certificate string from the certs object.
 * @param {string} region
 * @param {string} procedure
 * @returns {string} The certificate for the given region.
 */
export function getCertificateForRegion(region, procedure) {
  if (!supportedProcedures.includes(procedure)) {
    throw new Error(`Unsupported procedure: ${procedure}`);
  }

  const certFormat = procedureFormatMap[procedure];
  const cert = certs[certFormat]?.[region];

  if (!cert) {
    throw new Error(`Certificate not found: ${certFormat} for region: ${region}`);
  }

  return new X509Certificate(cert);
}

/**
 * Strips PEM headers/footers and whitespace to return only base64-encoded data.
 * @param {string} pem
 * @returns {string} Base64-encoded data.
 */
function pemToBase64(pem) {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}

/**
 * Converts a base64 string to an ArrayBuffer.
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const length = binaryString.length;
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Verifies the signature of an Instance Identity Document using a region-specific certificate.
 * @param {string} instanceIdentityDocument - The JSON string of the document.
 * @param {string} signatureBase64 - The base64-encoded signature to verify.
 * @returns {Promise<boolean>} - Whether the signature is valid.
 */
export async function verifyBase64InstanceIdentityDocument(instanceIdentityDocument, signatureBase64) {
  try {
    const instanceIdentityObject = JSON.parse(instanceIdentityDocument);
    const region = instanceIdentityObject.region;

    const cert = getCertificateForRegion(region, "base64");
    const publicKeyObj = cert.publicKey;
    const publicKeyB64 = publicKeyObj.export({ type: "spki", format: "pem" });
    const publicKeyBuffer = base64ToArrayBuffer(pemToBase64(publicKeyB64));

    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      false,
      ["verify"]
    );

    const documentBuffer = new TextEncoder().encode(instanceIdentityDocument);
    const signatureBuffer = base64ToArrayBuffer(signatureBase64);

    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBuffer,
      documentBuffer
    );

    return isValid;
  } catch (error) {
    console.error(error);
    return false;
  }
}
