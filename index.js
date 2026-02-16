import { certs } from "./certs.js";
import { X509Certificate } from "crypto";
import pkijs from "pkijs";
import * as asn1js from "asn1js";

const supportedProcedures = [
  // "dsa",
  "rsa",
  "rsa2048",
];

/**
 * Retrieve a certificate string from the certs object.
 * @param {string} region
 * @param {string} procedure
 * @returns {X509Certificate} The certificate for the given region.
 */
export function getCertificateForRegion(region, procedure) {
  if (!supportedProcedures.includes(procedure)) {
    throw new Error(`Unsupported procedure: ${procedure}`);
  }

  const certFormat = procedure;
  const cert = certs[certFormat]?.[region];

  if (!cert) {
    throw new Error(
      `Certificate not found: ${certFormat} for region: ${region}`,
    );
  }

  return new X509Certificate(cert);
}

/**
 * Converts a base64 string to an ArrayBuffer.
 * @param {string} base64
 * @returns {Uint8Array}
 */
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  return Uint8Array.from(binaryString, (c, i) => binaryString.charCodeAt(i));
}

/**
 * Verifies the signature of an Instance Identity Document using a region-specific certificate.
 * @param {string} instanceIdentityDocument - The JSON string of the document.
 * @param {string} signatureBase64 - The base64-encoded signature to verify.
 * @param {string} procedure - The procedure to use for verification (default: "rsa")
 * @returns {Promise<boolean>} - Whether the signature is valid.
 */
export async function verifyInstanceIdentityDocument(
  instanceIdentityDocument,
  signatureBase64,
  procedure = "rsa",
) {
  try {
    if (!signatureBase64) {
      throw new Error("Signature is required for verification.");
    }
    if (!instanceIdentityDocument) {
      throw new Error(
        "Instance identity document is required for verification.",
      );
    }
    if (!supportedProcedures.includes(procedure)) {
      throw new Error(`Unsupported procedure for key import: ${procedure}`);
    }

    const instanceIdentityObject = JSON.parse(instanceIdentityDocument);
    const region = instanceIdentityObject.region;

    const cert = getCertificateForRegion(region, procedure);
    const documentBuffer = new TextEncoder().encode(instanceIdentityDocument);

    // ==========================================
    // PATH 1: RSA 2048 (PKCS7 / CMS Signature)
    // ==========================================
    if (procedure === "rsa2048") {
      const pkcs7Buffer = base64ToArrayBuffer(signatureBase64);

      const asn1 = asn1js.fromBER(pkcs7Buffer.buffer);
      if (asn1.offset === -1) {
        throw new Error("Failed to parse PKCS7 signature.");
      }

      const cmsContent = new pkijs.ContentInfo({ schema: asn1.result });
      if (cmsContent.contentType !== "1.2.840.113549.1.7.2") {
        throw new Error("PKCS7 content is not SignedData.");
      }
      const signedData = new pkijs.SignedData({ schema: cmsContent.content });

    // Convert Node's X509Certificate to a PKI.js Certificate via its raw DER buffer
      const certDer = new Uint8Array(cert.raw);
      const asn1Cert = asn1js.fromBER(certDer.buffer);
      const pkijsCert = new pkijs.Certificate({ schema: asn1Cert.result });

      // --- THE FIX: Inject the out-of-band certificate into the CMS payload ---
      if (!signedData.certificates) {
        signedData.certificates = [];
      }
      signedData.certificates.push(pkijsCert);
      // ------------------------------------------------------------------------

      // Native PKI.js verification handles ALL the ASN.1/DER/byte-swapping quirks
      const isValid = await signedData.verify({
        signer: 0,
        data: documentBuffer.buffer, // Pass the ArrayBuffer of the detached content
        trustedCerts: [pkijsCert],
        checkChain: false, // We explicitly trust this AWS cert, no need to build a full PKI chain
      });

      return isValid;
    }

    // ==========================================
    // PATH 2: Standard RSA (Raw Signature)
    // ==========================================
    const publicKeyBuffer = cert.publicKey.export({ type: "spki", format: "der" });

    if (publicKeyBuffer.byteLength !== 162) {
      throw new Error(
        `Expected RSA 1024-bit public key to be 162 bytes, but got ${publicKeyBuffer.byteLength} bytes.`,
      );
    }

    const signatureBuffer = base64ToArrayBuffer(signatureBase64);

    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      false,
      ["verify"],
    );

    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBuffer,
      documentBuffer,
    );
  } catch (error) {
    console.error(error);
    throw error;
  }
}