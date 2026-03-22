import { certs } from "./certs.js";
import { createVerify, X509Certificate } from "node:crypto";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

const supportedProcedures = ["dsa", "rsa", "rsa2048"];

const PKCS7_SIGNED_DATA_OID = "1.2.840.113549.1.7.2";

/**
 * Retrieve a certificate string from the certs object.
 * @param {string} region
 * @param {string} procedure
 * @returns {X509Certificate} The certificate for the given region.
 */
export function getCertificateForRegion(region, procedure) {
  if (!supportedProcedures.includes(procedure)) {
    throw new Error(
      `Unsupported procedure: ${procedure}. Must be one of: ${supportedProcedures.join(", ")}`,
    );
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
  if (!signatureBase64) {
    throw new Error("Signature is required for verification.");
  }
  if (!instanceIdentityDocument) {
    throw new Error(
      "Instance identity document is required for verification.",
    );
  }
  if (!supportedProcedures.includes(procedure)) {
    throw new Error(
      `Unsupported procedure for key import: ${procedure}. Must be one of: ${supportedProcedures.join(", ")}`,
    );
  }

  let instanceIdentityObject;
  try {
    instanceIdentityObject = JSON.parse(instanceIdentityDocument);
  } catch {
    throw new Error(
      "Instance identity document is not valid JSON.",
    );
  }

  const region = instanceIdentityObject.region;
  if (!region || typeof region !== "string") {
    throw new Error(
      "Instance identity document is missing a valid 'region' field.",
    );
  }

  const cert = getCertificateForRegion(region, procedure);
  const documentBuffer = new TextEncoder().encode(instanceIdentityDocument);

  // ==========================================
  // PATH 1: DSA (deprecated, PKCS7 / CMS with DSA-SHA1)
  // ==========================================
  // PKI.js does not support DSA signature verification, so we parse the PKCS7
  // structure to extract the DER-encoded DSA signature and signed attributes,
  // then verify with Node's createVerify.
  if (procedure === "dsa") {
    const pkcs7Buffer = base64ToArrayBuffer(signatureBase64);

    const asn1 = asn1js.fromBER(pkcs7Buffer.buffer);
    if (asn1.offset === -1) {
      throw new Error("Failed to parse PKCS7 signature.");
    }

    const cmsContent = new pkijs.ContentInfo({ schema: asn1.result });
    if (cmsContent.contentType !== PKCS7_SIGNED_DATA_OID) {
      throw new Error("PKCS7 content is not SignedData.");
    }
    const signedData = new pkijs.SignedData({ schema: cmsContent.content });

    const signerInfo = signedData.signerInfos[0];
    const dsaSigDer = signerInfo.signature.valueBlock.valueHexView;

    // In PKCS7 with signed attributes, the signature is over the DER-encoded
    // authenticated attributes (which include a digest of the original content),
    // not over the raw content itself.
    const signedAttrsBytes = Buffer.from(signerInfo.signedAttrs.encodedValue);

    const verify = createVerify("DSS1");
    verify.update(signedAttrsBytes);
    return verify.verify(cert.publicKey, dsaSigDer);
  }

  // ==========================================
  // PATH 2: RSA 2048 (PKCS7 / CMS Signature)
  // ==========================================
  if (procedure === "rsa2048") {
    const pkcs7Buffer = base64ToArrayBuffer(signatureBase64);

    const asn1 = asn1js.fromBER(pkcs7Buffer.buffer);
    if (asn1.offset === -1) {
      throw new Error("Failed to parse PKCS7 signature.");
    }

    const cmsContent = new pkijs.ContentInfo({ schema: asn1.result });
    if (cmsContent.contentType !== PKCS7_SIGNED_DATA_OID) {
      throw new Error("PKCS7 content is not SignedData.");
    }
    const signedData = new pkijs.SignedData({ schema: cmsContent.content });

    // Convert Node's X509Certificate to a PKI.js Certificate via its raw DER buffer
    const certDer = new Uint8Array(cert.raw);
    const asn1Cert = asn1js.fromBER(certDer.buffer);
    const pkijsCert = new pkijs.Certificate({ schema: asn1Cert.result });

    // Inject the out-of-band certificate into the CMS payload.
    // AWS PKCS7 signatures are detached and don't include the signing certificate,
    // so we must add it ourselves for PKI.js verification to work.
    if (!signedData.certificates) {
      signedData.certificates = [];
    }
    signedData.certificates.push(pkijsCert);

    // Native PKI.js verification handles ALL the ASN.1/DER/byte-swapping quirks
    const isValid = await signedData.verify({
      signer: 0,
      data: documentBuffer.buffer,
      trustedCerts: [pkijsCert],
      // We explicitly trust this AWS cert — no need to build a full PKI chain,
      // as the certificates are embedded in this package, not fetched at runtime.
      checkChain: false,
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
}
