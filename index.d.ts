import { X509Certificate } from "node:crypto";

/**
 * Retrieves the AWS public certificate for a specific region and procedure.
 * @param region - The AWS region (e.g. "us-east-1").
 * @param procedure - "rsa" or "rsa2048".
 * @returns The X509Certificate for the given region.
 */
export function getCertificateForRegion(
  region: string,
  procedure: "dsa" | "rsa" | "rsa2048",
): X509Certificate;

/**
 * Verifies the signature of an Instance Identity Document using a region-specific certificate.
 * @param instanceIdentityDocument - The JSON string of the document.
 * @param signatureBase64 - The base64-encoded signature to verify.
 * @param procedure - The procedure to use for verification (default: "rsa").
 * @returns Whether the signature is valid.
 */
export function verifyInstanceIdentityDocument(
  instanceIdentityDocument: string,
  signatureBase64: string,
  procedure?: "dsa" | "rsa" | "rsa2048",
): Promise<boolean>;
