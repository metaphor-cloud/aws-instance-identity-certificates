import { describe, it, expect } from "@jest/globals";
import { X509Certificate } from "crypto";
import {
  getCertificateForRegion,
  verifyBase64InstanceIdentityDocument,
} from "./index.js";

describe("getCertificateForRegion", () => {
  it("should throw an error if the procedure is not supported", () => {
    expect(() =>
      getCertificateForRegion("us-east-1", "unsupported")
    ).toThrowError("Unsupported procedure: unsupported");
  });

  it("should throw an error if the certificate file does not exist", () => {
    expect(() => getCertificateForRegion("us-asdasd-1", "pkcs7")).toThrowError(
      "Certificate not found: dsa for region: us-asdasd-1"
    );
  });

  it("us-east-1 rsa2048 should return an X509Certificate object with valid subject and expiry", () => {
    const cert = getCertificateForRegion("us-east-1", "rsa2048");
    expect(cert).toBeInstanceOf(X509Certificate);
    expect(cert.subject).toBe(`C=US
ST=Washington State
L=Seattle
O=Amazon Web Services LLC`);
    expect(cert.validFrom).toBe("Aug 14 08:59:12 2015 GMT");
    expect(cert.validTo).toBe("Jan 17 08:59:12 2195 GMT");
  });

  it("us-east-1 base64 should return an X509Certificate object with valid subject and expiry", () => {
    const cert = getCertificateForRegion("us-east-1", "base64");
    expect(cert).toBeInstanceOf(X509Certificate);
    expect(cert.subject).toBe(`C=US
ST=Washington State
L=Seattle
O=Amazon Web Services LLC`);
    expect(cert.validFrom).toBe("Apr 29 17:34:01 2024 GMT");
    expect(cert.validTo).toBe("Apr 28 17:34:01 2029 GMT");
  });

  it("us-east-1 pkcs7 should return an X509Certificate object with valid subject and expiry", () => {
    const cert = getCertificateForRegion("us-east-1", "pkcs7");
    expect(cert).toBeInstanceOf(X509Certificate);
    expect(cert.subject).toBe(`C=US
ST=Washington State
L=Seattle
O=Amazon Web Services LLC`);
    expect(cert.validFrom).toBe("Jan  5 12:56:12 2012 GMT");
    expect(cert.validTo).toBe("Jan  5 12:56:12 2038 GMT");
  });
});

const validInstanceIdentityDocument = `{
  "accountId" : "189292791360",
  "architecture" : "x86_64",
  "availabilityZone" : "ap-southeast-2a",
  "billingProducts" : [ "bp-6fa54006" ],
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-03f052ebc3f436d52",
  "instanceId" : "i-050c2e3dd07033e9e",
  "instanceType" : "t2.micro",
  "kernelId" : null,
  "pendingTime" : "2025-02-05T09:18:10Z",
  "privateIp" : "10.254.1.186",
  "ramdiskId" : null,
  "region" : "ap-southeast-2",
  "version" : "2017-09-30"
}`;

const validBase64Signature = `HCcPKC1lRHrgflbwv5HFlD86tXmVc826COmFt48FnwjYAKwsgDhFXHyeLY4kiOmk0XrCgI2wXe3q
D7CPu38hRxRlVFhf1IXhxh9zitL2knV+6J3XkJlheXiYK2733+SvCAlDJbfmrndf4M5Zh/nCaUHQ
sLoJ0U0KpQrOG9uqpwo=`.replace(/\n/g, "");

describe("verifyBase64InstanceIdentityDocument", () => {
  it("should return true for a valid identity document and signature", async () => {
    const isValid = await verifyBase64InstanceIdentityDocument(
      validInstanceIdentityDocument,
      validBase64Signature
    );
    expect(isValid).toBe(true);
  });


  it("should return false for an invalid identity document", async () => {
    const isValid = await verifyBase64InstanceIdentityDocument(
      "invalid-base64-string",
      validBase64Signature
    );
    expect(isValid).toBe(false);
  });

  it("should return false for an invalid signature", async () => {
    const isValid = await verifyBase64InstanceIdentityDocument(
      validInstanceIdentityDocument,
      "invalid-base64-string"
    );
    expect(isValid).toBe(false);
  });

  it("should return false for an invalid identity document and signature", async () => {
    const isValid = await verifyBase64InstanceIdentityDocument(
      "invalid-base64-string",
      "invalid-base64-string"
    );
    expect(isValid).toBe(false);
  });
});