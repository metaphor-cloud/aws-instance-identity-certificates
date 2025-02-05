const { describe, it, expect } = require("@jest/globals");
const crypto = require("crypto");
const {
  getCertificateForRegion,
  verifyBase64InstanceIdentityDocument,
} = require("./index");

describe("getCertificateForRegion", () => {
  it("should throw an error if the procedure is not supported", () => {
    expect(() =>
      getCertificateForRegion("us-east-1", "unsupported")
    ).toThrowError("Unsupported procedure: unsupported");
  });
  it("should throw an error if the certificate file does not exist", () => {
    expect(() => getCertificateForRegion("us-east-1")).toThrowError(
      "Certificate not found for region: us-east-1"
    );
  });
  it("should return a valid X509Certificate object", () => {
    const cert = getCertificateForRegion("us-east-1", "rsa2048");
    expect(cert).toBeInstanceOf(crypto.X509Certificate);
  });
  it("should return a valid X509Certificate object with the correct subject", () => {
    const cert = getCertificateForRegion("us-east-1", "rsa2048");
    expect(cert.subject).toBe(`C=US
ST=Washington State
L=Seattle
O=Amazon Web Services LLC`);
  });
  it("should return a valid X509Certificate object with the correct issuer", () => {
    const cert = getCertificateForRegion("us-east-1", "rsa2048");
    expect(cert.issuer).toBe(`C=US
ST=Washington State
L=Seattle
O=Amazon Web Services LLC`);
  });
  it("should return a valid X509Certificate object with the correct validity period", () => {
    const cert = getCertificateForRegion("us-east-1", "rsa2048");
    expect(cert.validFrom).toEqual("Aug 14 08:59:12 2015 GMT");
    expect(cert.validTo).toEqual("Jan 17 08:59:12 2195 GMT");
  });
});

const instanceIdentityDocument = `{
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
const b64Signature = `HCcPKC1lRHrgflbwv5HFlD86tXmVc826COmFt48FnwjYAKwsgDhFXHyeLY4kiOmk0XrCgI2wXe3q
D7CPu38hRxRlVFhf1IXhxh9zitL2knV+6J3XkJlheXiYK2733+SvCAlDJbfmrndf4M5Zh/nCaUHQ
sLoJ0U0KpQrOG9uqpwo=`;

describe("verifyBase64InstanceIdentityDocument", () => {
  it("should return true for a valid signature", () => {
    const signature = Buffer.from(b64Signature, "base64");
    expect(
      verifyBase64InstanceIdentityDocument(instanceIdentityDocument, signature)
    ).toBe(true);
  });
  it("should return false for an invalid signature", () => {
    const signature = Buffer.from("invalid", "base64");
    expect(
      verifyBase64InstanceIdentityDocument(instanceIdentityDocument, signature)
    ).toBe(false);
  });
});
