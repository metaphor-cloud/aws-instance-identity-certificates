import { describe, it, expect } from "@jest/globals";
import { X509Certificate } from "crypto";
import {
  getCertificateForRegion,
  verifyInstanceIdentityDocument,
} from "./index.js";

const validInstanceIdentityDocument = `{
  "accountId" : "189292791360",
  "architecture" : "arm64",
  "availabilityZone" : "ap-southeast-2a",
  "billingProducts" : null,
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-0cbde744623b7506b",
  "instanceId" : "i-0c5541936caf78c12",
  "instanceType" : "t4g.small",
  "kernelId" : null,
  "pendingTime" : "2026-02-16T00:38:27Z",
  "privateIp" : "10.0.1.242",
  "ramdiskId" : null,
  "region" : "ap-southeast-2",
  "version" : "2017-09-30"
}`;

const invalidInstanceIdentityDocument = `{
  "architecture" : "x86_64",
  "availabilityZone" : "ap-southeast-2a",
  "billingProducts" : [ "bp-6fa54006" ],
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-03f052ebc3f436d52",
  "instanceType" : "t2.micro",
  "kernelId" : null,
  "pendingTime" : "2025-02-05T09:18:10Z",
  "privateIp" : "10.254.1.186",
  "region" : "ap-southeast-2",
  "version" : "2017-09-30"
}`;

const validRsaSignature = `
DVm1OtrMzph5Ts/diebX4f+iTMICLzhmht8ACup1gHM/XhPiT/Gt3O7QARmoV9lGyaktCilucc5D
ke8UMSHQY1ijPmGrTfzPxUwVw/6OFzQ/AlfjTnhygDgDh6KZU6/x52BvWkUqxemFT4CmqrKzvbZh
GaR5gDPKDGRTwaN7A4w=
`.replace(/\n/g, "");
const validRsa2048Signature = `
MIAGCSqGSIb3DQEHAqCAMIACAQExDTALBglghkgBZQMEAgEwgAYJKoZIhvcNAQcBoIAkgASCAeR7
CiAgImFjY291bnRJZCIgOiAiMTg5MjkyNzkxMzYwIiwKICAiYXJjaGl0ZWN0dXJlIiA6ICJhcm02
NCIsCiAgImF2YWlsYWJpbGl0eVpvbmUiIDogImFwLXNvdXRoZWFzdC0yYSIsCiAgImJpbGxpbmdQ
cm9kdWN0cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAibWFya2V0
cGxhY2VQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAiaW1hZ2VJZCIgOiAiYW1pLTBjYmRlNzQ0NjIz
Yjc1MDZiIiwKICAiaW5zdGFuY2VJZCIgOiAiaS0wYzU1NDE5MzZjYWY3OGMxMiIsCiAgImluc3Rh
bmNlVHlwZSIgOiAidDRnLnNtYWxsIiwKICAia2VybmVsSWQiIDogbnVsbCwKICAicGVuZGluZ1Rp
bWUiIDogIjIwMjYtMDItMTZUMDA6Mzg6MjdaIiwKICAicHJpdmF0ZUlwIiA6ICIxMC4wLjEuMjQy
IiwKICAicmFtZGlza0lkIiA6IG51bGwsCiAgInJlZ2lvbiIgOiAiYXAtc291dGhlYXN0LTIiLAog
ICJ2ZXJzaW9uIiA6ICIyMDE3LTA5LTMwIgp9AAAAAAAAMYICKzCCAicCAQEwaTBcMQswCQYDVQQG
EwJVUzEZMBcGA1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UE
ChMXQW1hem9uIFdlYiBTZXJ2aWNlcyBMTEMCCQC9mzoG/navazALBglghkgBZQMEAgGggZYwGAYJ
KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMjE2MDAzODI4WjArBgkq
hkiG9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQxIgQg
JuBakWdgxV8tjlul+DIT6i+w6b8/C55oWPvN4ZjsikQwDQYJKoZIhvcNAQELBQAEggEAKb9EHZze
cWagTKFctn6wj09JvLDpRx9nxBqT62WIh8lXYERWxCuL9Q6PcTnyaVgydldyZ+R2LSdb6+J7341l
LmKJpwwQCX/YuSlYWEKaQkliG6LSEFBg3sTmQeM4LhZAAiAlZ3U2OekfVqvCuzNRFcqfKbTPzUJU
q07M76Si2G8JcJW8OBYmzNsJYbeDVnhp3L6uet6zHWzlSA1U0Q3MNs8gmt9HWGzW9sDOaj5ZOkK7
WzMXqkdbCuFkesa6EaV2nRtD+Xm2LipxGbOwlmBPumg0WGcgDuPUc62A5DewgctliURC6qzhTLnS
AKOTPvMq3Nro7tmuvFahEjsAdcWoBQAAAAAAAA==
`.replace(/\n/g, "");
const validDsaDocument = `{
  "accountId" : "189292791360",
  "architecture" : "arm64",
  "availabilityZone" : "ap-southeast-2a",
  "billingProducts" : null,
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-0bd844a68ec62a014",
  "instanceId" : "i-01c4776ebe87bea77",
  "instanceType" : "t4g.small",
  "kernelId" : null,
  "pendingTime" : "2026-03-21T06:25:00Z",
  "privateIp" : "10.0.3.106",
  "ramdiskId" : null,
  "region" : "ap-southeast-2",
  "version" : "2017-09-30"
}`;
const validDsaSignature = `
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHkewog
ICJhY2NvdW50SWQiIDogIjE4OTI5Mjc5MTM2MCIsCiAgImFyY2hpdGVjdHVyZSIgOiAiYXJtNjQi
LAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJhcC1zb3V0aGVhc3QtMmEiLAogICJiaWxsaW5nUHJv
ZHVjdHMiIDogbnVsbCwKICAiZGV2cGF5UHJvZHVjdENvZGVzIiA6IG51bGwsCiAgIm1hcmtldHBs
YWNlUHJvZHVjdENvZGVzIiA6IG51bGwsCiAgImltYWdlSWQiIDogImFtaS0wYmQ4NDRhNjhlYzYy
YTAxNCIsCiAgImluc3RhbmNlSWQiIDogImktMDFjNDc3NmViZTg3YmVhNzciLAogICJpbnN0YW5j
ZVR5cGUiIDogInQ0Zy5zbWFsbCIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInBlbmRpbmdUaW1l
IiA6ICIyMDI2LTAzLTIxVDA2OjI1OjAwWiIsCiAgInByaXZhdGVJcCIgOiAiMTAuMC4zLjEwNiIs
CiAgInJhbWRpc2tJZCIgOiBudWxsLAogICJyZWdpb24iIDogImFwLXNvdXRoZWFzdC0yIiwKICAi
dmVyc2lvbiIgOiAiMjAxNy0wOS0zMCIKfQAAAAAAADGCAUAwggE8AgEBMGkwXDELMAkGA1UEBhMC
VVMxGTAXBgNVBAgTEFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoT
F0FtYXpvbiBXZWIgU2VydmljZXMgTExDAgkAlrpI2eVeGmcwCQYFKw4DAhoFAKCBhDAYBgkqhkiG
9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAzMjEwNjI1MDFaMCMGCSqGSIb3
DQEJBDEWBBTAf+QVSj7aVnR9alD8JoujUtCLdDAlBgkqhkiG9w0BCTQxGDAWMAkGBSsOAwIaBQCh
CQYHKoZIzjgEAzAJBgcqhkjOOAQDBC8wLQIUI2CKKQxMbi58V6h0ScBf2Nznt+oCFQCqBH7mWS1Z
m8naVIqxowB096q51gAAAAAAAA==
`.replace(/\n/g, "");
const invalidSignature = `
GCcPKC1lRHrgflbwv5HFlD86tXmVc826COmFt48FnwjYAKwsgDhFXHyeLY4kiOmk0XrAgI2wXe3q
D7CPu38hRxRlVFhf1IXhxh9zitL2knV+6J3XkJlheXiYK2733+SvCAlDJbfmrndf4M5Zh/nCaUHQ
sLoJ0U0KpQrOG9uqpwo=
`.replace(/\n/g, "");

describe("getCertificateForRegion", () => {
  it("should throw an error if the procedure is not supported", () => {
    expect(() =>
      getCertificateForRegion("us-east-1", "unsupported")
    ).toThrowError("Unsupported procedure: unsupported. Must be one of: dsa, rsa, rsa2048");
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

  it("us-east-1 rsa should return an X509Certificate object with valid subject and expiry", () => {
    const cert = getCertificateForRegion("us-east-1", "rsa");
    expect(cert).toBeInstanceOf(X509Certificate);
    expect(cert.subject).toBe(`C=US
ST=Washington State
L=Seattle
O=Amazon Web Services LLC`);
    expect(cert.validFrom).toBe("Apr 29 17:34:01 2024 GMT");
    expect(cert.validTo).toBe("Apr 28 17:34:01 2029 GMT");
  });

});

describe("verifyInstanceIdentityDocument", () => {
  it("should throw an error if the signature is missing", async () => {
    await expect(
      verifyInstanceIdentityDocument(validInstanceIdentityDocument, null, "rsa")
    ).rejects.toThrowError("Signature is required for verification.");
  });

  it("should throw an error if the instance identity document is missing", async () => {
    await expect(
      verifyInstanceIdentityDocument(null, validRsaSignature, "rsa")
    ).rejects.toThrowError("Instance identity document is required for verification.");
  });

  it("should throw an error if the procedure is not supported", async () => {
    await expect(
      verifyInstanceIdentityDocument(validInstanceIdentityDocument, validRsaSignature, "unsupported")
    ).rejects.toThrowError("Unsupported procedure for key import: unsupported. Must be one of: dsa, rsa, rsa2048");
  });

  it("should throw an error for invalid JSON", async () => {
    await expect(
      verifyInstanceIdentityDocument("not valid json", validRsaSignature, "rsa")
    ).rejects.toThrowError("Instance identity document is not valid JSON.");
  });

  it("should throw an error if region field is missing", async () => {
    await expect(
      verifyInstanceIdentityDocument('{"accountId": "123"}', validRsaSignature, "rsa")
    ).rejects.toThrowError("Instance identity document is missing a valid 'region' field.");
  });

  it("should return true for a valid RSA identity document and signature", async () => {
    const isValid = await verifyInstanceIdentityDocument(
      validInstanceIdentityDocument,
      validRsaSignature,
      "rsa",
    );
    expect(isValid).toBe(true);
  });

  it("should return true for a valid DSA identity document and signature", async () => {
    const isValid = await verifyInstanceIdentityDocument(
      validDsaDocument,
      validDsaSignature,
      "dsa",
    );
    expect(isValid).toBe(true);
  });

  it("should return true for a valid RSA 2048 identity document and signature", async () => {
    const isValid = await verifyInstanceIdentityDocument(
      validInstanceIdentityDocument,
      validRsa2048Signature,
      "rsa2048",
    );
    expect(isValid).toBe(true);
  });

  it("should return false for an invalid identity document", async () => {
    const isValid = await verifyInstanceIdentityDocument(
      invalidInstanceIdentityDocument,
      validRsaSignature,
      "rsa",
    );
    expect(isValid).toBe(false);
  });

  it("should return false for an invalid signature", async () => {
    const isValid = await verifyInstanceIdentityDocument(
      validInstanceIdentityDocument,
      invalidSignature,
      "rsa",
    );
    expect(isValid).toBe(false);
  });

  it("should return false for an invalid identity document and signature", async () => {
    const isValid = await verifyInstanceIdentityDocument(
      invalidInstanceIdentityDocument,
      invalidSignature,
      "rsa",
    );
    expect(isValid).toBe(false);
  });
});
