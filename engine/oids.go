package engine

import (
	"encoding/asn1"
	"strings"
)

var oidNames = map[string]string{
	// DN attributes
	"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L",
	"2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
	"2.5.4.13": "description", "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode",
	"2.5.4.42": "givenName", "2.5.4.43": "initials", "2.5.4.44": "generationQualifier",
	"2.5.4.46": "dnQualifier", "2.5.4.65": "pseudonym", "2.5.4.97": "organizationIdentifier",
	"1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1": "UID", "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
	"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST", "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",

	// public key algorithms
	"1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.10045.2.1": "id-ecPublicKey",
	"1.3.132.1.12": "id-ecDH", "1.3.101.110": "X25519", "1.3.101.111": "X448",
	"1.3.101.112": "Ed25519", "1.3.101.113": "Ed448", "1.2.840.10040.4.1": "DSA",
	"1.2.840.10045.1.1": "prime-field", "1.2.840.10045.1.2": "characteristic-two-field",

	// signature algorithms
	"1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
	"1.2.840.113549.1.1.10": "RSASSA-PSS", "1.2.840.113549.1.1.8": "MGF1",
	"1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
	"1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
	"1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
	"2.16.840.1.101.3.4.3.9": "ecdsa-with-SHA3-224", "2.16.840.1.101.3.4.3.10": "ecdsa-with-SHA3-256",
	"2.16.840.1.101.3.4.3.11": "ecdsa-with-SHA3-384", "2.16.840.1.101.3.4.3.12": "ecdsa-with-SHA3-512",
	"2.16.840.1.101.3.4.3.13": "rsa-with-SHA3-224", "2.16.840.1.101.3.4.3.14": "rsa-with-SHA3-256",
	"2.16.840.1.101.3.4.3.15": "rsa-with-SHA3-384", "2.16.840.1.101.3.4.3.16": "rsa-with-SHA3-512",
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	"1.2.840.10040.4.3": "dsa-with-sha1", "2.16.840.1.101.3.4.3.1": "dsa-with-sha224", "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",

	// hashes
	"1.2.840.113549.2.5": "md5", "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224",
	"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512",
	"2.16.840.1.101.3.4.2.7": "sha3-224", "2.16.840.1.101.3.4.2.8": "sha3-256", "2.16.840.1.101.3.4.2.9": "sha3-384",
	"2.16.840.1.101.3.4.2.10": "sha3-512",

	// curves
	"1.2.840.10045.3.1.1": "P-192", "1.3.132.0.33": "P-224", "1.2.840.10045.3.1.7": "P-256",
	"1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1",
	"1.3.36.3.3.2.8.1.1.1": "brainpoolP160r1", "1.3.36.3.3.2.8.1.1.3": "brainpoolP192r1",
	"1.3.36.3.3.2.8.1.1.5": "brainpoolP224r1", "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
	"1.3.36.3.3.2.8.1.1.9": "brainpoolP320r1", "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
	"1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",

	// extensions
	"2.5.29.9": "subjectDirectoryAttributes", "2.5.29.14": "subjectKeyIdentifier", "2.5.29.15": "keyUsage",
	"2.5.29.16": "privateKeyUsagePeriod", "2.5.29.17": "subjectAltName", "2.5.29.18": "issuerAltName",
	"2.5.29.19": "basicConstraints", "2.5.29.20": "cRLNumber", "2.5.29.21": "reasonCode",
	"2.5.29.23": "holdInstructionCode", "2.5.29.24": "invalidityDate", "2.5.29.27": "deltaCRLIndicator",
	"2.5.29.28": "issuingDistributionPoint", "2.5.29.29": "certificateIssuer", "2.5.29.30": "nameConstraints",
	"2.5.29.31": "cRLDistributionPoints", "2.5.29.32": "certificatePolicies", "2.5.29.33": "policyMappings",
	"2.5.29.35": "authorityKeyIdentifier", "2.5.29.36": "policyConstraints", "2.5.29.37": "extKeyUsage",
	"2.5.29.46": "freshestCRL", "2.5.29.54": "inhibitAnyPolicy", "2.5.29.32.0": "anyPolicy",
	"1.3.6.1.5.5.7.1.1": "authorityInfoAccess", "1.3.6.1.5.5.7.1.11": "subjectInfoAccess",
	"1.3.6.1.5.5.7.1.3": "qcStatements", "1.3.6.1.5.5.7.1.24": "tlsFeature",
	"1.3.6.1.5.5.7.48.1.5": "ocspNoCheck", "1.3.6.1.5.5.7.48.1.2": "ocspNonce",
	"1.3.6.1.4.1.11129.2.4.2": "CT SCT list", "1.3.6.1.4.1.11129.2.4.3": "CT precert poison",
	"2.16.840.1.113730.1.1": "netscapeCertType", "2.16.840.1.113730.1.13": "netscapeComment",
	"1.3.6.1.4.1.311.20.2": "msCertTemplateName", "1.3.6.1.4.1.311.21.7": "msCertTemplate",
	"1.3.6.1.4.1.311.21.1": "msCAVersion", "1.3.6.1.4.1.311.21.2": "msPrevCAHash",
	"1.3.6.1.4.1.311.21.10": "msAppPolicies", "1.3.6.1.4.1.311.25.2": "msNTDSSecurity",
	"2.23.136.1.1.6.1": "ICAO nameChange", "2.23.136.1.1.6.2": "ICAO documentTypeList",

	// access methods
	"1.3.6.1.5.5.7.48.1": "OCSP", "1.3.6.1.5.5.7.48.2": "caIssuers", "1.3.6.1.5.5.7.48.5": "caRepository",
	"1.3.6.1.5.5.7.2.1": "CPS", "1.3.6.1.5.5.7.2.2": "userNotice",

	// EKU
	"1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning",
	"1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
	"2.5.29.37.0": "anyExtendedKeyUsage", "2.23.136.1.1.3": "ICAO masterListSigner",
	"2.23.136.1.1.8": "ICAO deviationListSigner", "1.3.6.1.4.1.311.20.2.2": "msSmartcardLogon",
	"1.3.6.1.4.1.311.10.3.12": "msDocumentSigning", "1.2.840.113583.1.1.5": "adobePDFSigning",
	"1.3.6.1.5.5.7.3.36": "documentSigning",

	// CMS / PKCS
	"1.2.840.113549.1.7.1": "data", "1.2.840.113549.1.7.2": "signedData", "1.2.840.113549.1.7.3": "envelopedData",
	"1.2.840.113549.1.7.6": "encryptedData", "1.2.840.113549.1.9.3": "contentType",
	"1.2.840.113549.1.9.4": "messageDigest", "1.2.840.113549.1.9.5": "signingTime",
	"1.2.840.113549.1.9.7": "challengePassword", "1.2.840.113549.1.9.14": "extensionRequest",
	"1.2.840.113549.1.9.16.2.47": "signingCertificateV2", "1.2.840.113549.1.9.16.2.12": "signingCertificate",
	"1.2.840.113549.1.9.16.1.4": "TSTInfo", "1.2.840.113549.1.5.13": "PBES2",
	"2.23.136.1.1.1": "ICAO LDSSecurityObject", "2.23.136.1.1.2": "ICAO CscaMasterList",
	"2.23.136.1.1.7": "ICAO DeviationList",
}

func oidName(s string) string { return oidNames[s] }

func oidLabel(o asn1.ObjectIdentifier) string {
	s := o.String()
	if n := oidNames[s]; n != "" {
		return n + " (" + s + ")"
	}
	return s
}

func oidShort(o asn1.ObjectIdentifier) string {
	s := o.String()
	if n := oidNames[s]; n != "" {
		return n
	}
	return s
}

func mustOID(s string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		o = append(o, n)
	}
	return o
}

var (
	oidKU        = "2.5.29.15"
	oidEKU       = "2.5.29.37"
	oidBC        = "2.5.29.19"
	oidSKI       = "2.5.29.14"
	oidAKI       = "2.5.29.35"
	oidSAN       = "2.5.29.17"
	oidIAN       = "2.5.29.18"
	oidCRLDP     = "2.5.29.31"
	oidAIA       = "1.3.6.1.5.5.7.1.1"
	oidSIA       = "1.3.6.1.5.5.7.1.11"
	oidPolicies  = "2.5.29.32"
	oidPKUP      = "2.5.29.16"
	oidNC        = "2.5.29.30"
	oidPolCons   = "2.5.29.36"
	oidPolMap    = "2.5.29.33"
	oidInhibit   = "2.5.29.54"
	oidFreshest  = "2.5.29.46"
	oidDocType   = "2.23.136.1.1.6.2"
	oidNameChg   = "2.23.136.1.1.6.1"
	oidSCT       = "1.3.6.1.4.1.11129.2.4.2"
	oidPoison    = "1.3.6.1.4.1.11129.2.4.3"
	oidTLSFeat   = "1.3.6.1.5.5.7.1.24"
	oidOCSPNoChk = "1.3.6.1.5.5.7.48.1.5"
	oidQC        = "1.3.6.1.5.5.7.1.3"

	ekuServer   = "1.3.6.1.5.5.7.3.1"
	ekuAny      = "2.5.29.37.0"
	ekuICAOML   = "2.23.136.1.1.3"
	ekuICAODL   = "2.23.136.1.1.8"
	ekuOCSPSign = "1.3.6.1.5.5.7.3.9"
)

// extensions this engine understands (for the "unknown critical" rule).
var knownExt = map[string]bool{
	oidKU: true, oidEKU: true, oidBC: true, oidSKI: true, oidAKI: true, oidSAN: true, oidIAN: true,
	oidCRLDP: true, oidAIA: true, oidSIA: true, oidPolicies: true, oidPKUP: true, oidNC: true,
	oidPolCons: true, oidPolMap: true, oidInhibit: true, oidFreshest: true, oidDocType: true,
	oidNameChg: true, oidSCT: true, oidPoison: true, oidTLSFeat: true, oidOCSPNoChk: true, oidQC: true,
	"2.5.29.9": true, "2.16.840.1.113730.1.1": true, "2.16.840.1.113730.1.13": true,
	"1.3.6.1.4.1.311.20.2": true, "1.3.6.1.4.1.311.21.7": true, "1.3.6.1.4.1.311.21.1": true,
	"1.3.6.1.4.1.311.21.2": true, "1.3.6.1.4.1.311.21.10": true, "1.3.6.1.4.1.311.25.2": true,
}
