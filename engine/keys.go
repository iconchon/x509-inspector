package engine

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // legacy DSA certificates still exist
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	_ "crypto/md5"
	"crypto/rsa"
	_ "crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// PubKey is a leniently parsed SubjectPublicKeyInfo.
type PubKey struct {
	Algo     string // RSA, RSA-PSS, EC, Ed25519, Ed448, X25519, X448, DSA, ML-DSA, unknown
	AlgOID   string
	Bits     int
	RSA      *rsa.PublicKey
	RSAN     *big.Int
	RSAE     *big.Int
	EC       *ECPub
	Ed25519  ed25519.PublicKey
	DSA      *dsa.PublicKey
	Raw      []byte // subjectPublicKey bit string content
	SPKI     []byte
	Err      string
	Warnings []string
}

type ECPub struct {
	Curve      *Curve
	Explicit   bool
	NamedOID   string
	X, Y       *big.Int
	Compressed bool
}

type spkiRaw struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkcs1Pub struct {
	N *big.Int
	E *big.Int
}

func parseSPKI(der []byte) *PubKey {
	pk := &PubKey{SPKI: der, Algo: "unknown"}
	var s spkiRaw
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil {
		pk.Err = "SubjectPublicKeyInfo tidak bisa dibaca: " + err.Error()
		return pk
	}
	if len(rest) > 0 {
		pk.Warnings = append(pk.Warnings, "data sisa setelah SubjectPublicKeyInfo")
	}
	return parseKeyFrom(s.Algorithm, s.PublicKey.RightAlign(), der)
}

func parseKeyFrom(alg pkix.AlgorithmIdentifier, raw, spki []byte) *PubKey {
	pk := &PubKey{SPKI: spki, Raw: raw, AlgOID: alg.Algorithm.String(), Algo: "unknown"}
	switch pk.AlgOID {
	case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
		pk.Algo = "RSA"
		if pk.AlgOID == "1.2.840.113549.1.1.10" {
			pk.Algo = "RSA-PSS"
		}
		var k pkcs1Pub
		if _, err := asn1.Unmarshal(raw, &k); err != nil {
			pk.Err = "kunci RSA tidak bisa dibaca: " + err.Error()
			return pk
		}
		pk.RSAN, pk.RSAE = k.N, k.E
		pk.Bits = k.N.BitLen()
		if k.E.IsInt64() && k.E.Int64() > 0 && k.E.Int64() < 1<<31 {
			pk.RSA = &rsa.PublicKey{N: k.N, E: int(k.E.Int64())}
		} else {
			pk.Warnings = append(pk.Warnings, "eksponen publik RSA di luar jangkauan yang didukung")
		}
		if pk.AlgOID == "1.2.840.113549.1.1.1" && len(alg.Parameters.FullBytes) > 0 && alg.Parameters.Tag != asn1.TagNull {
			pk.Warnings = append(pk.Warnings, "parameter rsaEncryption harus NULL")
		}
	case "1.2.840.10045.2.1", "1.3.132.1.12":
		pk.Algo = "EC"
		ec := &ECPub{}
		pk.EC = ec
		params := alg.Parameters
		switch {
		case params.Tag == asn1.TagOID && params.Class == 0:
			var oid asn1.ObjectIdentifier
			asn1.Unmarshal(params.FullBytes, &oid)
			ec.NamedOID = oid.String()
			ec.Curve = curveByOID(ec.NamedOID)
			if ec.Curve == nil {
				pk.Err = "kurva bernama tidak didukung: " + oidLabel(oid)
				return pk
			}
		case params.Tag == asn1.TagSequence:
			c, notes, err := parseExplicitCurve(params.FullBytes)
			pk.Warnings = append(pk.Warnings, notes...)
			ec.Explicit = true
			if err != nil {
				pk.Err = "parameter kurva eksplisit tidak valid: " + err.Error()
				if c == nil {
					return pk
				}
			}
			ec.Curve = c
		case params.Tag == asn1.TagNull:
			pk.Err = "parameter EC implicitlyCA (NULL) tidak didukung"
			return pk
		default:
			pk.Err = "parameter EC tidak ada / tidak dikenal"
			return pk
		}
		pk.Bits = ec.Curve.Bits()
		x, y, comp, err := ec.Curve.decodePoint(raw)
		ec.X, ec.Y, ec.Compressed = x, y, comp
		if err != nil {
			pk.Err = err.Error()
		}
	case "1.3.101.112":
		pk.Algo = "Ed25519"
		pk.Bits = 256
		if len(raw) != ed25519.PublicKeySize {
			pk.Err = "panjang kunci Ed25519 salah"
		} else {
			pk.Ed25519 = ed25519.PublicKey(raw)
		}
	case "1.3.101.113":
		pk.Algo, pk.Bits = "Ed448", 456
	case "1.3.101.110":
		pk.Algo, pk.Bits = "X25519", 255
	case "1.3.101.111":
		pk.Algo, pk.Bits = "X448", 448
	case "1.2.840.10040.4.1":
		pk.Algo = "DSA"
		var p struct{ P, Q, G *big.Int }
		var y *big.Int
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil {
			pk.Err = "parameter DSA tidak ada / rusak"
			return pk
		}
		if _, err := asn1.Unmarshal(raw, &y); err != nil {
			pk.Err = "kunci DSA rusak"
			return pk
		}
		pk.DSA = &dsa.PublicKey{Parameters: dsa.Parameters{P: p.P, Q: p.Q, G: p.G}, Y: y}
		pk.Bits = p.P.BitLen()
	default:
		if strings.HasPrefix(pk.AlgOID, "2.16.840.1.101.3.4.3.") {
			pk.Algo = oidName(pk.AlgOID)
		}
		if strings.HasPrefix(pk.AlgOID, "2.16.840.1.101.3.4.4.") {
			pk.Algo = "ML-KEM"
		}
	}
	return pk
}

func (k *PubKey) Describe() string {
	switch k.Algo {
	case "RSA", "RSA-PSS":
		return fmt.Sprintf("%s %d bit, e=%s", k.Algo, k.Bits, k.RSAE)
	case "EC":
		if k.EC != nil && k.EC.Curve != nil {
			s := "ECDSA " + k.EC.Curve.Name
			if k.EC.Curve.Name == "eksplisit" {
				s = fmt.Sprintf("ECDSA kurva eksplisit tak dikenal (%d bit)", k.Bits)
			}
			if k.EC.Explicit {
				s += " (parameter eksplisit)"
			}
			return s
		}
		return "ECDSA"
	}
	if k.Bits > 0 {
		return fmt.Sprintf("%s %d bit", k.Algo, k.Bits)
	}
	return k.Algo + " (" + k.AlgOID + ")"
}

// Equal compares two public keys mathematically (so explicit vs named params still match).
func (k *PubKey) Equal(o *PubKey) bool {
	if k == nil || o == nil {
		return false
	}
	if k.RSAN != nil && o.RSAN != nil {
		return k.RSAN.Cmp(o.RSAN) == 0 && k.RSAE.Cmp(o.RSAE) == 0
	}
	if k.EC != nil && o.EC != nil && k.EC.X != nil && o.EC.X != nil && k.EC.Curve != nil && o.EC.Curve != nil {
		return k.EC.Curve.P.Cmp(o.EC.Curve.P) == 0 && k.EC.Curve.N.Cmp(o.EC.Curve.N) == 0 &&
			k.EC.X.Cmp(o.EC.X) == 0 && k.EC.Y.Cmp(o.EC.Y) == 0
	}
	return len(k.Raw) > 0 && bytes.Equal(k.Raw, o.Raw)
}

// keyFindings evaluates key strength and sanity.
func keyFindings(o *Object, k *PubKey, cat string) {
	if k.Err != "" {
		o.add(SevError, cat, "Kunci publik bermasalah: "+k.Err)
	}
	for _, w := range k.Warnings {
		o.add(SevWarn, cat, "Kunci publik: "+w)
	}
	switch k.Algo {
	case "RSA", "RSA-PSS":
		if k.RSAN == nil {
			return
		}
		switch {
		case k.Bits < 1024:
			o.add(SevError, cat, fmt.Sprintf("Kunci RSA %d bit sangat lemah (minimal 2048)", k.Bits))
		case k.Bits < 2048:
			o.add(SevWarn, cat, fmt.Sprintf("Kunci RSA %d bit di bawah minimum modern 2048 bit", k.Bits), "", "NIST SP 800-131A")
		default:
			o.add(SevOK, cat, fmt.Sprintf("Kekuatan kunci RSA %d bit memadai", k.Bits))
		}
		if k.RSAN.Bit(0) == 0 {
			o.add(SevError, cat, "Modulus RSA genap — kunci tidak valid")
		}
		e := k.RSAE
		if e.Bit(0) == 0 || e.Cmp(big.NewInt(1)) <= 0 {
			o.add(SevError, cat, "Eksponen publik RSA tidak valid (harus ganjil dan > 1)")
		} else if e.Cmp(big.NewInt(65537)) < 0 {
			o.add(SevWarn, cat, fmt.Sprintf("Eksponen publik RSA kecil (e=%s); disarankan 65537", e))
		}
		if k.Bits%8 != 0 {
			o.add(SevInfo, cat, fmt.Sprintf("Panjang modulus RSA tidak kelipatan 8 (%d bit)", k.Bits))
		}
	case "EC":
		if k.EC == nil || k.EC.Curve == nil {
			return
		}
		c := k.EC.Curve
		if c.Name == "eksplisit" {
			o.add(SevWarn, cat, "Kurva eksplisit tidak cocok dengan kurva standar mana pun — keamanannya tidak bisa dipastikan")
		} else if k.Err == "" {
			o.add(SevOK, cat, "Kunci publik EC valid (titik berada di kurva "+c.Name+")")
		}
		if k.Bits < 224 {
			o.add(SevWarn, cat, fmt.Sprintf("Kurva EC %d bit di bawah minimum modern (224/256 bit)", k.Bits))
		}
		if c.H != 1 {
			o.add(SevInfo, cat, fmt.Sprintf("Cofactor kurva = %d", c.H))
		}
		if k.EC.Explicit {
			o.add(SevInfo, "Kompatibilitas", "Kunci EC memakai parameter kurva eksplisit",
				"Ini lazim (dan diharapkan) pada PKI ICAO 9303, tetapi beberapa library ketat (Go crypto/x509, sebagian Java/Android, browser, Windows CryptoAPI) menolak sertifikat seperti ini.", "RFC 5480 §2.1.1 / ICAO 9303-12")
		}
	case "DSA":
		o.add(SevWarn, cat, "Algoritma DSA sudah usang", "", "FIPS 186-5")
	case "unknown":
		o.add(SevWarn, cat, "Algoritma kunci tidak dikenal: "+oidLabelS(k.AlgOID))
	}
}

func oidLabelS(s string) string {
	if n := oidName(s); n != "" {
		return n + " (" + s + ")"
	}
	return s
}

func keyFields(k *PubKey) Field {
	f := Field{N: "Kunci publik", V: k.Describe()}
	f.K = append(f.K, Field{N: "Algoritma", V: oidLabelS(k.AlgOID)})
	if k.RSAN != nil {
		f.K = append(f.K, Field{N: "Modulus", V: hexShort(k.RSAN.Bytes(), 512)}, Field{N: "Eksponen", V: k.RSAE.String()})
	}
	if k.EC != nil && k.EC.Curve != nil {
		c := k.EC.Curve
		f.K = append(f.K, Field{N: "Kurva", V: c.Name})
		if c.OID != "" {
			f.K = append(f.K, Field{N: "OID kurva", V: c.OID})
		}
		if k.EC.Explicit {
			f.K = append(f.K, Field{N: "Parameter", V: "eksplisit (prime, a, b, G, n, h di-encode langsung)", K: []Field{
				{N: "Prime p", V: hexShort(c.P.Bytes(), 80)}, {N: "a", V: hexShort(c.A.Bytes(), 80)}, {N: "b", V: hexShort(c.B.Bytes(), 80)},
				{N: "Order n", V: hexShort(c.N.Bytes(), 80)}, {N: "Cofactor", V: fmt.Sprint(c.H)},
			}})
		}
		if k.EC.X != nil {
			f.K = append(f.K, Field{N: "X", V: hexShort(k.EC.X.Bytes(), 80)})
		}
		if k.EC.Y != nil {
			f.K = append(f.K, Field{N: "Y", V: hexShort(k.EC.Y.Bytes(), 80)})
		}
		if k.EC.Compressed {
			f.K = append(f.K, Field{N: "Format titik", V: "terkompresi"})
		}
	}
	if k.Ed25519 != nil {
		f.K = append(f.K, Field{N: "Nilai", V: hexShort(k.Ed25519, 64)})
	}
	sum := sha256.Sum256(k.SPKI)
	if len(k.SPKI) > 0 {
		f.K = append(f.K, Field{N: "SPKI SHA-256 (pin)", V: base64.StdEncoding.EncodeToString(sum[:])})
	}
	return f
}

// ---------------- signatures ----------------

type sigInfo struct {
	Name string
	Hash crypto.Hash
	Kind string // RSA, PSS, ECDSA, Ed25519, Ed448, DSA, MLDSA, RAWRSA, RAWEC
	Weak string
}

var sigTable = map[string]sigInfo{
	"1.2.840.113549.1.1.4":    {"md5WithRSAEncryption", crypto.MD5, "RSA", "MD5 rusak secara kriptografis"},
	"1.2.840.113549.1.1.5":    {"sha1WithRSAEncryption", crypto.SHA1, "RSA", "SHA-1 sudah tidak aman untuk tanda tangan"},
	"1.2.840.113549.1.1.14":   {"sha224WithRSAEncryption", crypto.SHA224, "RSA", ""},
	"1.2.840.113549.1.1.11":   {"sha256WithRSAEncryption", crypto.SHA256, "RSA", ""},
	"1.2.840.113549.1.1.12":   {"sha384WithRSAEncryption", crypto.SHA384, "RSA", ""},
	"1.2.840.113549.1.1.13":   {"sha512WithRSAEncryption", crypto.SHA512, "RSA", ""},
	"1.2.840.113549.1.1.10":   {"RSASSA-PSS", 0, "PSS", ""},
	"1.2.840.10045.4.1":       {"ecdsa-with-SHA1", crypto.SHA1, "ECDSA", "SHA-1 sudah tidak aman untuk tanda tangan"},
	"1.2.840.10045.4.3.1":     {"ecdsa-with-SHA224", crypto.SHA224, "ECDSA", ""},
	"1.2.840.10045.4.3.2":     {"ecdsa-with-SHA256", crypto.SHA256, "ECDSA", ""},
	"1.2.840.10045.4.3.3":     {"ecdsa-with-SHA384", crypto.SHA384, "ECDSA", ""},
	"1.2.840.10045.4.3.4":     {"ecdsa-with-SHA512", crypto.SHA512, "ECDSA", ""},
	"2.16.840.1.101.3.4.3.9":  {"ecdsa-with-SHA3-224", crypto.SHA3_224, "ECDSA", ""},
	"2.16.840.1.101.3.4.3.10": {"ecdsa-with-SHA3-256", crypto.SHA3_256, "ECDSA", ""},
	"2.16.840.1.101.3.4.3.11": {"ecdsa-with-SHA3-384", crypto.SHA3_384, "ECDSA", ""},
	"2.16.840.1.101.3.4.3.12": {"ecdsa-with-SHA3-512", crypto.SHA3_512, "ECDSA", ""},
	"2.16.840.1.101.3.4.3.13": {"rsa-with-SHA3-224", crypto.SHA3_224, "RSA", ""},
	"2.16.840.1.101.3.4.3.14": {"rsa-with-SHA3-256", crypto.SHA3_256, "RSA", ""},
	"2.16.840.1.101.3.4.3.15": {"rsa-with-SHA3-384", crypto.SHA3_384, "RSA", ""},
	"2.16.840.1.101.3.4.3.16": {"rsa-with-SHA3-512", crypto.SHA3_512, "RSA", ""},
	"1.3.101.112":             {"Ed25519", 0, "Ed25519", ""},
	"1.3.101.113":             {"Ed448", 0, "Ed448", ""},
	"1.2.840.10040.4.3":       {"dsa-with-sha1", crypto.SHA1, "DSA", "SHA-1/DSA usang"},
	"2.16.840.1.101.3.4.3.1":  {"dsa-with-sha224", crypto.SHA224, "DSA", ""},
	"2.16.840.1.101.3.4.3.2":  {"dsa-with-sha256", crypto.SHA256, "DSA", ""},
	"2.16.840.1.101.3.4.3.17": {"ML-DSA-44", 0, "MLDSA", ""},
	"2.16.840.1.101.3.4.3.18": {"ML-DSA-65", 0, "MLDSA", ""},
	"2.16.840.1.101.3.4.3.19": {"ML-DSA-87", 0, "MLDSA", ""},
	// CMS SignerInfo sometimes carries the bare key algorithm; hash comes from digestAlgorithm.
	"1.2.840.113549.1.1.1": {"rsaEncryption", 0, "RAWRSA", ""},
	"1.2.840.10045.2.1":    {"id-ecPublicKey", 0, "RAWEC", ""},
}

var hashByOID = map[string]crypto.Hash{
	"1.2.840.113549.2.5": crypto.MD5, "1.3.14.3.2.26": crypto.SHA1, "2.16.840.1.101.3.4.2.4": crypto.SHA224,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256, "2.16.840.1.101.3.4.2.2": crypto.SHA384, "2.16.840.1.101.3.4.2.3": crypto.SHA512,
	"2.16.840.1.101.3.4.2.7": crypto.SHA3_224, "2.16.840.1.101.3.4.2.8": crypto.SHA3_256,
	"2.16.840.1.101.3.4.2.9": crypto.SHA3_384, "2.16.840.1.101.3.4.2.10": crypto.SHA3_512,
}

type pssParams struct {
	Hash       pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF        pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength int                      `asn1:"optional,explicit,tag:2,default:20"`
	Trailer    int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func sigName(alg pkix.AlgorithmIdentifier) string {
	if si, ok := sigTable[alg.Algorithm.String()]; ok {
		if si.Kind == "PSS" {
			h, _, salt, err := pssDetails(alg)
			if err == nil {
				return fmt.Sprintf("RSASSA-PSS (%s, salt %d)", hashLabel(h), salt)
			}
		}
		return si.Name
	}
	return oidLabel(alg.Algorithm)
}

func hashLabel(h crypto.Hash) string {
	if h == 0 {
		return "?"
	}
	return h.String()
}

func pssDetails(alg pkix.AlgorithmIdentifier) (crypto.Hash, crypto.Hash, int, error) {
	var p pssParams
	p.SaltLength, p.Trailer = 20, 1
	if len(alg.Parameters.FullBytes) > 0 {
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil {
			return 0, 0, 0, errors.New("parameter PSS rusak")
		}
	}
	h := crypto.SHA1
	if len(p.Hash.Algorithm) > 0 {
		var ok bool
		if h, ok = hashByOID[p.Hash.Algorithm.String()]; !ok {
			return 0, 0, 0, errors.New("hash PSS tidak dikenal")
		}
	}
	mh := crypto.SHA1
	if len(p.MGF.Algorithm) > 0 {
		var inner pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(p.MGF.Parameters.FullBytes, &inner); err == nil {
			if x, ok := hashByOID[inner.Algorithm.String()]; ok {
				mh = x
			}
		}
	}
	return h, mh, p.SaltLength, nil
}

// verify status values
const (
	vOK          = "ok"
	vBad         = "bad"
	vUnsupported = "unsupported"
)

// verifySig checks sig over signed using pub. hint is the digest algorithm for CMS raw-key OIDs.
func verifySig(pub *PubKey, alg pkix.AlgorithmIdentifier, signed, sig []byte, hint crypto.Hash) (string, string) {
	if pub == nil {
		return vUnsupported, "kunci penanda tangan tidak tersedia"
	}
	if pub.Err != "" && pub.RSA == nil && (pub.EC == nil || pub.EC.X == nil || pub.EC.Y == nil) && pub.Ed25519 == nil && pub.DSA == nil {
		return vUnsupported, "kunci penanda tangan rusak: " + pub.Err
	}
	si, ok := sigTable[alg.Algorithm.String()]
	if !ok {
		return vUnsupported, "algoritma tanda tangan tidak didukung: " + oidLabel(alg.Algorithm)
	}
	h := si.Hash
	kind := si.Kind
	if kind == "RAWRSA" {
		kind, h = "RSA", hint
	}
	if kind == "RAWEC" {
		kind, h = "ECDSA", hint
	}
	digest := func(hh crypto.Hash) ([]byte, error) {
		if hh == 0 || !hh.Available() {
			return nil, errors.New("hash tidak tersedia")
		}
		x := hh.New()
		x.Write(signed)
		return x.Sum(nil), nil
	}
	switch kind {
	case "RSA", "PSS":
		if pub.RSA == nil {
			return vBad, "algoritma tanda tangan RSA tetapi kunci penanda tangan bukan RSA"
		}
		if pub.Bits < 1024 {
			return vUnsupported, "kunci RSA < 1024 bit tidak diverifikasi"
		}
		if kind == "PSS" {
			ph, mh, salt, err := pssDetails(alg)
			if err != nil {
				return vBad, err.Error()
			}
			if ph != mh {
				return vUnsupported, "PSS dengan hash MGF1 berbeda tidak didukung"
			}
			d, err := digest(ph)
			if err != nil {
				return vUnsupported, err.Error()
			}
			if err := rsa.VerifyPSS(pub.RSA, ph, d, sig, &rsa.PSSOptions{SaltLength: salt, Hash: ph}); err != nil {
				return vBad, "tanda tangan RSA-PSS tidak cocok"
			}
			return vOK, ""
		}
		d, err := digest(h)
		if err != nil {
			return vUnsupported, err.Error()
		}
		if err := rsa.VerifyPKCS1v15(pub.RSA, h, d, sig); err != nil {
			if strings.Contains(err.Error(), "unsupported") {
				return vUnsupported, err.Error()
			}
			return vBad, "tanda tangan RSA tidak cocok"
		}
		return vOK, ""
	case "ECDSA":
		if pub.EC == nil || pub.EC.Curve == nil || pub.EC.X == nil || pub.EC.Y == nil {
			return vBad, "algoritma tanda tangan ECDSA tetapi kunci penanda tangan bukan EC yang valid"
		}
		var rs struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(sig, &rs)
		if err != nil || len(rest) > 0 {
			return vBad, "encoding tanda tangan ECDSA (r,s) rusak"
		}
		d, err := digest(h)
		if err != nil {
			return vUnsupported, err.Error()
		}
		c := pub.EC.Curve
		if std := stdCurve(c.Name); std != nil {
			ok := ecdsa.Verify(&ecdsa.PublicKey{Curve: std, X: pub.EC.X, Y: pub.EC.Y}, d, rs.R, rs.S)
			if ok {
				return vOK, ""
			}
			return vBad, "tanda tangan ECDSA tidak cocok"
		}
		if c.ecdsaVerify(pub.EC.X, pub.EC.Y, d, rs.R, rs.S) {
			return vOK, ""
		}
		return vBad, "tanda tangan ECDSA tidak cocok"
	case "Ed25519":
		if pub.Ed25519 == nil {
			return vBad, "kunci penanda tangan bukan Ed25519"
		}
		if ed25519.Verify(pub.Ed25519, signed, sig) {
			return vOK, ""
		}
		return vBad, "tanda tangan Ed25519 tidak cocok"
	case "DSA":
		if pub.DSA == nil {
			return vBad, "kunci penanda tangan bukan DSA"
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return vBad, "encoding tanda tangan DSA rusak"
		}
		d, err := digest(h)
		if err != nil {
			return vUnsupported, err.Error()
		}
		if n := (pub.DSA.Q.BitLen() + 7) / 8; len(d) > n {
			d = d[:n]
		}
		if dsa.Verify(pub.DSA, d, rs.R, rs.S) {
			return vOK, ""
		}
		return vBad, "tanda tangan DSA tidak cocok"
	}
	return vUnsupported, si.Name + " belum didukung untuk verifikasi"
}

func stdCurve(name string) elliptic.Curve {
	switch name {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}

// sigAlgFindings checks algorithm strength and key/algorithm consistency.
func sigAlgFindings(o *Object, alg pkix.AlgorithmIdentifier, signer *PubKey, selfSigned bool) {
	si, ok := sigTable[alg.Algorithm.String()]
	if !ok {
		o.add(SevWarn, "Tanda tangan", "Algoritma tanda tangan tidak dikenal: "+oidLabel(alg.Algorithm))
		return
	}
	if si.Weak != "" {
		if selfSigned {
			o.add(SevInfo, "Tanda tangan", si.Name+" pada sertifikat self-signed", si.Weak+". Pada root CA, tanda tangan dirinya sendiri tidak dipakai untuk kepercayaan, jadi dampaknya kecil.")
		} else if si.Hash == crypto.MD5 {
			o.add(SevError, "Tanda tangan", "Algoritma tanda tangan "+si.Name, si.Weak)
		} else {
			o.add(SevWarn, "Tanda tangan", "Algoritma tanda tangan "+si.Name, si.Weak)
		}
	}
	if (si.Kind == "RSA" || si.Kind == "PSS") && len(alg.Parameters.FullBytes) > 0 && si.Kind == "RSA" && alg.Parameters.Tag != asn1.TagNull {
		o.add(SevWarn, "Tanda tangan", "Parameter AlgorithmIdentifier RSA harus NULL")
	}
	if si.Kind == "RSA" && len(alg.Parameters.FullBytes) == 0 {
		o.add(SevInfo, "Tanda tangan", "Parameter NULL tidak ada pada AlgorithmIdentifier RSA", "RFC 4055 mewajibkan NULL; banyak validator tetap menerima.")
	}
	if si.Kind == "ECDSA" && len(alg.Parameters.FullBytes) > 0 {
		o.add(SevWarn, "Tanda tangan", "AlgorithmIdentifier ECDSA tidak boleh berisi parameter", "", "RFC 5758 §3.2")
	}
	if signer != nil && signer.EC != nil && si.Kind == "ECDSA" && signer.EC.Curve != nil {
		hb := si.Hash.Size() * 8
		if hb < signer.EC.Curve.Bits() && hb < 256 {
			o.add(SevInfo, "Tanda tangan", fmt.Sprintf("Hash %s lebih lemah dari kurva %s", si.Hash, signer.EC.Curve.Name))
		}
	}
}
