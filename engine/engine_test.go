package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCurveSelfTest(t *testing.T) {
	cs := knownCurves()
	if len(curveNotes) != 0 {
		t.Fatalf("curves failed self-test: %v", curveNotes)
	}
	if len(cs) != 10 {
		t.Fatalf("expected 10 curves, got %d", len(cs))
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mkCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, priv any) []byte {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }

func findings(o *Object) string {
	var b strings.Builder
	for _, f := range o.Findings {
		b.WriteString(f.Sev + " " + f.Msg + "\n")
	}
	return b.String()
}

func has(o *Object, sev, substr string) bool {
	for _, f := range o.Findings {
		if f.Sev == sev && strings.Contains(f.Msg, substr) {
			return true
		}
	}
	return false
}

func TestChainAndRevocation(t *testing.T) {
	now := time.Now()
	caKey, leafKey := mustKey(t), mustKey(t)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root", Country: []string{"ID"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour * 365), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	caDER := mkCert(t, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "www.example.test"},
		DNSNames: []string{"www.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour * 90),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER := mkCert(t, leafT, ca, &leafKey.PublicKey, caKey)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(5), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(48 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(77), RevocationTime: now.Add(-time.Minute)}}}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	data := append(pemOf(leafDER), pemOf(caDER)...)
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})...)
	rep := Analyze([]Input{{ID: "f1", Name: "bundle.pem", Data: data}}, Options{Hostname: "www.example.test"}, nil)
	if len(rep.Objects) != 3 {
		t.Fatalf("want 3 objects, got %d", len(rep.Objects))
	}
	leaf := rep.Objects[0]
	if !has(leaf, SevOK, "Tanda tangan diverifikasi") {
		t.Errorf("leaf signature not verified:\n%s", findings(leaf))
	}
	if !has(leaf, SevError, "DICABUT") {
		t.Errorf("revocation not detected:\n%s", findings(leaf))
	}
	if !has(leaf, SevOK, "cocok dengan SAN") {
		t.Errorf("hostname not matched:\n%s", findings(leaf))
	}
	if !has(rep.Objects[2], SevOK, "Tanda tangan CRL valid") {
		t.Errorf("CRL signature:\n%s", findings(rep.Objects[2]))
	}
}

// Re-encode a P-256 certificate with explicit EC parameters (ICAO style) and re-sign it.
func TestExplicitParams(t *testing.T) {
	now := time.Now()
	k := mustKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "CSCA Test", Country: []string{"ID"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{9, 9}}
	der := mkCert(t, tmpl, tmpl, &k.PublicKey, k)

	c := curveByOID("1.2.840.10045.3.1.7")
	pt := elliptic.Marshal(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	g := elliptic.Marshal(elliptic.P256(), c.Gx, c.Gy)
	type fieldID struct {
		T asn1.ObjectIdentifier
		P *big.Int
	}
	type curve struct{ A, B []byte }
	params, _ := asn1.Marshal(struct {
		V     int
		F     fieldID
		C     curve
		Base  []byte
		Order *big.Int
		H     int
	}{1, fieldID{asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, c.P}, curve{c.A.FillBytes(make([]byte, 32)), c.B.FillBytes(make([]byte, 32))}, g, c.N, 1})
	spki, _ := asn1.Marshal(struct {
		A pkix.AlgorithmIdentifier
		K asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: asn1.RawValue{FullBytes: params}}, asn1.BitString{Bytes: pt, BitLength: len(pt) * 8}})

	// swap SPKI inside the TBS
	outer, _, _ := readTLV(der)
	parts, _ := children(outer.Content)
	tk, _ := children(parts[0].Content)
	var body []byte
	for i, e := range tk {
		if i == 6 {
			body = append(body, spki...)
		} else {
			body = append(body, e.Full...)
		}
	}
	tbs := encodeTLV(0x30, body)
	h := sha256.Sum256(tbs)
	sig, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
	bs, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	full := encodeTLV(0x30, append(append(append([]byte{}, tbs...), parts[1].Full...), bs...))

	rep := Analyze([]Input{{ID: "f", Name: "csca.der", Data: full}}, Options{}, nil)
	o := rep.Objects[0]
	if o.Kind != "certificate" {
		t.Fatalf("not parsed as certificate: %s", findings(o))
	}
	if !has(o, SevOK, "self-signed valid") {
		t.Errorf("explicit-param signature not verified:\n%s", findings(o))
	}
	if !has(o, SevWarn, "Parser X.509 ketat") {
		t.Errorf("expected stdlib incompatibility warning:\n%s", findings(o))
	}
}

// Generic (math/big) ECDSA must agree with crypto/ecdsa.
func TestGenericECDSA(t *testing.T) {
	k := mustKey(t)
	h := sha256.Sum256([]byte("hello"))
	r, s, _ := ecdsa.Sign(rand.Reader, k, h[:])
	c := curveByOID("1.2.840.10045.3.1.7")
	if !c.ecdsaVerify(k.X, k.Y, h[:], r, s) {
		t.Fatal("generic ECDSA rejected a valid signature")
	}
	h[0] ^= 1
	if c.ecdsaVerify(k.X, k.Y, h[:], r, s) {
		t.Fatal("generic ECDSA accepted a bad signature")
	}
}

func TestGarbageNeverPanics(t *testing.T) {
	inputs := []Input{
		{ID: "a", Name: "a", Data: []byte("hello world")},
		{ID: "b", Name: "b", Data: []byte{0x30, 0x82, 0xff, 0xff, 0x01}},
		{ID: "c", Name: "c", Data: []byte("-----BEGIN CERTIFICATE-----\n!!!notbase64\n-----END CERTIFICATE-----\n")},
		{ID: "d", Name: "d", Data: []byte{}},
		{ID: "e", Name: "e", Data: []byte{0x30, 0x80, 0x02, 0x01, 0x03, 0x00, 0x00}},
	}
	rep := Analyze(inputs, Options{}, nil)
	if len(rep.Files) != len(inputs) {
		t.Fatalf("files: %d", len(rep.Files))
	}
	if rep.Counts[SevError] == 0 {
		t.Fatal("expected errors for garbage input")
	}
}
