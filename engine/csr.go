package engine

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CSR is a PKCS#10 certification request.
type CSR struct {
	Obj       *Object
	DER       []byte
	Info      []byte
	Version   int
	Subject   *DN
	Pub       *PubKey
	SigAlg    pkix.AlgorithmIdentifier
	Signature []byte
	Exts      []pkix.Extension
	Attrs     []string
}

func parseCSR(der []byte) (*CSR, error) {
	outer, rest, err := readTLV(der)
	if err != nil || !outer.is(clsUniversal, 16) || len(rest) > 0 {
		return nil, errors.New("bukan SEQUENCE tunggal")
	}
	parts, err := children(outer.Content)
	if err != nil || len(parts) != 3 || !parts[0].is(clsUniversal, 16) || !parts[2].is(clsUniversal, 3) {
		return nil, errors.New("struktur CertificationRequest tidak sesuai")
	}
	r := &CSR{DER: der, Info: parts[0].Full}
	if _, err := asn1.Unmarshal(parts[1].Full, &r.SigAlg); err != nil {
		return nil, errors.New("algoritma rusak")
	}
	if len(parts[2].Content) > 0 {
		r.Signature = parts[2].Content[1:]
	}
	ik, _ := children(parts[0].Content)
	if len(ik) < 3 || !ik[0].is(clsUniversal, 2) || !ik[1].is(clsUniversal, 16) || !ik[2].is(clsUniversal, 16) {
		return nil, errors.New("CertificationRequestInfo tidak sesuai")
	}
	// A certificate TBS would start with [0] or have more elements; a CSR info has exactly version,subject,spki,[0]attrs
	if len(ik) > 4 {
		return nil, errors.New("bukan CSR")
	}
	r.Version = int(new(big.Int).SetBytes(ik[0].Content).Int64()) + 1
	r.Subject = parseDN(ik[1].Full)
	r.Pub = parseSPKI(ik[2].Full)
	if r.Pub.AlgOID == "" {
		return nil, errors.New("SubjectPublicKeyInfo tidak valid")
	}
	r.Obj = &Object{Kind: "csr", der: der, pemTyp: "CERTIFICATE REQUEST"}
	if len(ik) == 4 && ik[3].is(clsContext, 0) {
		attrs, _ := children(ik[3].Content)
		for _, a := range attrs {
			ak, _ := children(a.Content)
			if len(ak) < 2 {
				continue
			}
			oid, _ := oidString(ak[0].Content)
			r.Attrs = append(r.Attrs, oid)
			if oid == "1.2.840.113549.1.9.14" {
				vals, _ := children(ak[1].Content)
				if len(vals) > 0 {
					asn1.Unmarshal(vals[0].Full, &r.Exts)
				}
			}
		}
	}
	return r, nil
}

func buildCSRObject(r *CSR, opts Options, at time.Time) {
	o := r.Obj
	o.Label = "CSR " + r.Subject.Short()
	extFields, x := parseExtensions(o, r.Exts, "csr")
	var attrF []Field
	for _, a := range r.Attrs {
		v := ""
		if a == "1.2.840.113549.1.9.7" {
			v = "(disembunyikan)"
			o.add(SevWarn, "Keamanan", "CSR berisi challengePassword (teks polos di dalam CSR)")
		}
		attrF = append(attrF, Field{N: oidLabelS(a), V: v})
	}
	o.Fields = []Field{
		{N: "Versi", V: fmt.Sprintf("v%d", r.Version)},
		dnField("Subject", r.Subject),
		keyFields(r.Pub),
		{N: "Atribut", V: fmt.Sprint(len(r.Attrs)), K: attrF},
		{N: "Ekstensi yang diminta", V: fmt.Sprint(len(r.Exts)), K: extFields},
		{N: "Algoritma tanda tangan", V: sigName(r.SigAlg)},
	}
	o.sum("Subject", r.Subject.String())
	o.sum("Kunci", r.Pub.Describe())
	o.sum("Tanda tangan", sigName(r.SigAlg))
	if len(x.SAN) > 0 {
		var s []string
		for _, g := range x.SAN {
			s = append(s, g.String())
		}
		o.sum("SAN", fmt.Sprint(s))
	}
	if r.Version != 1 {
		o.add(SevError, "Struktur", "Versi CSR harus v1 (0)", "", "RFC 2986")
	}
	dnFindings(o, r.Subject, "Subject")
	if r.Subject.Empty() && !x.SANPresent {
		o.add(SevWarn, "Nama", "CSR tanpa subject dan tanpa SAN")
	}
	keyFindings(o, r.Pub, "Kunci")
	sigAlgFindings(o, r.SigAlg, r.Pub, true)
	st, msg := verifySig(r.Pub, r.SigAlg, r.Info, r.Signature, 0)
	switch st {
	case vOK:
		o.add(SevOK, "Tanda tangan", "Tanda tangan CSR valid (proof-of-possession kunci privat)")
	case vBad:
		o.add(SevError, "Tanda tangan", "Tanda tangan CSR TIDAK valid", msg)
	default:
		o.add(SevInfo, "Tanda tangan", "Tanda tangan CSR tidak bisa diverifikasi", msg)
	}
	if h := opts.Hostname; h != "" {
		ok := false
		for _, g := range x.SAN {
			if g.Type == "dns" && matchHostname(g.Value, h) {
				ok = true
			}
		}
		if ok {
			o.add(SevOK, "Hostname", "SAN pada CSR mencakup "+h)
		} else {
			o.add(SevWarn, "Hostname", "SAN pada CSR tidak mencakup "+h)
		}
	}
}
