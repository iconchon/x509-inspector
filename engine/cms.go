package engine

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CMS is a PKCS#7 / CMS SignedData container (p7b, p7c, ICAO master list, SOD...).
type CMS struct {
	Obj          *Object
	DER          []byte
	ContentType  string
	EContentType string
	EContent     []byte
	CertDER      [][]byte
	CRLDER       [][]byte
	Signers      []*signerInfo
	SODWrapped   bool
	MLCerts      [][]byte // CscaMasterList contents
	LDS          *ldsInfo
}

type signerInfo struct {
	Version      int
	SIDIssuer    *DN
	SIDSerial    []byte
	SIDSKI       []byte
	DigestAlg    pkix.AlgorithmIdentifier
	SignedAttrs  []byte // full [0] element (re-tagged to SET for verification)
	SigAlg       pkix.AlgorithmIdentifier
	Signature    []byte
	MsgDigest    []byte
	CTypeAttr    string
	SigningTime  time.Time
	SignerCert   *Cert
}

type ldsInfo struct {
	Version  int
	HashAlg  string
	DGs      []KV
}

func parseCMS(der []byte) (*CMS, error) {
	m := &CMS{DER: der}
	t, _, err := readTLV(der)
	if err != nil {
		return nil, err
	}
	if t.is(clsApp, 23) { // ICAO EF.SOD wrapper 0x77
		m.SODWrapped = true
		inner, _, err := readTLV(t.Content)
		if err != nil {
			return nil, errors.New("isi EF.SOD rusak")
		}
		t = inner
	}
	if !t.is(clsUniversal, 16) {
		return nil, errors.New("ContentInfo bukan SEQUENCE")
	}
	kids, err := children(t.Content)
	if err != nil || len(kids) < 1 || !kids[0].is(clsUniversal, 6) {
		return nil, errors.New("ContentInfo tidak sesuai")
	}
	m.ContentType, _ = oidString(kids[0].Content)
	if m.ContentType != "1.2.840.113549.1.7.2" {
		return m, nil // recognised container, but not SignedData
	}
	if len(kids) < 2 || !kids[1].is(clsContext, 0) {
		return nil, errors.New("SignedData kosong")
	}
	sdT, _, err := readTLV(kids[1].Content)
	if err != nil {
		return nil, err
	}
	sd, err := children(sdT.Content)
	if err != nil || len(sd) < 3 {
		return nil, errors.New("SignedData rusak")
	}
	i := 1 // version
	i++    // digestAlgorithms
	if i < len(sd) {
		eci, _ := children(sd[i].Content)
		if len(eci) > 0 {
			m.EContentType, _ = oidString(eci[0].Content)
		}
		if len(eci) > 1 && eci[1].is(clsContext, 0) {
			oc, _, err := readTLV(eci[1].Content)
			if err == nil {
				m.EContent = oc.Content
			}
		}
		i++
	}
	for ; i < len(sd); i++ {
		switch {
		case sd[i].is(clsContext, 0):
			cs, _ := children(sd[i].Content)
			for _, c := range cs {
				if c.is(clsUniversal, 16) {
					m.CertDER = append(m.CertDER, c.Full)
				}
			}
		case sd[i].is(clsContext, 1):
			cs, _ := children(sd[i].Content)
			for _, c := range cs {
				if c.is(clsUniversal, 16) {
					m.CRLDER = append(m.CRLDER, c.Full)
				}
			}
		case sd[i].is(clsUniversal, 17):
			sis, _ := children(sd[i].Content)
			for _, s := range sis {
				if si := parseSignerInfo(s); si != nil {
					m.Signers = append(m.Signers, si)
				}
			}
		}
	}
	switch m.EContentType {
	case "2.23.136.1.1.2": // CscaMasterList ::= SEQUENCE { version, certList SET OF Certificate }
		if ml, _, err := readTLV(m.EContent); err == nil {
			mk, _ := children(ml.Content)
			if len(mk) >= 2 {
				cs, _ := children(mk[1].Content)
				for _, c := range cs {
					m.MLCerts = append(m.MLCerts, c.Full)
				}
			}
		}
	case "2.23.136.1.1.1":
		m.LDS = parseLDS(m.EContent)
	}
	return m, nil
}

func parseSignerInfo(s tlv) *signerInfo {
	k, err := children(s.Content)
	if err != nil || len(k) < 5 {
		return nil
	}
	si := &signerInfo{}
	si.Version = int(new(big.Int).SetBytes(k[0].Content).Int64())
	switch {
	case k[1].is(clsUniversal, 16):
		ik, _ := children(k[1].Content)
		if len(ik) == 2 {
			si.SIDIssuer = parseDN(ik[0].Full)
			si.SIDSerial = ik[1].Content
		}
	case k[1].is(clsContext, 0):
		si.SIDSKI = k[1].Content
	}
	asn1.Unmarshal(k[2].Full, &si.DigestAlg)
	j := 3
	if k[j].is(clsContext, 0) {
		si.SignedAttrs = k[j].Full
		attrs, _ := children(k[j].Content)
		for _, a := range attrs {
			ak, _ := children(a.Content)
			if len(ak) < 2 {
				continue
			}
			oid, _ := oidString(ak[0].Content)
			vals, _ := children(ak[1].Content)
			if len(vals) == 0 {
				continue
			}
			switch oid {
			case "1.2.840.113549.1.9.4":
				si.MsgDigest = vals[0].Content
			case "1.2.840.113549.1.9.3":
				si.CTypeAttr, _ = oidString(vals[0].Content)
			case "1.2.840.113549.1.9.5":
				si.SigningTime, _ = parseTimeAny(vals[0])
			}
		}
		j++
	}
	if j+1 >= len(k) {
		return si
	}
	asn1.Unmarshal(k[j].Full, &si.SigAlg)
	si.Signature = k[j+1].Content
	return si
}

func parseLDS(b []byte) *ldsInfo {
	t, _, err := readTLV(b)
	if err != nil {
		return nil
	}
	k, _ := children(t.Content)
	if len(k) < 3 {
		return nil
	}
	l := &ldsInfo{Version: int(new(big.Int).SetBytes(k[0].Content).Int64())}
	var alg pkix.AlgorithmIdentifier
	asn1.Unmarshal(k[1].Full, &alg)
	l.HashAlg = oidShort(alg.Algorithm)
	dgs, _ := children(k[2].Content)
	for _, d := range dgs {
		dk, _ := children(d.Content)
		if len(dk) == 2 {
			l.DGs = append(l.DGs, KV{fmt.Sprintf("DG%d", new(big.Int).SetBytes(dk[0].Content).Int64()), hexShort(dk[1].Content, 64)})
		}
	}
	return l
}

func cmsKind(m *CMS) string {
	switch {
	case m.SODWrapped || m.EContentType == "2.23.136.1.1.1":
		return "ICAO EF.SOD (LDS Security Object)"
	case m.EContentType == "2.23.136.1.1.2":
		return "ICAO CSCA Master List"
	case m.EContentType == "2.23.136.1.1.7":
		return "ICAO Deviation List"
	case m.ContentType == "1.2.840.113549.1.7.2" && len(m.Signers) == 0:
		return "PKCS#7 bundle sertifikat"
	case m.ContentType == "1.2.840.113549.1.7.2":
		return "CMS SignedData"
	}
	return "CMS " + oidLabelS(m.ContentType)
}

// verifyCMS checks every SignerInfo; signer certs are looked up in pool.
func verifyCMS(m *CMS, pool []*Cert, at time.Time) {
	o := m.Obj
	if m.ContentType != "1.2.840.113549.1.7.2" {
		o.add(SevInfo, "CMS", "Tipe konten "+oidLabelS(m.ContentType)+" — tidak diverifikasi")
		return
	}
	if len(m.Signers) == 0 {
		if len(m.CertDER) > 0 {
			o.add(SevOK, "CMS", fmt.Sprintf("Bundle berisi %d sertifikat dan %d CRL (tanpa penanda tangan)", len(m.CertDER), len(m.CRLDER)))
		}
		return
	}
	for n, si := range m.Signers {
		tag := fmt.Sprintf("Signer #%d: ", n+1)
		for _, c := range pool {
			if si.SIDSKI != nil && bytes.Equal(c.X.SKI, si.SIDSKI) {
				si.SignerCert = c
				break
			}
			if si.SIDIssuer != nil && bytes.Equal(c.SerialRaw, si.SIDSerial) {
				if ok, _ := sameName(c.Issuer, si.SIDIssuer); ok {
					si.SignerCert = c
					break
				}
			}
		}
		h, ok := hashByOID[si.DigestAlg.Algorithm.String()]
		if !ok {
			o.add(SevWarn, "CMS", tag+"algoritma digest tidak dikenal: "+oidLabel(si.DigestAlg.Algorithm))
			continue
		}
		if h == crypto.SHA1 || h == crypto.MD5 {
			o.add(SevWarn, "CMS", tag+"memakai digest lemah "+h.String())
		}
		signed := m.EContent
		if si.SignedAttrs != nil {
			if si.MsgDigest == nil {
				o.add(SevError, "CMS", tag+"signedAttrs tanpa atribut messageDigest")
			} else if m.EContent != nil {
				d := h.New()
				d.Write(m.EContent)
				if bytes.Equal(d.Sum(nil), si.MsgDigest) {
					o.add(SevOK, "CMS", tag+"messageDigest cocok dengan isi (konten tidak berubah)")
				} else {
					o.add(SevError, "CMS", tag+"messageDigest TIDAK cocok — isi telah dimodifikasi")
				}
			} else {
				o.add(SevInfo, "CMS", tag+"tanda tangan detached (konten tidak disertakan) — messageDigest tidak bisa dicek")
			}
			if si.CTypeAttr != "" && si.CTypeAttr != m.EContentType {
				o.add(SevError, "CMS", tag+"atribut contentType ≠ eContentType")
			}
			signed = append([]byte{0x31}, si.SignedAttrs[1:]...)
		}
		if !si.SigningTime.IsZero() {
			o.add(SevInfo, "CMS", tag+"signingTime "+fmtTime(si.SigningTime))
		}
		if si.SignerCert == nil {
			o.add(SevWarn, "CMS", tag+"sertifikat penanda tangan tidak ditemukan", "Tambahkan sertifikat penanda tangan (mis. DS / Master List Signer) untuk verifikasi tanda tangan.")
			continue
		}
		st, msg := verifySig(si.SignerCert.Pub, si.SigAlg, signed, si.Signature, h)
		lbl := si.SignerCert.Label()
		switch st {
		case vOK:
			o.add(SevOK, "CMS", tag+"tanda tangan valid oleh \""+lbl+"\"")
		case vBad:
			o.add(SevError, "CMS", tag+"tanda tangan TIDAK valid", msg)
		default:
			o.add(SevInfo, "CMS", tag+"tanda tangan tidak bisa diverifikasi", msg)
		}
		sc := si.SignerCert
		if !si.SigningTime.IsZero() && (si.SigningTime.Before(sc.NotBefore) || si.SigningTime.After(sc.NotAfter)) {
			o.add(SevWarn, "CMS", tag+"signingTime di luar masa berlaku sertifikat penanda tangan")
		}
		if sc.X.PKUPAfter != nil && !si.SigningTime.IsZero() && si.SigningTime.After(*sc.X.PKUPAfter) {
			o.add(SevWarn, "CMS", tag+"ditandatangani setelah masa pakai kunci (privateKeyUsagePeriod) berakhir")
		}
		if m.EContentType == "2.23.136.1.1.2" {
			found := false
			for _, e := range sc.X.EKU {
				if e == ekuICAOML {
					found = true
				}
			}
			if !found {
				o.add(SevWarn, "ICAO", tag+"penanda tangan Master List tidak memiliki EKU masterListSigner (2.23.136.1.1.3)")
			}
		}
	}
}

func buildCMSObject(m *CMS) {
	o := m.Obj
	o.Label = cmsKind(m)
	o.sum("Jenis", cmsKind(m))
	o.sum("contentType", oidLabelS(m.ContentType))
	if m.EContentType != "" {
		o.sum("eContentType", oidLabelS(m.EContentType))
	}
	o.sum("Sertifikat", fmt.Sprint(len(m.CertDER)+len(m.MLCerts)))
	if len(m.CRLDER) > 0 {
		o.sum("CRL", fmt.Sprint(len(m.CRLDER)))
	}
	o.sum("Penanda tangan", fmt.Sprint(len(m.Signers)))
	o.Fields = []Field{{N: "contentType", V: oidLabelS(m.ContentType)}}
	if m.EContentType != "" {
		o.Fields = append(o.Fields, Field{N: "eContentType", V: oidLabelS(m.EContentType)}, Field{N: "eContent", V: fmt.Sprintf("%d byte", len(m.EContent))})
	}
	if len(m.MLCerts) > 0 {
		o.Fields = append(o.Fields, Field{N: "CSCA di Master List", V: fmt.Sprint(len(m.MLCerts))})
	}
	for n, si := range m.Signers {
		f := Field{N: fmt.Sprintf("SignerInfo #%d", n+1), K: []Field{
			{N: "digestAlgorithm", V: oidLabel(si.DigestAlg.Algorithm)},
			{N: "signatureAlgorithm", V: sigName(si.SigAlg)},
		}}
		if si.SIDIssuer != nil {
			f.K = append(f.K, Field{N: "issuer", V: si.SIDIssuer.String()}, Field{N: "serial", V: hexColon(si.SIDSerial)})
		}
		if si.SIDSKI != nil {
			f.K = append(f.K, Field{N: "subjectKeyIdentifier", V: hexColon(si.SIDSKI)})
		}
		if !si.SigningTime.IsZero() {
			f.K = append(f.K, Field{N: "signingTime", V: fmtTime(si.SigningTime)})
		}
		o.Fields = append(o.Fields, f)
	}
	if m.LDS != nil {
		f := Field{N: "LDS Security Object", V: fmt.Sprintf("v%d, hash %s", m.LDS.Version, m.LDS.HashAlg)}
		for _, d := range m.LDS.DGs {
			f.K = append(f.K, Field{N: d.K, V: d.V})
		}
		o.Fields = append(o.Fields, f)
		o.sum("Data group", fmt.Sprint(len(m.LDS.DGs)))
	}
	if m.EContentType == "2.23.136.1.1.2" && len(m.MLCerts) == 0 {
		o.add(SevWarn, "ICAO", "Master List tidak berisi sertifikat CSCA")
	}
}
