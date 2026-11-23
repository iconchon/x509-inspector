package engine

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type revEntry struct {
	SerialRaw []byte
	Serial    *big.Int
	Date      time.Time
	Reason    string
}

// CRL is a leniently parsed certificate revocation list.
type CRL struct {
	Obj        *Object
	DER        []byte
	TBS        []byte
	Version    int
	SigOuter   pkix.AlgorithmIdentifier
	SigInner   pkix.AlgorithmIdentifier
	Signature  []byte
	Issuer     *DN
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    []revEntry
	Exts       []pkix.Extension
	AKIKeyID   []byte
	Number     *big.Int
	IsDelta    bool
	IDP        bool

	IssuerCert *Cert
	SigStatus  string
	Online     string // URL it was fetched from
}

var reasonNames = map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise"}

func parseCRL(der []byte) (*CRL, error) {
	outer, rest, err := readTLV(der)
	if err != nil || !outer.is(clsUniversal, 16) {
		return nil, errors.New("bukan SEQUENCE")
	}
	if len(rest) > 0 {
		return nil, errors.New("data sisa")
	}
	parts, err := children(outer.Content)
	if err != nil || len(parts) != 3 || !parts[0].is(clsUniversal, 16) || !parts[2].is(clsUniversal, 3) {
		return nil, errors.New("struktur CertificateList tidak sesuai")
	}
	r := &CRL{DER: der, TBS: parts[0].Full, Version: 1}
	if _, err := asn1.Unmarshal(parts[1].Full, &r.SigOuter); err != nil {
		return nil, errors.New("signatureAlgorithm rusak")
	}
	if len(parts[2].Content) > 0 {
		r.Signature = parts[2].Content[1:]
	}
	tk, _ := children(parts[0].Content)
	i := 0
	if i < len(tk) && tk[i].is(clsUniversal, 2) {
		r.Version = int(new(big.Int).SetBytes(tk[i].Content).Int64()) + 1
		i++
	}
	if i >= len(tk) || !tk[i].is(clsUniversal, 16) {
		return nil, errors.New("signature (tbs) tidak ada")
	}
	if _, err := asn1.Unmarshal(tk[i].Full, &r.SigInner); err != nil {
		return nil, errors.New("signature (tbs) rusak")
	}
	i++
	if i >= len(tk) || !tk[i].is(clsUniversal, 16) {
		return nil, errors.New("issuer tidak ada")
	}
	r.Issuer = parseDN(tk[i].Full)
	i++
	if i >= len(tk) || (tk[i].Tag != 23 && tk[i].Tag != 24) {
		return nil, errors.New("thisUpdate tidak ada")
	}
	r.Obj = &Object{Kind: "crl", der: der, pemTyp: "X509 CRL"}
	var note string
	r.ThisUpdate, note = parseTimeAny(tk[i])
	if note != "" {
		r.Obj.add(SevWarn, "Waktu", "thisUpdate: "+note)
	}
	i++
	if i < len(tk) && tk[i].Class == 0 && (tk[i].Tag == 23 || tk[i].Tag == 24) {
		r.NextUpdate, note = parseTimeAny(tk[i])
		if note != "" {
			r.Obj.add(SevWarn, "Waktu", "nextUpdate: "+note)
		}
		i++
	}
	if i < len(tk) && tk[i].is(clsUniversal, 16) {
		ents, _ := children(tk[i].Content)
		for _, e := range ents {
			ek, _ := children(e.Content)
			if len(ek) < 2 {
				continue
			}
			re := revEntry{SerialRaw: ek[0].Content, Serial: new(big.Int).SetBytes(ek[0].Content)}
			re.Date, _ = parseTimeAny(ek[1])
			if len(ek) > 2 {
				var exts []pkix.Extension
				asn1.Unmarshal(ek[2].Full, &exts)
				for _, x := range exts {
					if x.Id.String() == "2.5.29.21" {
						var en asn1.Enumerated
						if _, err := asn1.Unmarshal(x.Value, &en); err == nil {
							re.Reason = reasonNames[int(en)]
						}
					}
				}
			}
			r.Revoked = append(r.Revoked, re)
		}
		i++
	}
	if i < len(tk) && tk[i].is(clsContext, 0) {
		asn1.Unmarshal(tk[i].Content, &r.Exts)
	}
	return r, nil
}

func buildCRLObject(r *CRL, at time.Time) {
	o := r.Obj
	o.Label = "CRL " + r.Issuer.Short()
	ef := []Field{}
	for _, e := range r.Exts {
		id := e.Id.String()
		f := Field{N: oidLabel(e.Id)}
		switch id {
		case "2.5.29.20":
			var n *big.Int
			if _, err := asn1.Unmarshal(e.Value, &n); err == nil {
				r.Number = n
				f.V = n.String()
			}
		case "2.5.29.27":
			r.IsDelta = true
			f.V = "delta CRL"
		case "2.5.29.35":
			t, _, err := readTLV(e.Value)
			if err == nil {
				kids, _ := children(t.Content)
				for _, k := range kids {
					if k.is(clsContext, 0) {
						r.AKIKeyID = k.Content
						f.V = hexColon(k.Content)
					}
				}
			}
		case "2.5.29.28":
			r.IDP = true
			f.V = "ada"
			if !e.Critical {
				o.add(SevWarn, "Ekstensi", "issuingDistributionPoint harus critical", "", "RFC 5280 §5.2.5")
			}
		default:
			f.V = hexShort(e.Value, 32)
			if e.Critical {
				o.add(SevError, "Ekstensi", "Ekstensi CRL critical tidak dikenal: "+oidLabel(e.Id))
			}
		}
		ef = append(ef, f)
	}
	sum := sha256.Sum256(r.DER)
	revF := Field{N: "Sertifikat dicabut", V: fmt.Sprint(len(r.Revoked))}
	for i, e := range r.Revoked {
		if i >= 500 {
			revF.K = append(revF.K, Field{N: "…", V: fmt.Sprintf("%d entri lagi tidak ditampilkan", len(r.Revoked)-500)})
			break
		}
		v := e.Date.UTC().Format("2006-01-02 15:04")
		if e.Reason != "" {
			v += " — " + e.Reason
		}
		revF.K = append(revF.K, Field{N: hexColon(e.SerialRaw), V: v})
	}
	o.Fields = []Field{
		{N: "Versi", V: fmt.Sprintf("v%d", r.Version)},
		{N: "Algoritma tanda tangan", V: sigName(r.SigOuter)},
		dnField("Issuer", r.Issuer),
		{N: "thisUpdate", V: fmtTime(r.ThisUpdate)},
		{N: "nextUpdate", V: fmtTime(r.NextUpdate)},
		revF,
		{N: "Ekstensi", V: fmt.Sprint(len(r.Exts)), K: ef},
		{N: "SHA-256", V: hexColon(sum[:])},
	}
	o.sum("Issuer", r.Issuer.String())
	o.sum("thisUpdate", fmtTime(r.ThisUpdate))
	o.sum("nextUpdate", fmtTime(r.NextUpdate))
	if r.Number != nil {
		o.sum("CRL number", r.Number.String())
	}
	o.sum("Jumlah dicabut", fmt.Sprint(len(r.Revoked)))
	o.sum("Tanda tangan", sigName(r.SigOuter))
	if r.Online != "" {
		o.sum("Diunduh dari", r.Online)
	}

	dnFindings(o, r.Issuer, "Issuer")
	if len(r.Exts) > 0 && r.Version != 2 {
		o.add(SevError, "Struktur", "CRL memiliki ekstensi tetapi bukan v2", "", "RFC 5280 §5.1.2.1")
	}
	if !r.SigInner.Algorithm.Equal(r.SigOuter.Algorithm) {
		o.add(SevError, "Tanda tangan", "Algoritma tanda tangan TBS ≠ luar")
	}
	sigAlgFindings(o, r.SigOuter, nil, false)
	if r.NextUpdate.IsZero() {
		o.add(SevWarn, "Waktu", "CRL tanpa nextUpdate", "", "RFC 5280 §5.1.2.5")
	} else {
		if !r.NextUpdate.After(r.ThisUpdate) {
			o.add(SevError, "Waktu", "nextUpdate tidak lebih besar dari thisUpdate")
		}
		if at.After(r.NextUpdate) {
			o.add(SevError, "Waktu", "CRL sudah kedaluwarsa (nextUpdate lewat)", fmt.Sprintf("Lewat %s — ambil CRL terbaru.", roughDur(at.Sub(r.NextUpdate))))
		} else {
			o.add(SevOK, "Waktu", "CRL masih berlaku", fmt.Sprintf("nextUpdate dalam %s", roughDur(r.NextUpdate.Sub(at))))
		}
	}
	if at.Before(r.ThisUpdate) {
		o.add(SevWarn, "Waktu", "thisUpdate di masa depan")
	}
	if r.Version == 2 {
		if r.AKIKeyID == nil {
			o.add(SevWarn, "Ekstensi", "CRL tanpa authorityKeyIdentifier", "", "RFC 5280 §5.2.1")
		}
		if r.Number == nil {
			o.add(SevWarn, "Ekstensi", "CRL tanpa cRLNumber", "", "RFC 5280 §5.2.3")
		}
	}
	seen := map[string]bool{}
	for _, e := range r.Revoked {
		k := string(e.SerialRaw)
		if seen[k] {
			o.add(SevWarn, "Struktur", "Serial ganda di daftar revokasi: "+hexColon(e.SerialRaw))
			break
		}
		seen[k] = true
	}
}
