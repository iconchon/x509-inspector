package engine

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Cert is a leniently parsed X.509 certificate.
type Cert struct {
	Obj         *Object
	DER         []byte
	TBS         []byte
	Version     int
	SerialRaw   []byte
	Serial      *big.Int
	SigOuter    pkix.AlgorithmIdentifier
	SigInner    pkix.AlgorithmIdentifier
	SigOuterRaw []byte
	SigInnerRaw []byte
	Signature   []byte
	Issuer      *DN
	Subject     *DN
	NotBefore   time.Time
	NotAfter    time.Time
	Pub         *PubKey
	Exts        []pkix.Extension
	X           *ExtInfo
	HasUID      bool
	Std         *x509.Certificate
	StdErr      error
	SelfIssued  bool
	SelfSigned  string // ok | bad | unsupported | ""
	ICAO        bool
	ICAORole    string
	TLSServer   bool

	// set by chain building
	IssuerCert  *Cert
	IssuerSig   string
	Revoked     string
}

func parseCert(der []byte) (*Cert, error) {
	c := &Cert{DER: der}
	outer, rest, err := readTLV(der)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("data sisa setelah sertifikat")
	}
	if !outer.is(clsUniversal, 16) {
		return nil, errors.New("bukan SEQUENCE")
	}
	parts, err := children(outer.Content)
	if err != nil || len(parts) != 3 {
		return nil, errors.New("Certificate harus berisi 3 elemen (tbs, algoritma, tanda tangan)")
	}
	if !parts[0].is(clsUniversal, 16) || !parts[1].is(clsUniversal, 16) || !parts[2].is(clsUniversal, 3) {
		return nil, errors.New("struktur Certificate tidak sesuai")
	}
	c.TBS = parts[0].Full
	c.SigOuterRaw = parts[1].Full
	if _, err := asn1.Unmarshal(parts[1].Full, &c.SigOuter); err != nil {
		return nil, errors.New("signatureAlgorithm rusak")
	}
	if len(parts[2].Content) < 1 {
		return nil, errors.New("signatureValue kosong")
	}
	c.Signature = parts[2].Content[1:]

	tk, err := children(parts[0].Content)
	if err != nil {
		return nil, errors.New("TBSCertificate rusak: " + err.Error())
	}
	i := 0
	c.Version = 1
	if i < len(tk) && tk[i].is(clsContext, 0) {
		inner, _, err := readTLV(tk[i].Content)
		if err != nil || !inner.is(clsUniversal, 2) {
			return nil, errors.New("field version rusak")
		}
		c.Version = int(new(big.Int).SetBytes(inner.Content).Int64()) + 1
		i++
	}
	need := func(tag int, what string) (tlv, error) {
		if i >= len(tk) || !tk[i].is(clsUniversal, tag) {
			return tlv{}, errors.New(what + " tidak ditemukan / salah tipe")
		}
		i++
		return tk[i-1], nil
	}
	ser, err := need(2, "serialNumber")
	if err != nil {
		return nil, err
	}
	c.SerialRaw = ser.Content
	c.Serial = new(big.Int).SetBytes(ser.Content)
	if len(ser.Content) > 0 && ser.Content[0]&0x80 != 0 {
		c.Serial.Sub(c.Serial, new(big.Int).Lsh(big.NewInt(1), uint(len(ser.Content)*8)))
	}
	sa, err := need(16, "signature (tbs)")
	if err != nil {
		return nil, err
	}
	c.SigInnerRaw = sa.Full
	asn1.Unmarshal(sa.Full, &c.SigInner)
	iss, err := need(16, "issuer")
	if err != nil {
		return nil, err
	}
	c.Issuer = parseDN(iss.Full)
	val, err := need(16, "validity")
	if err != nil {
		return nil, err
	}
	vk, _ := children(val.Content)
	if len(vk) != 2 {
		return nil, errors.New("validity harus berisi notBefore dan notAfter")
	}
	sub, err := need(16, "subject")
	if err != nil {
		return nil, err
	}
	c.Subject = parseDN(sub.Full)
	spki, err := need(16, "subjectPublicKeyInfo")
	if err != nil {
		return nil, err
	}
	c.Pub = parseSPKI(spki.Full)
	for ; i < len(tk); i++ {
		switch {
		case tk[i].is(clsContext, 1), tk[i].is(clsContext, 2):
			c.HasUID = true
		case tk[i].is(clsContext, 3):
			if _, err := asn1.Unmarshal(tk[i].Content, &c.Exts); err != nil {
				return nil, errors.New("blok extensions rusak: " + err.Error())
			}
		}
	}
	c.Obj = &Object{Kind: "certificate", der: der, pemTyp: "CERTIFICATE"}
	o := c.Obj
	var notes [2]string
	c.NotBefore, notes[0] = parseTimeAny(vk[0])
	c.NotAfter, notes[1] = parseTimeAny(vk[1])
	for k, n := range notes {
		if n != "" {
			o.add(SevWarn, "Waktu", []string{"notBefore", "notAfter"}[k]+": "+n, "", "RFC 5280 §4.1.2.5")
		}
	}
	for k, t := range vk {
		tm := []time.Time{c.NotBefore, c.NotAfter}[k]
		if t.Tag == 24 && tm.Year() < 2050 && !tm.IsZero() {
			o.add(SevWarn, "Waktu", "Tanggal sebelum 2050 harus memakai UTCTime, bukan GeneralizedTime", "", "RFC 5280 §4.1.2.5")
		}
	}
	return c, nil
}

func (c *Cert) Label() string {
	if c.Subject == nil {
		return "sertifikat"
	}
	return c.Subject.Short()
}

func certRole(c *Cert, profile string) string {
	x := c.X
	ekuHas := func(o string) bool {
		for _, e := range x.EKU {
			if e == o {
				return true
			}
		}
		return false
	}
	upper := strings.ToUpper(c.Subject.String() + " | " + c.Issuer.String())
	c.ICAO = profile == "icao" || (profile == "auto" || profile == "") &&
		(x.DocTypePresent || ekuHas(ekuICAOML) || ekuHas(ekuICAODL) || strings.Contains(upper, "CSCA") ||
			strings.Contains(upper, "DOCUMENT SIGNER") || strings.Contains(upper, "MASTER LIST"))
	c.TLSServer = profile == "tls" || (profile == "auto" || profile == "") && !c.ICAO && !x.IsCA &&
		(ekuHas(ekuServer) || (!x.EKUPresent && hasDNS(x.SAN)))
	if c.ICAO {
		switch {
		case x.IsCA && c.SelfIssued:
			c.ICAORole = "CSCA"
			return "ICAO CSCA (root)"
		case x.IsCA:
			c.ICAORole = "CSCA-link"
			return "ICAO CSCA link"
		case ekuHas(ekuICAOML):
			c.ICAORole = "MLS"
			return "ICAO Master List Signer"
		case ekuHas(ekuICAODL):
			c.ICAORole = "DLS"
			return "ICAO Deviation List Signer"
		default:
			c.ICAORole = "DS"
			return "ICAO Document Signer"
		}
	}
	switch {
	case x.IsCA && c.SelfIssued:
		return "Root CA"
	case x.IsCA:
		return "Intermediate CA"
	case c.Version == 1 && c.SelfIssued:
		return "Root CA (v1)"
	case ekuHas(ekuOCSPSign):
		return "OCSP responder"
	case c.TLSServer:
		return "End-entity (TLS server)"
	case c.SelfIssued:
		return "End-entity self-signed"
	}
	return "End-entity"
}

func hasDNS(gs []GenName) bool {
	for _, g := range gs {
		if g.Type == "dns" {
			return true
		}
	}
	return false
}

// buildCertObject decodes fields and runs all single-certificate checks.
func buildCertObject(c *Cert, opts Options, at time.Time) {
	o := c.Obj
	extFields, x := parseExtensions(o, c.Exts, "cert")
	c.X = x
	if same, _ := sameName(c.Subject, c.Issuer); same {
		c.SelfIssued = true
		st, msg := verifySig(c.Pub, c.SigOuter, c.TBS, c.Signature, 0)
		c.SelfSigned = st
		if st == vBad && x.AKIKeyID != nil && x.SKI != nil && !bytes.Equal(x.AKIKeyID, x.SKI) {
			c.SelfSigned = "" // self-issued but signed by another key (e.g. key rollover)
		} else if st == vBad {
			_ = msg
		}
	}
	o.Role = certRole(c, opts.Profile)
	o.Label = c.Label()

	// ---------- fields ----------
	sha1sum := sha1.Sum(c.DER)
	sha256sum := sha256.Sum256(c.DER)
	o.Fields = []Field{
		{N: "Versi", V: fmt.Sprintf("v%d", c.Version)},
		{N: "Serial number", V: hexColon(c.SerialRaw) + "  (" + c.Serial.String() + ")"},
		{N: "Algoritma tanda tangan", V: sigName(c.SigOuter)},
		dnField("Issuer", c.Issuer),
		{N: "Masa berlaku", K: []Field{{N: "notBefore", V: fmtTime(c.NotBefore)}, {N: "notAfter", V: fmtTime(c.NotAfter)}, {N: "Durasi", V: humanDur(c.NotAfter.Sub(c.NotBefore))}}},
		dnField("Subject", c.Subject),
		keyFields(c.Pub),
		{N: "Ekstensi", V: fmt.Sprintf("%d", len(c.Exts)), K: extFields},
		{N: "Tanda tangan", V: hexShort(c.Signature, 600)},
		{N: "Fingerprint", K: []Field{{N: "SHA-256", V: hexColon(sha256sum[:])}, {N: "SHA-1", V: hexColon(sha1sum[:])}}},
	}
	o.sum("Subject", c.Subject.String())
	o.sum("Issuer", c.Issuer.String())
	o.sum("Peran", o.Role)
	o.sum("Serial", hexColon(c.SerialRaw))
	o.sum("Berlaku", fmtTime(c.NotBefore)+"  →  "+fmtTime(c.NotAfter))
	if x.PKUPPresent {
		s := "-"
		if x.PKUPBefore != nil {
			s = fmtTime(*x.PKUPBefore)
		}
		e := "-"
		if x.PKUPAfter != nil {
			e = fmtTime(*x.PKUPAfter)
		}
		o.sum("Masa pakai kunci", s+"  →  "+e)
	}
	o.sum("Kunci", c.Pub.Describe())
	o.sum("Tanda tangan", sigName(c.SigOuter))
	if x.KUPresent {
		o.sum("Key usage", kuString(x.KU))
	}
	if len(x.EKU) > 0 {
		var n []string
		for _, e := range x.EKU {
			n = append(n, oidShort(mustOID(e)))
		}
		o.sum("Extended key usage", strings.Join(n, ", "))
	}
	if len(x.SAN) > 0 {
		var n []string
		for _, g := range x.SAN {
			n = append(n, g.String())
		}
		o.sum("SAN", strings.Join(n, ", "))
	}
	o.sum("SHA-256", hexColon(sha256sum[:]))

	lintCert(c, opts, at)
}

func humanDur(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 0 {
		return "negatif!"
	}
	y := days / 365
	r := days % 365
	if y > 0 {
		return fmt.Sprintf("%d hari (± %d tahun %d bulan)", days, y, r/30)
	}
	return fmt.Sprintf("%d hari", days)
}

func lintCert(c *Cert, opts Options, at time.Time) {
	o := c.Obj
	x := c.X
	ref5280 := "RFC 5280"

	// ---- structure ----
	if c.Version < 1 || c.Version > 3 {
		o.add(SevError, "Struktur", fmt.Sprintf("Versi sertifikat tidak valid: %d", c.Version))
	}
	if len(c.Exts) > 0 && c.Version != 3 {
		o.add(SevError, "Struktur", "Sertifikat memiliki ekstensi tetapi bukan v3", "", ref5280+" §4.1.2.1")
	}
	if c.HasUID {
		o.add(SevWarn, "Struktur", "issuerUniqueID/subjectUniqueID dipakai (tidak boleh oleh CA yang patuh)", "", ref5280+" §4.1.2.8")
	}
	if c.Version == 1 && !c.SelfIssued {
		o.add(SevWarn, "Struktur", "Sertifikat v1 (tanpa ekstensi) yang bukan root — usang")
	}
	switch {
	case len(c.SerialRaw) == 0:
		o.add(SevError, "Struktur", "Serial number kosong")
	case c.Serial.Sign() < 0:
		o.add(SevError, "Struktur", "Serial number negatif", "", ref5280+" §4.1.2.2")
	case c.Serial.Sign() == 0:
		o.add(SevWarn, "Struktur", "Serial number bernilai 0", "", ref5280+" §4.1.2.2")
	}
	if len(c.SerialRaw) > 20 {
		o.add(SevError, "Struktur", fmt.Sprintf("Serial number %d oktet (maksimum 20)", len(c.SerialRaw)), "", ref5280+" §4.1.2.2")
	}
	if len(c.SerialRaw) > 1 && ((c.SerialRaw[0] == 0 && c.SerialRaw[1]&0x80 == 0) || (c.SerialRaw[0] == 0xff && c.SerialRaw[1]&0x80 != 0)) {
		o.add(SevWarn, "Struktur", "Serial number tidak ter-encode minimal (bukan DER)")
	}
	if c.Serial.Sign() > 0 && c.Serial.BitLen() < 64 && !c.SelfIssued {
		o.add(SevInfo, "Struktur", fmt.Sprintf("Serial number hanya %d bit entropi maksimum (CA/B Forum mensyaratkan ≥64 bit acak untuk TLS publik)", c.Serial.BitLen()))
	}
	if !bytes.Equal(c.SigInnerRaw, c.SigOuterRaw) {
		if c.SigInner.Algorithm.Equal(c.SigOuter.Algorithm) {
			o.add(SevWarn, "Tanda tangan", "AlgorithmIdentifier di TBS dan luar sertifikat berbeda encoding parameternya", "", ref5280+" §4.1.1.2")
		} else {
			o.add(SevError, "Tanda tangan", "Algoritma tanda tangan di TBS ("+sigName(c.SigInner)+") ≠ di luar ("+sigName(c.SigOuter)+")", "", ref5280+" §4.1.1.2")
		}
	}
	if isBER(c.DER) {
		o.add(SevWarn, "Format", "Sertifikat memakai encoding BER, bukan DER", "Tanda tangan dihitung atas DER; sebagian validator menolak BER.")
	}

	// ---- names ----
	dnFindings(o, c.Issuer, "Issuer")
	dnFindings(o, c.Subject, "Subject")
	if c.Issuer.Empty() {
		o.add(SevError, "Nama", "Issuer DN kosong", "", ref5280+" §4.1.2.4")
	}
	if c.Subject.Empty() {
		if !x.SANPresent {
			o.add(SevError, "Nama", "Subject kosong dan tidak ada SubjectAltName", "", ref5280+" §4.1.2.6")
		} else if !x.SANCritical {
			o.add(SevError, "Nama", "Subject kosong, maka SubjectAltName wajib critical", "", ref5280+" §4.2.1.6")
		}
	}

	// ---- validity ----
	exp := opts.ExpiryWarnDays
	if exp <= 0 {
		exp = 30
	}
	switch {
	case c.NotBefore.IsZero() || c.NotAfter.IsZero():
		o.add(SevError, "Waktu", "Masa berlaku tidak bisa dibaca")
	case !c.NotAfter.After(c.NotBefore):
		o.add(SevError, "Waktu", "notAfter tidak lebih besar dari notBefore")
	case at.Before(c.NotBefore):
		o.add(SevError, "Waktu", "Sertifikat BELUM berlaku", fmt.Sprintf("Mulai berlaku %s (%s lagi). Pastikan jam perangkat verifikasi benar.", fmtTime(c.NotBefore), roughDur(c.NotBefore.Sub(at))))
	case at.After(c.NotAfter):
		o.add(SevError, "Waktu", "Sertifikat sudah KEDALUWARSA", fmt.Sprintf("Berakhir %s (%s yang lalu).", fmtTime(c.NotAfter), roughDur(at.Sub(c.NotAfter))))
	case c.NotAfter.Sub(at) < time.Duration(exp)*24*time.Hour:
		o.add(SevWarn, "Waktu", fmt.Sprintf("Sertifikat akan kedaluwarsa dalam %s", roughDur(c.NotAfter.Sub(at))))
	default:
		o.add(SevOK, "Waktu", "Sertifikat sedang dalam masa berlaku", fmt.Sprintf("Sisa %s.", roughDur(c.NotAfter.Sub(at))))
	}
	if !c.NotBefore.IsZero() && at.Sub(c.NotBefore) >= 0 && at.Sub(c.NotBefore) < 24*time.Hour {
		o.add(SevInfo, "Waktu", "Sertifikat baru mulai berlaku kurang dari 24 jam lalu", "Perangkat dengan jam tertinggal / zona waktu salah akan melaporkan 'not yet valid'.")
	}
	if x.PKUPPresent {
		if x.PKUPBefore != nil && x.PKUPAfter != nil && !x.PKUPAfter.After(*x.PKUPBefore) {
			o.add(SevError, "Waktu", "privateKeyUsagePeriod: notAfter ≤ notBefore")
		}
		if x.PKUPBefore != nil && x.PKUPBefore.Before(c.NotBefore) {
			o.add(SevWarn, "Waktu", "Masa pakai kunci dimulai sebelum masa berlaku sertifikat")
		}
		if x.PKUPAfter != nil && x.PKUPAfter.After(c.NotAfter) {
			o.add(SevError, "Waktu", "Masa pakai kunci melewati masa berlaku sertifikat")
		}
		if x.PKUPAfter != nil && at.After(*x.PKUPAfter) {
			o.add(SevInfo, "Waktu", "Masa pakai kunci privat sudah berakhir", "Kunci tidak boleh lagi dipakai menandatangani; tanda tangan lama tetap bisa diverifikasi.")
		} else if x.PKUPBefore != nil && at.Before(*x.PKUPBefore) {
			o.add(SevWarn, "Waktu", "Masa pakai kunci privat belum dimulai")
		} else if x.PKUPAfter != nil {
			o.add(SevOK, "Waktu", "Dalam masa pakai kunci privat", fmt.Sprintf("Sisa %s untuk menandatangani.", roughDur(x.PKUPAfter.Sub(at))))
		}
		if x.PKUPBefore != nil && !x.PKUPBefore.Equal(c.NotBefore) {
			o.add(SevInfo, "Waktu", "Awal masa pakai kunci berbeda dari notBefore sertifikat")
		}
	}

	// ---- key + signature algorithm ----
	keyFindings(o, c.Pub, "Kunci")
	sigAlgFindings(o, c.SigOuter, c.Pub, c.SelfIssued)
	if c.SelfIssued {
		switch c.SelfSigned {
		case vOK:
			o.add(SevOK, "Tanda tangan", "Tanda tangan self-signed valid")
		case vBad:
			o.add(SevError, "Tanda tangan", "Sertifikat self-issued tetapi tanda tangannya TIDAK cocok dengan kuncinya sendiri", "Bisa berarti rusak/dimodifikasi, atau ditandatangani kunci lain dengan nama sama (key rollover).")
		case vUnsupported:
			o.add(SevInfo, "Tanda tangan", "Tanda tangan self-signed tidak bisa diverifikasi (algoritma tidak didukung)")
		}
	}

	// ---- extensions ----
	if c.Version == 3 {
		lintExtCombos(c)
	}

	// ---- hostname ----
	if h := strings.TrimSpace(opts.Hostname); h != "" && !x.IsCA {
		checkHostname(c, h)
	}

	// ---- compatibility with strict stdlib parser ----
	c.Std, c.StdErr = x509.ParseCertificate(c.DER)
	if c.StdErr != nil {
		o.add(SevWarn, "Kompatibilitas", "Parser X.509 ketat (Go crypto/x509) menolak sertifikat ini", c.StdErr.Error()+". Aplikasi yang memakai parser ketat bisa gagal memuatnya; inspector ini tetap memeriksa dengan parser toleran.")
	}

	if c.ICAO {
		lintICAO(c, at)
	}
	if c.TLSServer {
		lintTLS(c)
	}
}

func lintExtCombos(c *Cert) {
	o, x := c.Obj, c.X
	ref := "RFC 5280"
	if x.KUPresent && !x.KUCritical {
		o.add(SevWarn, "Ekstensi", "keyUsage sebaiknya critical", "", ref+" §4.2.1.3")
	}
	if x.IsCA {
		if !x.BCCritical {
			o.add(SevError, "Ekstensi", "basicConstraints pada CA harus critical", "", ref+" §4.2.1.9")
		}
		if x.KUPresent && x.KU&kuKeyCertSign == 0 {
			o.add(SevError, "Ekstensi", "CA (basicConstraints CA=true) tanpa keyUsage keyCertSign", "", ref+" §4.2.1.3")
		}
		if !x.KUPresent {
			o.add(SevWarn, "Ekstensi", "Sertifikat CA tanpa keyUsage", "", ref+" §4.2.1.3")
		}
		if x.SKI == nil {
			o.add(SevError, "Ekstensi", "Sertifikat CA wajib memiliki subjectKeyIdentifier", "", ref+" §4.2.1.2")
		}
	} else {
		if x.KU&kuKeyCertSign != 0 {
			o.add(SevError, "Ekstensi", "keyUsage keyCertSign tanpa basicConstraints CA=true", "", ref+" §4.2.1.3")
		}
		if x.PathLen >= 0 {
			o.add(SevError, "Ekstensi", "pathLenConstraint diisi padahal CA=false", "", ref+" §4.2.1.9")
		}
		if x.SKI == nil {
			o.add(SevInfo, "Ekstensi", "Tidak ada subjectKeyIdentifier (disarankan untuk sertifikat end-entity)", "", ref+" §4.2.1.2")
		}
	}
	if x.PathLen >= 0 && x.KUPresent && x.KU&kuKeyCertSign == 0 {
		o.add(SevError, "Ekstensi", "pathLenConstraint hanya bermakna jika keyCertSign diset")
	}
	if !x.AKIPresent && !(c.SelfIssued && c.SelfSigned == vOK) {
		o.add(SevError, "Ekstensi", "authorityKeyIdentifier wajib ada (kecuali root self-signed)", "", ref+" §4.2.1.1")
	}
	if c.SelfIssued && x.AKIKeyID != nil && x.SKI != nil && !bytes.Equal(x.AKIKeyID, x.SKI) && c.SelfSigned == vOK {
		o.add(SevWarn, "Ekstensi", "Root self-signed: AKI ≠ SKI")
	}
	if x.KU&(1<<7) != 0 || x.KU&(1<<8) != 0 {
		if x.KU&kuKeyAgreement == 0 {
			o.add(SevError, "Ekstensi", "encipherOnly/decipherOnly tanpa keyAgreement", "", ref+" §4.2.1.3")
		}
	}
	if c.Pub != nil && (c.Pub.Algo == "EC" || c.Pub.Algo == "Ed25519") && x.KU&kuKeyEncipherment != 0 {
		o.add(SevWarn, "Ekstensi", "keyEncipherment tidak berlaku untuk kunci "+c.Pub.Algo, "", "RFC 5480 §3")
	}
	for _, e := range x.EKU {
		if e == ekuAny && x.EKUCritical {
			o.add(SevWarn, "Ekstensi", "anyExtendedKeyUsage tidak boleh di extKeyUsage yang critical", "", ref+" §4.2.1.12")
		}
	}
	if x.Poison {
		o.add(SevWarn, "Ekstensi", "Ini precertificate Certificate Transparency (bukan sertifikat final)")
	}
	if !c.SelfIssued && !x.CRLDPPresent && len(x.OCSP) == 0 {
		o.add(SevInfo, "Revokasi", "Tidak ada CRL Distribution Point maupun OCSP — status revokasi tidak bisa dicek otomatis")
	}
}

func checkHostname(c *Cert, host string) {
	o, x := c.Obj, c.X
	var names []string
	hasDNSorIP := false
	for _, g := range x.SAN {
		if g.Type == "dns" || g.Type == "ip" {
			hasDNSorIP = true
			names = append(names, g.Value)
			if g.Type == "dns" && matchHostname(g.Value, host) {
				o.add(SevOK, "Hostname", "Hostname \""+host+"\" cocok dengan SAN "+g.Value)
				return
			}
			if g.Type == "ip" && g.Value == host {
				o.add(SevOK, "Hostname", "Alamat IP \""+host+"\" cocok dengan SAN")
				return
			}
		}
	}
	cn := c.Subject.Get("CN")
	if !hasDNSorIP && cn != "" && matchHostname(cn, host) {
		o.add(SevWarn, "Hostname", "Hostname hanya cocok dengan CN (tanpa SAN) — browser modern menolak ini")
		return
	}
	o.add(SevError, "Hostname", "Hostname \""+host+"\" TIDAK cocok", "Nama yang tersedia: "+strings.Join(append(names, "CN="+cn), ", "))
}

func lintTLS(c *Cert) {
	o, x := c.Obj, c.X
	if !hasDNS(x.SAN) {
		ipOK := false
		for _, g := range x.SAN {
			if g.Type == "ip" {
				ipOK = true
			}
		}
		if !ipOK {
			o.add(SevError, "TLS", "Sertifikat server TLS tanpa SAN dNSName/IP", "Browser modern mengabaikan CN.", "CA/B BR §7.1.2.7.12")
		}
	}
	days := c.NotAfter.Sub(c.NotBefore).Hours() / 24
	if days > 398 {
		o.add(SevInfo, "TLS", fmt.Sprintf("Masa berlaku %.0f hari melebihi 398 hari (batas untuk TLS yang dipercaya publik)", days), "", "CA/B BR §6.3.2")
	}
	if x.KUPresent && x.KU&(kuDigitalSignature|kuKeyEncipherment|kuKeyAgreement) == 0 {
		o.add(SevError, "TLS", "keyUsage tidak mengizinkan handshake TLS (perlu digitalSignature)")
	}
	for _, g := range x.SAN {
		if g.Type == "dns" && strings.Count(g.Value, "*") > 0 && !strings.HasPrefix(g.Value, "*.") {
			o.add(SevWarn, "TLS", "Wildcard tidak berada di label paling kiri: "+g.Value)
		}
	}
}

func roughDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d menit", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f jam", d.Hours())
	case d < 120*24*time.Hour:
		return fmt.Sprintf("%d hari", int(d.Hours()/24))
	default:
		return fmt.Sprintf("%d hari (± %.1f tahun)", int(d.Hours()/24), d.Hours()/24/365)
	}
}
