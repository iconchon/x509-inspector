package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func (a *analyzer) load(in Input) {
	sum := sha256.Sum256(in.Data)
	fe := &FileEntry{ID: in.ID, Name: in.Name, Path: in.Path, Origin: in.Origin, Size: len(in.Data), SHA256: hex.EncodeToString(sum[:])}
	a.rep.Files = append(a.rep.Files, fe)
	defer func() {
		if r := recover(); r != nil {
			fe.add(SevError, "Internal", fmt.Sprintf("Terjadi kesalahan internal saat membaca file: %v", r))
		}
	}()
	data := in.Data
	if len(bytes.TrimSpace(data)) == 0 {
		fe.Format = "kosong"
		fe.add(SevError, "Format", "File kosong")
		return
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		fe.add(SevInfo, "Format", "File diawali UTF-8 BOM")
		data = data[3:]
	}
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		a.loadPEM(fe, in, data)
		return
	}
	if hx := bytes.TrimSpace(data); looksHex(hx) {
		if der, err := hex.DecodeString(stripSpace(strings.ReplaceAll(string(hx), ":", ""))); err == nil && len(der) > 8 && (der[0] == 0x30 || der[0] == 0x77) {
			fe.Format = "Hex"
			fe.add(SevInfo, "Format", "Isi berupa teks hex; didekode otomatis")
			a.loadDERStream(fe, in, der, "")
			return
		}
	}
	if txt := bytes.TrimSpace(data); looksBase64(txt) {
		if der, err := base64.StdEncoding.DecodeString(stripSpace(string(txt))); err == nil && len(der) > 8 {
			fe.Format = "Base64 (tanpa header PEM)"
			fe.add(SevInfo, "Format", "Isi berupa Base64 tanpa header -----BEGIN-----; didekode otomatis")
			a.loadDERStream(fe, in, der, "")
			return
		}
	}
	fe.Format = "DER (biner)"
	a.loadDERStream(fe, in, data, "")
}

func (a *analyzer) loadPEM(fe *FileEntry, in Input, data []byte) {
	fe.Format = "PEM"
	begins := bytes.Count(data, []byte("-----BEGIN "))
	rest := data
	n := 0
	for {
		idx := bytes.Index(rest, []byte("-----BEGIN "))
		if idx < 0 {
			break
		}
		if idx > 0 && n == 0 && len(bytes.TrimSpace(rest[:idx])) > 0 {
			fe.add(SevInfo, "Format", "Ada teks di luar blok PEM (diabaikan)")
		}
		blk, r2 := pem.Decode(rest[idx:])
		if blk == nil {
			// find this header line to report which block is bad, then skip past it
			line := rest[idx:]
			if e := bytes.IndexByte(line, '\n'); e > 0 {
				line = line[:e]
			}
			fe.add(SevError, "Format", "Blok PEM rusak: "+strings.TrimSpace(string(line)), "Base64 tidak valid, header/footer tidak cocok, atau footer -----END----- hilang.")
			rest = rest[idx+11:]
			continue
		}
		n++
		where := fmt.Sprintf("PEM #%d (%s)", n, blk.Type)
		if blk.Headers["Proc-Type"] != "" && strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
			k := &PrivKey{Format: "PEM terenkripsi (legacy " + blk.Headers["DEK-Info"] + ")", Encrypted: true}
			k.Obj = &Object{Kind: "private-key"}
			a.keys = append(a.keys, k)
			a.addObj(fe, k.Obj, where)
		} else {
			a.handleDER(fe, in, blk.Bytes, blk.Type, where)
		}
		rest = r2
	}
	if n == 0 {
		fe.add(SevError, "Format", "Tidak ada blok PEM yang bisa dibaca")
	} else if n < begins {
		fe.add(SevWarn, "Format", fmt.Sprintf("%d dari %d blok PEM bisa dibaca", n, begins))
	}
}

func (a *analyzer) loadDERStream(fe *FileEntry, in Input, der []byte, hint string) {
	off := 0
	n := 0
	for len(der) > 0 {
		// tolerate trailing zero padding / whitespace
		if len(bytes.Trim(der, "\x00\r\n\t ")) == 0 {
			fe.add(SevInfo, "Format", fmt.Sprintf("%d byte padding di akhir file", len(der)))
			return
		}
		t, rest, err := readTLV(der)
		if err != nil {
			if n == 0 {
				fe.add(SevError, "Format", "Bukan PEM/DER yang valid: "+err.Error(), "Awal file: "+hexShort(der, 24))
				o := &Object{Kind: "unknown", Label: "Data tidak dikenali", der: der}
				o.add(SevError, "Format", "Data tidak bisa di-decode sebagai ASN.1")
				a.addObj(fe, o, "seluruh file")
			} else {
				fe.add(SevWarn, "Format", fmt.Sprintf("Data sisa yang tidak bisa dibaca di offset %d (%d byte)", off, len(der)))
			}
			return
		}
		n++
		where := "DER"
		if n > 1 || len(rest) > 0 {
			where = fmt.Sprintf("DER #%d @%d", n, off)
		}
		if t.Indefinite && !(t.Class == clsUniversal && t.Tag == 16 && a.looksPKCS12(t.Full)) {
			fe.add(SevInfo, "Format", "Memakai encoding BER (panjang indefinite)")
		}
		a.handleDER(fe, in, t.Full, hint, where)
		off += len(t.Full)
		der = rest
	}
}

func (a *analyzer) looksPKCS12(der []byte) bool {
	t, _, err := readTLV(der)
	if err != nil {
		return false
	}
	k, _ := children(t.Content)
	return len(k) >= 2 && k[0].is(clsUniversal, 2) && len(k[0].Content) == 1 && k[0].Content[0] == 3 && k[1].is(clsUniversal, 16)
}

func (a *analyzer) handleDER(fe *FileEntry, in Input, der []byte, hint, where string) {
	defer func() {
		if r := recover(); r != nil {
			o := &Object{Kind: "unknown", Label: "Gagal diproses", der: der}
			o.add(SevError, "Internal", fmt.Sprintf("Kesalahan internal: %v", r))
			a.addObj(fe, o, where)
		}
	}()
	var errs []string
	try := func(kind string, f func() error) bool {
		if err := f(); err != nil {
			errs = append(errs, kind+": "+err.Error())
			return false
		}
		return true
	}
	certF := func() error {
		d := der
		if hint == "TRUSTED CERTIFICATE" {
			if t, _, err := readTLV(d); err == nil {
				d = t.Full
			}
		}
		c, err := parseCert(d)
		if err != nil {
			if !bytes.Equal(d, der) {
				return err
			}
			if nd, e2 := toDER(der); e2 == nil && !bytes.Equal(nd, der) {
				if c2, e3 := parseCert(nd); e3 == nil {
					c2.DER = der
					c2.Obj.der = der
					c2.Obj.add(SevWarn, "Format", "Sertifikat ter-encode BER; dibaca setelah dinormalisasi ke DER")
					c = c2
					err = nil
				}
			}
			if err != nil {
				return err
			}
		}
		a.certs = append(a.certs, c)
		a.addObj(fe, c.Obj, where)
		return nil
	}
	crlF := func() error {
		r, err := parseCRL(der)
		if err != nil {
			return err
		}
		a.crls = append(a.crls, r)
		a.addObj(fe, r.Obj, where)
		return nil
	}
	csrF := func() error {
		r, err := parseCSR(der)
		if err != nil {
			return err
		}
		a.csrs = append(a.csrs, r)
		a.addObj(fe, r.Obj, where)
		return nil
	}
	cmsF := func() error {
		d := der
		m, err := parseCMS(d)
		if err != nil {
			if nd, e2 := toDER(der); e2 == nil {
				m, err = parseCMS(nd)
			}
			if err != nil {
				return err
			}
		}
		m.Obj = &Object{Kind: "cms", der: der, pemTyp: "PKCS7"}
		a.cmss = append(a.cmss, m)
		a.addObj(fe, m.Obj, where)
		for i, cd := range m.CertDER {
			a.handleDER(fe, in, cd, "CERTIFICATE", fmt.Sprintf("%s → sertifikat #%d", where, i+1))
		}
		for i, cd := range m.MLCerts {
			a.handleDER(fe, in, cd, "CERTIFICATE", fmt.Sprintf("%s → Master List CSCA #%d", where, i+1))
		}
		for i, cd := range m.CRLDER {
			a.handleDER(fe, in, cd, "X509 CRL", fmt.Sprintf("%s → CRL #%d", where, i+1))
		}
		return nil
	}
	keyF := func() error {
		k, err := parsePrivKey(der, hint)
		if err != nil {
			return err
		}
		k.Obj = &Object{Kind: "private-key"}
		a.keys = append(a.keys, k)
		a.addObj(fe, k.Obj, where)
		return nil
	}
	pubF := func() error {
		pk := parseSPKI(der)
		if pk.AlgOID == "" {
			if hint == "RSA PUBLIC KEY" {
				var k pkcs1Pub
				if _, err := asn1.Unmarshal(der, &k); err == nil {
					pk = &PubKey{Algo: "RSA", AlgOID: "1.2.840.113549.1.1.1", RSAN: k.N, RSAE: k.E, Bits: k.N.BitLen(), Raw: der}
				}
			}
			if pk.AlgOID == "" {
				return errors.New(pk.Err)
			}
		}
		o := &Object{Kind: "public-key", der: der, pemTyp: "PUBLIC KEY", Label: "Kunci publik " + pk.Describe()}
		o.sum("Kunci", pk.Describe())
		o.Fields = []Field{keyFields(pk)}
		keyFindings(o, pk, "Kunci")
		a.pubs = append(a.pubs, pubEntry{o, pk})
		a.addObj(fe, o, where)
		return nil
	}
	p12F := func() error { return a.loadPKCS12(fe, in, der, where) }

	switch hint {
	case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
		if try("sertifikat", certF) {
			return
		}
	case "X509 CRL":
		if try("CRL", crlF) {
			return
		}
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		if try("CSR", csrF) {
			return
		}
	case "PKCS7", "CMS":
		if try("CMS", cmsF) {
			return
		}
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY":
		if try("kunci privat", keyF) {
			return
		}
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		if try("kunci publik", pubF) {
			return
		}
	case "EC PARAMETERS", "DH PARAMETERS":
		o := &Object{Kind: "params", Label: hint, der: der}
		o.add(SevInfo, "Format", "Blok "+hint+" (parameter saja, bukan kunci)")
		a.addObj(fe, o, where)
		return
	case "":
	default:
		fe.add(SevInfo, "Format", "Tipe blok PEM tidak dikenal: "+hint+" — mencoba deteksi otomatis")
	}

	// sniffing
	if len(der) > 0 && der[0] == 0x77 && try("SOD", cmsF) {
		return
	}
	t, _, _ := readTLV(der)
	k, _ := children(t.Content)
	if len(k) > 0 && k[0].is(clsUniversal, 6) && try("CMS", cmsF) {
		return
	}
	if a.looksPKCS12(der) {
		if try("PKCS#12", p12F) {
			return
		}
	}
	for _, f := range []struct {
		n string
		f func() error
	}{{"sertifikat", certF}, {"CRL", crlF}, {"CSR", csrF}, {"kunci publik", pubF}, {"kunci privat", keyF}} {
		if try(f.n, f.f) {
			if hint != "" {
				fe.add(SevWarn, "Format", fmt.Sprintf("%s: label PEM \"%s\" tidak sesuai isi (terdeteksi sebagai %s)", where, hint, f.n))
			}
			return
		}
	}
	o := &Object{Kind: "unknown", Label: "Objek ASN.1 tidak dikenali", der: der}
	o.add(SevError, "Format", "Struktur tidak dikenali sebagai sertifikat/CRL/CSR/kunci/CMS", strings.Join(errs, "\n"))
	o.Fields = []Field{{N: "Ukuran", V: fmt.Sprintf("%d byte", len(der))}}
	a.addObj(fe, o, where)
}

func (a *analyzer) loadPKCS12(fe *FileEntry, in Input, der []byte, where string) error {
	fe.Format = "PKCS#12"
	pws := []string{in.Password}
	if in.Password != "" {
		pws = append(pws, "")
	}
	var lastErr error
	for _, pw := range pws {
		key, cert, cas, err := pkcs12.DecodeChain(der, pw)
		if err == nil {
			o := &Object{Kind: "pkcs12", Label: "Kontainer PKCS#12", der: der}
			o.sum("Isi", fmt.Sprintf("1 kunci privat, %d sertifikat", 1+len(cas)))
			if pw == "" {
				o.add(SevWarn, "Keamanan", "PKCS#12 bisa dibuka TANPA password")
			} else {
				o.add(SevOK, "PKCS#12", "Password benar, kontainer berhasil dibuka")
			}
			a.addObj(fe, o, where)
			k := &PrivKey{Format: "PKCS#12", Pub: pubFromStd(key)}
			k.Obj = &Object{Kind: "private-key"}
			a.keys = append(a.keys, k)
			a.addObj(fe, k.Obj, where+" → kunci privat")
			a.handleDER(fe, in, cert.Raw, "CERTIFICATE", where+" → sertifikat utama")
			for i, c := range cas {
				a.handleDER(fe, in, c.Raw, "CERTIFICATE", fmt.Sprintf("%s → sertifikat CA #%d", where, i+1))
			}
			return nil
		}
		if certs, err2 := pkcs12.DecodeTrustStore(der, pw); err2 == nil {
			o := &Object{Kind: "pkcs12", Label: "Kontainer PKCS#12 (trust store)", der: der}
			a.addObj(fe, o, where)
			for i, c := range certs {
				a.handleDER(fe, in, c.Raw, "CERTIFICATE", fmt.Sprintf("%s → sertifikat #%d", where, i+1))
			}
			return nil
		}
		lastErr = err
	}
	if errors.Is(lastErr, pkcs12.ErrIncorrectPassword) {
		fe.NeedsPassword = true
		o := &Object{Kind: "pkcs12", Label: "Kontainer PKCS#12 (terkunci)", der: der}
		if in.Password == "" {
			o.add(SevInfo, "PKCS#12", "Masukkan password untuk membuka kontainer PKCS#12")
		} else {
			o.add(SevWarn, "PKCS#12", "Password PKCS#12 salah")
		}
		a.addObj(fe, o, where)
		return nil
	}
	o := &Object{Kind: "pkcs12", Label: "Kontainer PKCS#12", der: der}
	o.add(SevError, "PKCS#12", "PKCS#12 tidak bisa dibuka", fmt.Sprint(lastErr))
	a.addObj(fe, o, where)
	return nil
}

func looksBase64(b []byte) bool {
	if len(b) < 40 {
		return false
	}
	for _, c := range b {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
			return false
		}
	}
	return true
}

func looksHex(b []byte) bool {
	if len(b) < 40 {
		return false
	}
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == ' ' || c == '\r' || c == '\n' || c == '\t') {
			return false
		}
	}
	return true
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
}
