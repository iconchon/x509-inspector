package engine

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

type pubEntry struct {
	o *Object
	k *PubKey
}

type analyzer struct {
	opts  Options
	at    time.Time
	rep   *Report
	certs []*Cert
	crls  []*CRL
	csrs  []*CSR
	keys  []*PrivKey
	cmss  []*CMS
	pubs  []pubEntry
	seq   int
	sigs  map[[2]*Cert][2]string
	fetch Fetcher
}

// Fetcher downloads a URL (injected so the app can cache and cancel).
type Fetcher func(url string) ([]byte, error)

func (a *analyzer) addObj(fe *FileEntry, o *Object, where string) {
	a.seq++
	o.ID = fmt.Sprintf("o%d", a.seq)
	o.FileID = fe.ID
	o.Where = where
	a.rep.Objects = append(a.rep.Objects, o)
	fe.Objects = append(fe.Objects, o.ID)
}

// ParseAt parses the user supplied validation time.
func ParseAt(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Now().UTC(), nil
	}
	for _, l := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Now().UTC(), fmt.Errorf("format waktu tidak dikenal: %q", s)
}

// Analyze runs the whole pipeline. It never fails; problems become findings.
func Analyze(inputs []Input, opts Options, fetch Fetcher) (rep *Report) {
	rep = &Report{Version: 1, Generated: time.Now().UTC().Format(time.RFC3339), Options: opts}
	at, err := ParseAt(opts.At)
	if err != nil {
		rep.Notes = append(rep.Notes, Finding{Sev: SevWarn, Cat: "Opsi", Msg: err.Error() + " — memakai waktu sekarang"})
	}
	rep.at = at
	rep.At = at.Format(time.RFC3339)
	if opts.Profile == "" {
		opts.Profile = "auto"
	}
	a := &analyzer{opts: opts, at: at, rep: rep, sigs: map[[2]*Cert][2]string{}, fetch: fetch}
	defer func() {
		if r := recover(); r != nil {
			rep.Notes = append(rep.Notes, Finding{Sev: SevError, Cat: "Internal", Msg: fmt.Sprintf("Kesalahan internal: %v", r), Detail: string(debug.Stack())})
		}
		a.finalize()
	}()

	for _, in := range inputs {
		a.load(in)
	}
	a.buildAll(0)

	if opts.Online && fetch != nil {
		a.onlinePrefetch()
	}

	a.step("rantai", a.chains)
	a.step("CRL", a.crlIssuers)
	a.step("revokasi", a.revocation)
	a.step("CMS", a.cmsVerify)
	a.step("kunci", a.keyMatch)
	a.step("duplikat", a.duplicates)
	if opts.Online && fetch != nil {
		a.step("OCSP", a.ocspAll)
	}
	if opts.SystemTrust {
		a.step("trust store", a.systemTrust)
	}
	if curveNotes != nil {
		rep.Notes = append(rep.Notes, Finding{Sev: SevInfo, Cat: "Internal", Msg: "Kurva dinonaktifkan karena gagal self-test: " + strings.Join(curveNotes, ", ")})
	}
	return rep
}

func (a *analyzer) step(name string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			a.rep.Notes = append(a.rep.Notes, Finding{Sev: SevError, Cat: "Internal", Msg: fmt.Sprintf("Langkah %s gagal: %v", name, r)})
		}
	}()
	f()
}

// buildAll decodes fields and runs per-object checks for objects not yet built.
func (a *analyzer) buildAll(_ int) {
	for _, c := range a.certs {
		if c.X == nil {
			a.safe(c.Obj, func() { buildCertObject(c, a.opts, a.at) })
		}
	}
	for _, r := range a.crls {
		if r.Obj.Label == "" {
			a.safe(r.Obj, func() { buildCRLObject(r, a.at) })
		}
	}
	for _, r := range a.csrs {
		if r.Obj.Label == "" {
			a.safe(r.Obj, func() { buildCSRObject(r, a.opts, a.at) })
		}
	}
	for _, k := range a.keys {
		if k.Obj.Label == "" {
			a.safe(k.Obj, func() { buildPrivKeyObject(k) })
		}
	}
	for _, m := range a.cmss {
		if m.Obj.Label == "" {
			a.safe(m.Obj, func() { buildCMSObject(m) })
		}
	}
}

func (a *analyzer) safe(o *Object, f func()) {
	defer func() {
		if r := recover(); r != nil {
			o.add(SevError, "Internal", fmt.Sprintf("Kesalahan internal saat memeriksa objek: %v", r))
			if o.Label == "" {
				o.Label = "Objek (gagal diproses)"
			}
		}
	}()
	f()
}

// ---------------- chain building ----------------

func (a *analyzer) verifyLink(child, parent *Cert) (string, string) {
	k := [2]*Cert{child, parent}
	if r, ok := a.sigs[k]; ok {
		return r[0], r[1]
	}
	st, msg := verifySig(parent.Pub, child.SigOuter, child.TBS, child.Signature, 0)
	a.sigs[k] = [2]string{st, msg}
	return st, msg
}

func (a *analyzer) issuerCandidates(c *Cert) (byName []*Cert, byKeyOnly []*Cert) {
	for _, p := range a.certs {
		if p == c || p.X == nil {
			continue
		}
		nameOK, _ := sameName(p.Subject, c.Issuer)
		keyOK := c.X.AKIKeyID == nil || p.X.SKI == nil || bytes.Equal(c.X.AKIKeyID, p.X.SKI)
		if nameOK && keyOK {
			byName = append(byName, p)
		} else if !nameOK && c.X.AKIKeyID != nil && p.X.SKI != nil && bytes.Equal(c.X.AKIKeyID, p.X.SKI) {
			byKeyOnly = append(byKeyOnly, p)
		}
	}
	return
}

// findIssuer returns the best issuer and the verification status.
func (a *analyzer) findIssuer(c *Cert) (*Cert, string, string, bool) {
	cands, keyOnly := a.issuerCandidates(c)
	var firstBad *Cert
	var badMsg string
	for _, p := range cands {
		st, msg := a.verifyLink(c, p)
		if st == vOK {
			return p, st, "", false
		}
		if firstBad == nil {
			firstBad, badMsg = p, msg
		}
	}
	for _, p := range cands {
		if st, msg := a.verifyLink(c, p); st == vUnsupported {
			return p, st, msg, false
		}
	}
	for _, p := range keyOnly {
		if st, _ := a.verifyLink(c, p); st == vOK {
			return p, st, "", true
		}
	}
	if firstBad != nil {
		return firstBad, vBad, badMsg, false
	}
	return nil, "", "", false
}

func (a *analyzer) chains() {
	for _, c := range a.certs {
		if c.X == nil {
			continue
		}
		a.safe(c.Obj, func() { a.chainFor(c) })
	}
}

func (a *analyzer) chainFor(c *Cert) {
	o := c.Obj
	path := []*Cert{c}
	links := []ChainLink{}
	cur := c
	complete := false
	for depth := 0; depth < 12; depth++ {
		if cur.SelfIssued && cur.SelfSigned == vOK {
			complete = true
			links = append(links, ChainLink{ID: cur.Obj.ID, Label: cur.Label(), Status: "ok", Note: cur.Obj.Role + " — trust anchor (self-signed)"})
			break
		}
		p, st, msg, nameMismatch := a.findIssuer(cur)
		if cur == c {
			c.IssuerCert, c.IssuerSig = p, st
		}
		if p == nil {
			links = append(links, ChainLink{ID: cur.Obj.ID, Label: cur.Label(), Status: "warn", Note: cur.Obj.Role})
			links = append(links, ChainLink{Label: cur.Issuer.Short(), Status: "info", Note: "issuer tidak ada di file yang dimuat"})
			break
		}
		lst := map[string]string{vOK: "ok", vBad: "error", vUnsupported: "info"}[st]
		note := cur.Obj.Role
		switch st {
		case vOK:
			note += " — tanda tangan valid"
		case vBad:
			note += " — tanda tangan TIDAK valid"
		default:
			note += " — tanda tangan tidak bisa diverifikasi"
		}
		links = append(links, ChainLink{ID: cur.Obj.ID, Label: cur.Label(), Status: lst, Note: note})
		if cur == c {
			switch st {
			case vOK:
				o.add(SevOK, "Rantai", "Tanda tangan diverifikasi dengan kunci issuer \""+p.Label()+"\"")
			case vBad:
				o.add(SevError, "Rantai", "Tanda tangan TIDAK valid terhadap issuer \""+p.Label()+"\"", msg+". Sertifikat mungkin rusak/dimodifikasi atau issuer yang dimuat bukan penerbit sebenarnya (key rollover).")
			default:
				o.add(SevInfo, "Rantai", "Tanda tangan terhadap issuer \""+p.Label()+"\" tidak bisa diverifikasi", msg)
			}
			if nameMismatch {
				o.add(SevWarn, "Rantai", "Issuer cocok berdasarkan AKI/SKI tetapi nama DN-nya berbeda")
			}
			if _, exact := sameName(p.Subject, c.Issuer); !exact && !nameMismatch {
				o.add(SevInfo, "Rantai", "Nama issuer cocok hanya secara case-insensitive / beda encoding string")
			}
			a.issuerConstraints(c, p)
		}
		if st == vBad {
			break
		}
		for _, q := range path {
			if q == p {
				links = append(links, ChainLink{Label: "loop", Status: "error", Note: "rantai berputar (loop)"})
				depth = 99
			}
		}
		path = append(path, p)
		cur = p
	}
	// pathLenConstraint over the full path
	for i := 1; i < len(path); i++ {
		ca := path[i]
		if ca.X.PathLen >= 0 {
			inter := 0
			for j := 1; j < i; j++ {
				if !path[j].SelfIssued {
					inter++
				}
			}
			if inter > ca.X.PathLen {
				o.add(SevError, "Rantai", fmt.Sprintf("pathLenConstraint=%d milik \"%s\" dilanggar (%d CA perantara)", ca.X.PathLen, ca.Label(), inter), "", "RFC 5280 §6.1.4")
			}
		}
		if a.at.After(ca.NotAfter) || a.at.Before(ca.NotBefore) {
			o.add(SevWarn, "Rantai", "CA di rantai di luar masa berlaku: \""+ca.Label()+"\"")
		}
	}
	c.Obj.Chain = links
	if !(c.SelfIssued && c.SelfSigned == vOK) {
		if complete {
			o.add(SevOK, "Rantai", fmt.Sprintf("Rantai lengkap sampai trust anchor (%d sertifikat)", len(path)), "Anchor berasal dari file yang Anda muat — kepercayaannya bergantung pada sumber file itu.")
		} else if c.IssuerCert == nil {
			o.add(SevInfo, "Rantai", "Sertifikat issuer tidak dimuat — tanda tangan belum diverifikasi", "Muat juga sertifikat CA/CSCA penerbit (issuer: "+c.Issuer.String()+") atau aktifkan mode online.")
		}
	}
}

func (a *analyzer) issuerConstraints(c, p *Cert) {
	o := c.Obj
	if p.Version < 3 {
		o.add(SevWarn, "Rantai", "Issuer adalah sertifikat v1 (tanpa basicConstraints)")
	} else if !p.X.IsCA {
		o.add(SevError, "Rantai", "Issuer \""+p.Label()+"\" bukan CA (basicConstraints CA=false/tidak ada)", "", "RFC 5280 §6.1.4")
	}
	if p.X.KUPresent && p.X.KU&kuKeyCertSign == 0 {
		o.add(SevError, "Rantai", "keyUsage issuer tidak mengizinkan keyCertSign", "", "RFC 5280 §6.1.4")
	}
	if c.NotBefore.Before(p.NotBefore) || c.NotAfter.After(p.NotAfter) {
		o.add(SevInfo, "Rantai", "Masa berlaku sertifikat melampaui masa berlaku issuer")
	}
	if p.X.PKUPAfter != nil && c.NotBefore.After(*p.X.PKUPAfter) {
		o.add(SevWarn, "Rantai", "Diterbitkan setelah masa pakai kunci issuer (privateKeyUsagePeriod) berakhir")
	}
	if c.ICAO && c.ICAORole == "DS" && p.ICAORole != "CSCA" && p.ICAORole != "CSCA-link" {
		o.add(SevWarn, "ICAO", "Penerbit Document Signer bukan CSCA")
	}
	if c.ICAO && !strings.EqualFold(c.Subject.Get("C"), p.Subject.Get("C")) {
		o.add(SevError, "ICAO", "countryName berbeda dengan CSCA penerbit")
	}
	if p.X.NCPresent {
		o.add(SevInfo, "Rantai", "Issuer memiliki nameConstraints (tidak dievaluasi otomatis)")
	}
}

// ---------------- CRL / revocation ----------------

func (a *analyzer) crlIssuers() {
	for _, r := range a.crls {
		var cand *Cert
		st, msg := "", ""
		for _, c := range a.certs {
			if c.X == nil {
				continue
			}
			if ok, _ := sameName(c.Subject, r.Issuer); !ok {
				continue
			}
			if r.AKIKeyID != nil && c.X.SKI != nil && !bytes.Equal(r.AKIKeyID, c.X.SKI) {
				continue
			}
			s, m := verifySig(c.Pub, r.SigOuter, r.TBS, r.Signature, 0)
			if cand == nil || s == vOK {
				cand, st, msg = c, s, m
			}
			if s == vOK {
				break
			}
		}
		r.IssuerCert, r.SigStatus = cand, st
		o := r.Obj
		switch {
		case cand == nil:
			o.add(SevInfo, "Tanda tangan", "Sertifikat penerbit CRL tidak dimuat — tanda tangan CRL belum diverifikasi")
		case st == vOK:
			o.add(SevOK, "Tanda tangan", "Tanda tangan CRL valid oleh \""+cand.Label()+"\"")
			if cand.X.KUPresent && cand.X.KU&kuCRLSign == 0 {
				o.add(SevError, "Tanda tangan", "Penerbit CRL tidak memiliki keyUsage cRLSign")
			}
		case st == vBad:
			o.add(SevError, "Tanda tangan", "Tanda tangan CRL TIDAK valid", msg)
		default:
			o.add(SevInfo, "Tanda tangan", "Tanda tangan CRL tidak bisa diverifikasi", msg)
		}
	}
}

func (a *analyzer) revocation() {
	for _, c := range a.certs {
		if c.X == nil || (c.SelfIssued && c.SelfSigned == vOK) {
			continue
		}
		applicable := 0
		var foreign []string
		for _, r := range a.crls {
			if ok, _ := sameName(r.Issuer, c.Issuer); !ok {
				if r.Online != "" {
					for _, u := range c.X.CRLDP {
						if u == r.Online {
							foreign = append(foreign, r.Issuer.Short()+" ("+u+")")
						}
					}
				}
				continue
			}
			applicable++
			if r.AKIKeyID != nil && c.X.AKIKeyID != nil && !bytes.Equal(r.AKIKeyID, c.X.AKIKeyID) {
				continue
			}
			src := "CRL"
			if r.Online != "" {
				src = "CRL online (" + r.Online + ")"
			}
			trusted := r.SigStatus == vOK
			var hit *revEntry
			for i := range r.Revoked {
				if bytes.Equal(bytes.TrimLeft(r.Revoked[i].SerialRaw, "\x00"), bytes.TrimLeft(c.SerialRaw, "\x00")) {
					hit = &r.Revoked[i]
					break
				}
			}
			stale := !r.NextUpdate.IsZero() && a.at.After(r.NextUpdate)
			if hit != nil {
				when := hit.Date.UTC().Format("2006-01-02 15:04 UTC")
				reason := hit.Reason
				if reason == "" {
					reason = "tanpa alasan"
				}
				d := "Menurut " + src + " (thisUpdate " + fmtTime(r.ThisUpdate) + ")."
				if !trusted {
					d += " PERHATIAN: tanda tangan CRL belum terverifikasi."
				}
				if hit.Date.After(a.at) {
					o := c.Obj
					o.add(SevWarn, "Revokasi", "Dicabut pada "+when+" ("+reason+"), setelah waktu validasi", d)
				} else {
					c.Revoked = reason
					c.Obj.add(SevError, "Revokasi", "Sertifikat DICABUT pada "+when+" ("+reason+")", d)
				}
				continue
			}
			sev := SevOK
			msg := "Tidak tercantum di " + src
			if !trusted {
				sev = SevInfo
				msg += " (tanda tangan CRL belum terverifikasi)"
			}
			if stale {
				sev = SevWarn
				msg += " — tetapi CRL sudah kedaluwarsa"
			}
			c.Obj.add(sev, "Revokasi", msg, "Penerbit CRL: "+r.Issuer.Short()+", nextUpdate "+fmtTime(r.NextUpdate))
		}
		if applicable == 0 && len(foreign) > 0 {
			c.Obj.add(SevWarn, "Revokasi", "CRL yang diunduh dari CRLDP sertifikat ini diterbitkan oleh CA lain — status revokasi tidak bisa ditentukan",
				"Issuer sertifikat: "+c.Issuer.Short()+". CRL yang didapat: "+strings.Join(foreign, "; ")+". Kemungkinan CRL untuk CSCA baru belum dipublikasikan di lokasi tersebut.")
		}
	}
}

func (a *analyzer) cmsVerify() {
	for _, m := range a.cmss {
		a.safe(m.Obj, func() { verifyCMS(m, a.certs, a.at) })
	}
}

func (a *analyzer) keyMatch() {
	for _, k := range a.keys {
		if k.Pub == nil || k.Encrypted {
			continue
		}
		matched := false
		for _, c := range a.certs {
			if c.Pub.Equal(k.Pub) {
				matched = true
				k.Obj.add(SevOK, "Kunci", "Cocok dengan sertifikat \""+c.Label()+"\"")
				c.Obj.add(SevOK, "Kunci", "Kunci privat yang cocok ikut dimuat ("+k.Obj.Where+")")
			}
		}
		for _, r := range a.csrs {
			if r.Pub.Equal(k.Pub) {
				matched = true
				k.Obj.add(SevOK, "Kunci", "Cocok dengan CSR \""+r.Subject.Short()+"\"")
			}
		}
		if !matched && (len(a.certs) > 0 || len(a.csrs) > 0) {
			k.Obj.add(SevWarn, "Kunci", "Tidak cocok dengan sertifikat/CSR mana pun yang dimuat")
		}
	}
	for _, p := range a.pubs {
		for _, c := range a.certs {
			if c.Pub.Equal(p.k) {
				p.o.add(SevOK, "Kunci", "Sama dengan kunci publik sertifikat \""+c.Label()+"\"")
			}
		}
	}
	for _, r := range a.csrs {
		for _, c := range a.certs {
			if c.Pub.Equal(r.Pub) {
				r.Obj.add(SevInfo, "Kunci", "Kunci CSR sama dengan sertifikat \""+c.Label()+"\"")
			}
		}
	}
}

func (a *analyzer) duplicates() {
	seen := map[[32]byte]*Cert{}
	for _, c := range a.certs {
		h := sha256.Sum256(c.DER)
		if p, ok := seen[h]; ok {
			c.Obj.add(SevInfo, "Struktur", "Duplikat dari sertifikat yang sama di "+p.Obj.Where)
			continue
		}
		seen[h] = c
	}
}

// systemTrust asks the OS trust store (bounded in time and count).
func (a *analyzer) systemTrust() {
	inter := x509.NewCertPool()
	for _, c := range a.certs {
		if c.Std != nil {
			inter.AddCert(c.Std)
		}
	}
	count := 0
	icaoNoted := false
	for _, c := range a.certs {
		if c.Std == nil || c.X == nil {
			continue
		}
		if c.ICAO {
			if !icaoNoted {
				a.rep.Notes = append(a.rep.Notes, Finding{Sev: SevInfo, Cat: "Trust store", Msg: "Sertifikat ICAO tidak dicek ke trust store OS (CSCA tidak pernah ada di trust store OS; gunakan Master List/CSCA)."})
				icaoNoted = true
			}
			continue
		}
		if count >= 15 {
			c.Obj.add(SevInfo, "Trust store", "Tidak dicek ke trust store OS (batas 15 sertifikat per analisis)")
			continue
		}
		count++
		type res struct {
			chains [][]*x509.Certificate
			err    error
		}
		ch := make(chan res, 1)
		std := c.Std
		go func() {
			defer func() { recover() }()
			cs, err := std.Verify(x509.VerifyOptions{Intermediates: inter, CurrentTime: a.at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			ch <- res{cs, err}
		}()
		select {
		case r := <-ch:
			if r.err == nil {
				var names []string
				if len(r.chains) > 0 {
					for _, x := range r.chains[0] {
						names = append(names, x.Subject.CommonName)
					}
				}
				c.Obj.add(SevOK, "Trust store", "Dipercaya oleh trust store sistem operasi", "Rantai: "+strings.Join(names, " → "))
			} else {
				c.Obj.add(SevInfo, "Trust store", "Tidak dipercaya oleh trust store sistem operasi", r.err.Error()+". Wajar untuk PKI privat/internal.")
			}
		case <-time.After(6 * time.Second):
			c.Obj.add(SevInfo, "Trust store", "Pemeriksaan trust store OS timeout (6 detik)")
		}
	}
}

func (a *analyzer) finalize() {
	total := map[string]int{SevError: 0, SevWarn: 0, SevInfo: 0, SevOK: 0}
	for _, o := range a.rep.Objects {
		o.Findings = sortFindings(o.Findings)
		o.Worst = worst(o.Findings)
		o.Counts = countSev(o.Findings)
		if o.Fields == nil {
			o.Fields = []Field{}
		}
		if o.Summary == nil {
			o.Summary = []KV{}
		}
		if o.der != nil && o.pemTyp != "" && o.Kind != "private-key" {
			o.PEM = pemEncode(o.pemTyp, o.der)
		}
		for k, v := range o.Counts {
			total[k] += v
		}
	}
	for _, f := range a.rep.Files {
		for _, fd := range f.Findings {
			total[fd.Sev]++
		}
		if f.Objects == nil {
			f.Objects = []string{}
		}
		if f.Findings == nil {
			f.Findings = []Finding{}
		}
	}
	if a.rep.Objects == nil {
		a.rep.Objects = []*Object{}
	}
	if a.rep.Files == nil {
		a.rep.Files = []*FileEntry{}
	}
	a.rep.Counts = total
}

func sortFindings(fs []Finding) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, s := range []string{SevError, SevWarn, SevInfo, SevOK} {
		for _, f := range fs {
			if f.Sev == s {
				out = append(out, f)
			}
		}
	}
	return out
}
