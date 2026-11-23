package engine

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

func pemEncode(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// HTTPFetcher is the default network fetcher with sane limits.
func HTTPFetcher() Fetcher {
	client := &http.Client{Timeout: 20 * time.Second}
	var mu sync.Mutex
	cache := map[string][]byte{}
	return func(url string) ([]byte, error) {
		mu.Lock()
		if b, ok := cache[url]; ok {
			mu.Unlock()
			return b, nil
		}
		mu.Unlock()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "x509-inspector/1.0")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, err
		}
		mu.Lock()
		cache[url] = b
		mu.Unlock()
		return b, nil
	}
}

func fetchable(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

func (a *analyzer) note(sev, msg string, detail ...string) {
	f := Finding{Sev: sev, Cat: "Online", Msg: msg}
	if len(detail) > 0 {
		f.Detail = detail[0]
	}
	a.rep.Notes = append(a.rep.Notes, f)
}

// fetchMany downloads URLs concurrently and returns results in order.
func (a *analyzer) fetchMany(urls []string) map[string][]byte {
	out := map[string][]byte{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			defer func() { recover() }()
			sem <- struct{}{}
			defer func() { <-sem }()
			b, err := a.fetch(u)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				a.note(SevWarn, "Gagal mengunduh "+u, err.Error())
				return
			}
			out[u] = b
		}(u)
	}
	wg.Wait()
	return out
}

func (a *analyzer) onlinePrefetch() {
	seen := map[string]bool{}
	// 1. missing issuers via AIA caIssuers (up to 3 rounds to climb the chain)
	for round := 0; round < 3; round++ {
		var urls []string
		for _, c := range a.certs {
			if c.X == nil || (c.SelfIssued && c.SelfSigned == vOK) {
				continue
			}
			if p, _, _, _ := a.findIssuer(c); p != nil {
				continue
			}
			for _, u := range c.X.CAIssuers {
				if fetchable(u) && !seen[u] && len(urls) < 10 {
					seen[u] = true
					urls = append(urls, u)
				}
			}
		}
		if len(urls) == 0 {
			break
		}
		got := a.fetchMany(urls)
		for _, u := range urls {
			if b, ok := got[u]; ok {
				a.load(Input{ID: fmt.Sprintf("net%d", len(a.rep.Files)), Name: u, Origin: "online", Data: b})
				a.note(SevInfo, "Sertifikat issuer diunduh dari AIA: "+u)
			}
		}
		a.buildAll(0)
	}
	// 2. CRLs from CRL distribution points
	var urls []string
	for _, c := range a.certs {
		if c.X == nil || (c.SelfIssued && c.SelfSigned == vOK) {
			continue
		}
		for _, u := range c.X.CRLDP {
			if fetchable(u) && !seen[u] && len(urls) < 15 {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}
	if len(urls) == 0 {
		return
	}
	got := a.fetchMany(urls)
	// prefer one CRL per issuer: load every successful download (identical CRLs are harmless)
	for _, u := range urls {
		b, ok := got[u]
		if !ok {
			continue
		}
		before := len(a.crls)
		a.load(Input{ID: fmt.Sprintf("net%d", len(a.rep.Files)), Name: u, Origin: "online", Data: b})
		for _, r := range a.crls[before:] {
			r.Online = u
		}
		if len(a.crls) > before {
			a.note(SevOK, "CRL diunduh: "+u)
		} else {
			a.note(SevWarn, "Isi dari "+u+" bukan CRL yang valid")
		}
	}
	a.buildAll(0)
}

// ---------------- OCSP ----------------

type certID struct {
	HashAlg        pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	Serial         *big.Int
}
type ocspReqEntry struct{ Cert certID }
type ocspTBS struct{ List []ocspReqEntry }
type ocspReq struct{ TBS ocspTBS }

func (a *analyzer) ocspAll() {
	n := 0
	for _, c := range a.certs {
		if c.X == nil || len(c.X.OCSP) == 0 || c.IssuerCert == nil || (c.SelfIssued && c.SelfSigned == vOK) {
			continue
		}
		if n >= 15 {
			break
		}
		n++
		a.ocspOne(c)
	}
}

func (a *analyzer) ocspOne(c *Cert) {
	o := c.Obj
	p := c.IssuerCert
	nh := sha1.Sum(p.Subject.Raw)
	kh := sha1.Sum(p.Pub.Raw)
	serial := new(big.Int).SetBytes(c.SerialRaw)
	req, err := asn1.Marshal(ocspReq{TBS: ocspTBS{List: []ocspReqEntry{{Cert: certID{
		HashAlg:        pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Parameters: asn1.NullRawValue},
		IssuerNameHash: nh[:], IssuerKeyHash: kh[:], Serial: serial,
	}}}}})
	if err != nil {
		return
	}
	for _, u := range c.X.OCSP {
		if !fetchable(u) {
			continue
		}
		body, err := postOCSP(u, req)
		if err != nil {
			o.add(SevInfo, "Revokasi", "OCSP "+u+" gagal dihubungi", err.Error())
			continue
		}
		resp, err := ocsp.ParseResponse(body, p.Std)
		if err != nil && resp == nil {
			o.add(SevWarn, "Revokasi", "Respons OCSP tidak valid dari "+u, err.Error())
			continue
		}
		if resp.SerialNumber != nil && resp.SerialNumber.Cmp(serial) != 0 {
			o.add(SevWarn, "Revokasi", "Respons OCSP untuk serial yang berbeda")
			continue
		}
		verified := err == nil && p.Std != nil
		suffix := ""
		if !verified {
			suffix = " (tanda tangan respons belum terverifikasi)"
		}
		switch resp.Status {
		case ocsp.Good:
			sev := SevOK
			if !verified {
				sev = SevInfo
			}
			o.add(sev, "Revokasi", "OCSP: status GOOD"+suffix, "Responder "+u+", thisUpdate "+fmtTime(resp.ThisUpdate))
		case ocsp.Revoked:
			o.add(SevError, "Revokasi", "OCSP: sertifikat DICABUT"+suffix, fmt.Sprintf("Waktu %s, alasan %s", fmtTime(resp.RevokedAt), reasonNames[resp.RevocationReason]))
		default:
			o.add(SevWarn, "Revokasi", "OCSP: status UNKNOWN"+suffix, "Responder tidak mengenali sertifikat ini.")
		}
		if !resp.NextUpdate.IsZero() && a.at.After(resp.NextUpdate) {
			o.add(SevWarn, "Revokasi", "Respons OCSP sudah kedaluwarsa (nextUpdate lewat)")
		}
		return
	}
}

func postOCSP(url string, req []byte) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	r, err := http.NewRequest("POST", url, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/ocsp-request")
	r.Header.Set("User-Agent", "x509-inspector/1.0")
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
