package engine

import (
	"fmt"
	"strings"
	"time"
)

const refICAO = "ICAO Doc 9303-12"

// lintICAO applies the eMRTD PKI certificate profile (CSCA / DS / ML signer).
// Wording is deliberately cautious where requirements differ between editions.
func lintICAO(c *Cert, at time.Time) {
	o, x := c.Obj, c.X
	role := c.ICAORole
	ic := c.Issuer.Get("C")
	sc := c.Subject.Get("C")
	if ic == "" {
		o.add(SevError, "ICAO", "Issuer tidak memiliki countryName", "", refICAO)
	}
	if sc == "" {
		o.add(SevError, "ICAO", "Subject tidak memiliki countryName", "", refICAO)
	}
	if ic != "" && sc != "" && !strings.EqualFold(ic, sc) {
		o.add(SevError, "ICAO", fmt.Sprintf("countryName issuer (%s) ≠ subject (%s)", ic, sc), "Di PKI eMRTD, CSCA hanya menerbitkan sertifikat untuk negaranya sendiri.", refICAO)
	}
	if c.Version != 3 {
		o.add(SevError, "ICAO", "Sertifikat ICAO harus v3", "", refICAO)
	}

	switch role {
	case "CSCA", "CSCA-link":
		if !x.KUPresent || !x.KUCritical {
			o.add(SevWarn, "ICAO", "keyUsage CSCA harus ada dan critical", "", refICAO)
		} else if x.KU != kuKeyCertSign|kuCRLSign {
			o.add(SevWarn, "ICAO", "keyUsage CSCA seharusnya tepat keyCertSign + cRLSign (sekarang: "+kuString(x.KU)+")", "", refICAO)
		} else {
			o.add(SevOK, "ICAO", "keyUsage CSCA sesuai (keyCertSign, cRLSign)")
		}
		if x.PathLen != 0 {
			o.add(SevInfo, "ICAO", "basicConstraints CSCA biasanya pathLenConstraint=0", "", refICAO)
		}
		if role == "CSCA-link" && !x.AKIPresent {
			o.add(SevError, "ICAO", "Link certificate wajib memiliki authorityKeyIdentifier", "", refICAO)
		}
	case "DS":
		if !x.KUPresent || !x.KUCritical {
			o.add(SevError, "ICAO", "keyUsage Document Signer harus ada dan critical", "", refICAO)
		} else if x.KU != kuDigitalSignature {
			o.add(SevWarn, "ICAO", "keyUsage Document Signer seharusnya hanya digitalSignature (sekarang: "+kuString(x.KU)+")", "", refICAO)
		} else {
			o.add(SevOK, "ICAO", "keyUsage Document Signer sesuai (digitalSignature, critical)")
		}
		if x.BCPresent && x.IsCA {
			o.add(SevError, "ICAO", "Document Signer tidak boleh CA=true", "", refICAO)
		}
		if !x.DocTypePresent {
			o.add(SevWarn, "ICAO", "Ekstensi documentTypeList (2.23.136.1.1.6.2) tidak ada", "Diwajibkan untuk DS pada edisi 9303 terbaru; verifier yang ketat bisa menolak.", refICAO)
		} else {
			o.add(SevOK, "ICAO", "documentTypeList ada: "+strings.Join(x.DocTypes, ", "))
		}
		if !x.AKIPresent {
			o.add(SevError, "ICAO", "Document Signer wajib memiliki authorityKeyIdentifier", "", refICAO)
		}
		if !x.PKUPPresent {
			o.add(SevInfo, "ICAO", "Tidak ada privateKeyUsagePeriod", "Disarankan agar periode penandatanganan dokumen terlihat jelas.", refICAO)
		} else if x.PKUPBefore != nil && x.PKUPAfter != nil {
			sign := x.PKUPAfter.Sub(*x.PKUPBefore)
			tail := c.NotAfter.Sub(*x.PKUPAfter)
			o.add(SevInfo, "ICAO", fmt.Sprintf("Periode tanda tangan %s; sertifikat tetap berlaku %s setelahnya (untuk masa berlaku dokumen)", roughDur(sign), roughDur(tail)))
		}
	case "MLS", "DLS":
		if !x.KUPresent || x.KU&kuDigitalSignature == 0 {
			o.add(SevWarn, "ICAO", "Signer list harus memiliki keyUsage digitalSignature", "", refICAO)
		}
		if !x.EKUCritical {
			o.add(SevInfo, "ICAO", "extKeyUsage signer list biasanya critical", "", refICAO)
		}
	}

	if !x.CRLDPPresent {
		o.add(SevWarn, "ICAO", "cRLDistributionPoints tidak ada", "Profil 9303-12 mengharapkan titik distribusi CRL (umumnya juga ICAO PKD).", refICAO)
	} else {
		pkd := false
		for _, u := range x.CRLDP {
			if strings.Contains(strings.ToLower(u), "icao.int") {
				pkd = true
			}
		}
		if pkd {
			o.add(SevOK, "ICAO", "CRL Distribution Point mencakup ICAO PKD")
		}
	}
	if !x.IANPresent {
		o.add(SevWarn, "ICAO", "issuerAltName tidak ada", "", refICAO)
	}
	if !x.SANPresent && (role == "CSCA" || role == "CSCA-link" || role == "DS") {
		o.add(SevInfo, "ICAO", "subjectAltName tidak ada", "Beberapa edisi 9303-12 menandai SAN wajib untuk CSCA/DS; cek edisi yang dipakai negara penerbit.", refICAO)
	}
	if c.Pub != nil && c.Pub.EC != nil && !c.Pub.EC.Explicit {
		o.add(SevInfo, "ICAO", "Kunci ECDSA memakai named curve (bukan parameter eksplisit)", "Profil ICAO mengharapkan parameter domain eksplisit; sebagian inspection system lama mungkin bergantung padanya.", refICAO)
	}
	if len(c.SerialRaw) > 20 {
		o.add(SevError, "ICAO", "Serial number melebihi 20 oktet", "", refICAO)
	}
}
