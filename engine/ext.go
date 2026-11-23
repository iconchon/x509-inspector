package engine

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// ExtInfo holds the semantically relevant parts of the extensions.
type ExtInfo struct {
	KUPresent, KUCritical bool
	KU                    int // bit i set == KeyUsage bit i
	EKUPresent            bool
	EKUCritical           bool
	EKU                   []string
	BCPresent, BCCritical bool
	IsCA                  bool
	PathLen               int // -1 = none
	SKI, AKIKeyID         []byte
	AKIPresent            bool
	AKIHasIssuerSerial    bool
	SANPresent            bool
	SANCritical           bool
	SAN                   []GenName
	IANPresent            bool
	IAN                   []GenName
	CRLDP                 []string
	CRLDPPresent          bool
	OCSP, CAIssuers       []string
	PKUPPresent           bool
	PKUPBefore, PKUPAfter *time.Time
	DocTypePresent        bool
	DocTypes              []string
	Policies              []string
	NCPresent             bool
	OCSPNoCheck           bool
	MustStaple            bool
	Poison                bool
	SCT                   bool
}

var kuNames = []string{"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
	"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}

const (
	kuDigitalSignature = 1 << 0
	kuNonRepudiation   = 1 << 1
	kuKeyEncipherment  = 1 << 2
	kuKeyAgreement     = 1 << 4
	kuKeyCertSign      = 1 << 5
	kuCRLSign          = 1 << 6
)

func kuString(ku int) string {
	var s []string
	for i, n := range kuNames {
		if ku&(1<<i) != 0 {
			s = append(s, n)
		}
	}
	if len(s) == 0 {
		return "(kosong)"
	}
	return strings.Join(s, ", ")
}

func parseTimeAny(t tlv) (time.Time, string) {
	s := string(t.Content)
	var layouts []string
	note := ""
	switch t.Tag {
	case 23:
		layouts = []string{"060102150405Z0700", "0601021504Z0700"}
		if len(s) != 13 || !strings.HasSuffix(s, "Z") {
			note = "UTCTime tidak dalam format DER (YYMMDDHHMMSSZ)"
		}
	case 24:
		layouts = []string{"20060102150405Z0700", "20060102150405.999999999Z0700", "200601021504Z0700"}
		if !strings.HasSuffix(s, "Z") || strings.Contains(s, ".") || len(s) != 15 {
			note = "GeneralizedTime tidak dalam format DER (YYYYMMDDHHMMSSZ)"
		}
	default:
		return time.Time{}, "bukan UTCTime/GeneralizedTime"
	}
	for _, l := range layouts {
		if tm, err := time.Parse(l, s); err == nil {
			if t.Tag == 23 && tm.Year() >= 2050 {
				tm = tm.AddDate(-100, 0, 0)
			}
			return tm.UTC(), note
		}
	}
	return time.Time{}, "waktu tidak bisa dibaca: " + s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	wib := t.In(time.FixedZone("WIB", 7*3600))
	return t.UTC().Format("2006-01-02 15:04:05") + " UTC (" + wib.Format("15:04") + " WIB)"
}

// parseExtensions decodes all extensions into display fields + ExtInfo, adding findings.
func parseExtensions(o *Object, exts []pkix.Extension, ctx string) ([]Field, *ExtInfo) {
	x := &ExtInfo{PathLen: -1}
	var fields []Field
	seen := map[string]bool{}
	for _, e := range exts {
		id := e.Id.String()
		name := oidName(id)
		if name == "" {
			name = id
		}
		f := Field{N: name}
		if e.Critical {
			f.N += " [critical]"
		}
		if seen[id] {
			o.add(SevError, "Ekstensi", "Ekstensi duplikat: "+name, "", "RFC 5280 §4.2")
		}
		seen[id] = true
		if !knownExt[id] {
			if e.Critical {
				o.add(SevError, "Ekstensi", "Ekstensi critical tidak dikenal: "+name, "Validator yang patuh RFC 5280 wajib menolak sertifikat dengan ekstensi critical yang tidak dipahaminya.", "RFC 5280 §4.2")
			} else {
				o.add(SevInfo, "Ekstensi", "Ekstensi tidak dikenal (non-critical): "+name)
			}
			f.V = hexShort(e.Value, 48)
			fields = append(fields, f)
			continue
		}
		bad := func(msg string) {
			o.add(SevError, "Ekstensi", name+": "+msg)
			f.V = "RUSAK — " + msg
		}
		v := e.Value
		switch id {
		case oidKU:
			x.KUPresent, x.KUCritical = true, e.Critical
			var bs asn1.BitString
			if rest, err := asn1.Unmarshal(v, &bs); err != nil || len(rest) > 0 {
				bad("BIT STRING keyUsage rusak")
				break
			}
			for i := 0; i < bs.BitLength && i < 9; i++ {
				if bs.At(i) == 1 {
					x.KU |= 1 << i
				}
			}
			f.V = kuString(x.KU)
			if x.KU == 0 {
				o.add(SevError, "Ekstensi", "keyUsage ada tetapi tidak ada bit yang diset", "", "RFC 5280 §4.2.1.3")
			}
		case oidEKU:
			x.EKUPresent, x.EKUCritical = true, e.Critical
			var ids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(v, &ids); err != nil {
				bad("daftar OID rusak")
				break
			}
			var names []string
			for _, i := range ids {
				x.EKU = append(x.EKU, i.String())
				names = append(names, oidShort(i))
				f.K = append(f.K, Field{N: oidShort(i), V: i.String()})
			}
			f.V = strings.Join(names, ", ")
			if len(ids) == 0 {
				o.add(SevError, "Ekstensi", "extKeyUsage kosong")
			}
		case oidBC:
			x.BCPresent, x.BCCritical = true, e.Critical
			var bc struct {
				CA      bool `asn1:"optional"`
				PathLen int  `asn1:"optional,default:-1"`
			}
			if _, err := asn1.Unmarshal(v, &bc); err != nil {
				bad("struktur rusak")
				break
			}
			x.IsCA, x.PathLen = bc.CA, bc.PathLen
			f.V = fmt.Sprintf("CA=%v", bc.CA)
			if bc.PathLen >= 0 {
				f.V += fmt.Sprintf(", pathLen=%d", bc.PathLen)
			}
		case oidSKI:
			if e.Critical {
				o.add(SevError, "Ekstensi", "subjectKeyIdentifier tidak boleh critical", "", "RFC 5280 §4.2.1.2")
			}
			var ski []byte
			if _, err := asn1.Unmarshal(v, &ski); err != nil {
				bad("OCTET STRING rusak")
				break
			}
			x.SKI = ski
			f.V = hexColon(ski)
			if len(ski) == 0 {
				o.add(SevError, "Ekstensi", "subjectKeyIdentifier kosong")
			}
		case oidAKI:
			x.AKIPresent = true
			if e.Critical {
				o.add(SevError, "Ekstensi", "authorityKeyIdentifier tidak boleh critical", "", "RFC 5280 §4.2.1.1")
			}
			t, _, err := readTLV(v)
			if err != nil {
				bad("struktur rusak")
				break
			}
			kids, _ := children(t.Content)
			for _, k := range kids {
				switch {
				case k.is(clsContext, 0):
					x.AKIKeyID = k.Content
					f.K = append(f.K, Field{N: "keyIdentifier", V: hexColon(k.Content)})
				case k.is(clsContext, 1):
					x.AKIHasIssuerSerial = true
					gs, _ := parseGeneralNames(k.Content)
					f.K = append(f.K, genNamesField("authorityCertIssuer", gs))
				case k.is(clsContext, 2):
					f.K = append(f.K, Field{N: "authorityCertSerialNumber", V: hexColon(k.Content)})
				}
			}
			f.V = hexColon(x.AKIKeyID)
			if x.AKIKeyID == nil {
				f.V = "(tanpa keyIdentifier)"
				o.add(SevWarn, "Ekstensi", "authorityKeyIdentifier tidak memuat keyIdentifier", "", "RFC 5280 §4.2.1.1")
			}
		case oidSAN, oidIAN:
			t, _, err := readTLV(v)
			if err != nil || !t.is(clsUniversal, 16) {
				bad("GeneralNames rusak")
				break
			}
			gs, err := parseGeneralNames(t.Content)
			if err != nil {
				bad("GeneralNames rusak")
			}
			for _, g := range gs {
				if g.Bad != "" {
					o.add(SevWarn, "Ekstensi", fmt.Sprintf("%s entri %s: %s", name, g.String(), g.Bad))
				}
			}
			if len(gs) == 0 {
				o.add(SevError, "Ekstensi", name+" kosong", "", "RFC 5280 §4.2.1.6")
			}
			if id == oidSAN {
				x.SANPresent, x.SANCritical, x.SAN = true, e.Critical, gs
			} else {
				x.IANPresent, x.IAN = true, gs
			}
			ff := genNamesField(f.N, gs)
			f = ff
		case oidCRLDP, oidFreshest:
			if id == oidCRLDP {
				x.CRLDPPresent = true
			}
			t, _, err := readTLV(v)
			if err != nil {
				bad("struktur rusak")
				break
			}
			dps, _ := children(t.Content)
			var all []string
			for i, dp := range dps {
				df := Field{N: fmt.Sprintf("DistributionPoint #%d", i+1)}
				kids, _ := children(dp.Content)
				for _, k := range kids {
					switch {
					case k.is(clsContext, 0):
						inner, _, err := readTLV(k.Content)
						if err == nil && inner.is(clsContext, 0) {
							gs, _ := parseGeneralNames(inner.Content)
							for _, g := range gs {
								df.K = append(df.K, Field{N: genLabel[g.Type], V: g.Value})
								all = append(all, g.String())
								if g.Type == "uri" && id == oidCRLDP {
									x.CRLDP = append(x.CRLDP, g.Value)
								}
							}
						} else {
							df.K = append(df.K, Field{N: "nameRelativeToCRLIssuer"})
						}
					case k.is(clsContext, 1):
						df.K = append(df.K, Field{N: "reasons", V: hexShort(k.Content, 8)})
					case k.is(clsContext, 2):
						gs, _ := parseGeneralNames(k.Content)
						df.K = append(df.K, genNamesField("cRLIssuer", gs))
					}
				}
				f.K = append(f.K, df)
			}
			f.V = strings.Join(all, ", ")
		case oidAIA, oidSIA:
			t, _, err := readTLV(v)
			if err != nil {
				bad("struktur rusak")
				break
			}
			ads, _ := children(t.Content)
			var all []string
			for _, ad := range ads {
				kids, _ := children(ad.Content)
				if len(kids) != 2 {
					continue
				}
				m, _ := oidString(kids[0].Content)
				g := parseGeneralName(kids[1])
				mn := oidName(m)
				if mn == "" {
					mn = m
				}
				f.K = append(f.K, Field{N: mn, V: g.String()})
				all = append(all, mn+" - "+g.Value)
				if g.Type == "uri" {
					if m == "1.3.6.1.5.5.7.48.1" {
						x.OCSP = append(x.OCSP, g.Value)
					} else if m == "1.3.6.1.5.5.7.48.2" && id == oidAIA {
						x.CAIssuers = append(x.CAIssuers, g.Value)
					}
				}
			}
			f.V = strings.Join(all, ", ")
			if e.Critical {
				o.add(SevError, "Ekstensi", name+" tidak boleh critical", "", "RFC 5280 §4.2.2")
			}
		case oidPolicies:
			t, _, err := readTLV(v)
			if err != nil {
				bad("struktur rusak")
				break
			}
			pis, _ := children(t.Content)
			for _, pi := range pis {
				kids, _ := children(pi.Content)
				if len(kids) == 0 {
					continue
				}
				p, _ := oidString(kids[0].Content)
				x.Policies = append(x.Policies, p)
				pf := Field{N: oidLabelS(p)}
				if len(kids) > 1 {
					qs, _ := children(kids[1].Content)
					for _, q := range qs {
						qk, _ := children(q.Content)
						if len(qk) == 2 {
							qo, _ := oidString(qk[0].Content)
							val := ""
							if isStringTag(qk[1].Tag) {
								val, _ = decodeString(qk[1].Tag, qk[1].Content)
							} else {
								un, _ := children(qk[1].Content)
								for _, u := range un {
									if isStringTag(u.Tag) {
										s, _ := decodeString(u.Tag, u.Content)
										val += s
									}
								}
							}
							pf.K = append(pf.K, Field{N: oidLabelS(qo), V: val})
						}
					}
				}
				f.K = append(f.K, pf)
			}
			f.V = fmt.Sprintf("%d kebijakan", len(x.Policies))
		case oidPKUP:
			x.PKUPPresent = true
			t, _, err := readTLV(v)
			if err != nil {
				bad("struktur rusak")
				break
			}
			kids, _ := children(t.Content)
			for _, k := range kids {
				tm, note := parseTimeAny(tlv{Tag: 24, Content: k.Content})
				if note != "" && tm.IsZero() {
					bad(note)
					continue
				}
				tt := tm
				if k.is(clsContext, 0) {
					x.PKUPBefore = &tt
					f.K = append(f.K, Field{N: "notBefore", V: fmtTime(tm)})
				} else if k.is(clsContext, 1) {
					x.PKUPAfter = &tt
					f.K = append(f.K, Field{N: "notAfter", V: fmtTime(tm)})
				}
			}
			if e.Critical {
				o.add(SevWarn, "Ekstensi", "privateKeyUsagePeriod sebaiknya tidak critical")
			}
			if x.PKUPBefore == nil && x.PKUPAfter == nil {
				o.add(SevError, "Ekstensi", "privateKeyUsagePeriod kosong (minimal salah satu waktu harus ada)")
			}
		case oidDocType:
			x.DocTypePresent = true
			t, _, err := readTLV(v)
			if err != nil {
				bad("struktur rusak")
				break
			}
			kids, _ := children(t.Content)
			if len(kids) >= 2 && kids[0].is(clsUniversal, 2) {
				f.K = append(f.K, Field{N: "version", V: fmt.Sprint(int(new(asn1Int).set(kids[0].Content)))})
				items, _ := children(kids[1].Content)
				for _, it := range items {
					s, prob := decodeString(it.Tag, it.Content)
					x.DocTypes = append(x.DocTypes, s)
					if it.Tag != 19 {
						o.add(SevWarn, "ICAO", "documentTypeList: nilai harus PrintableString")
					}
					if prob != "" {
						o.add(SevWarn, "ICAO", "documentTypeList: "+prob)
					}
				}
				f.K = append(f.K, Field{N: "docTypes", V: strings.Join(x.DocTypes, ", ")})
				f.V = strings.Join(x.DocTypes, ", ")
			} else {
				bad("struktur DocumentTypeListSyntax tidak sesuai")
			}
			if len(x.DocTypes) == 0 {
				o.add(SevWarn, "ICAO", "documentTypeList tidak berisi jenis dokumen")
			}
		case oidNC:
			x.NCPresent = true
			f.V = "ada"
			if !e.Critical {
				o.add(SevWarn, "Ekstensi", "nameConstraints harus critical", "", "RFC 5280 §4.2.1.10")
			}
			t, _, err := readTLV(v)
			if err == nil {
				kids, _ := children(t.Content)
				for _, k := range kids {
					lbl := "permitted"
					if k.Tag == 1 {
						lbl = "excluded"
					}
					subs, _ := children(k.Content)
					for _, s := range subs {
						sk, _ := children(s.Content)
						if len(sk) > 0 {
							f.K = append(f.K, Field{N: lbl, V: parseGeneralName(sk[0]).String()})
						}
					}
				}
			}
		case oidOCSPNoChk:
			x.OCSPNoCheck = true
			f.V = "ya"
		case oidTLSFeat:
			x.MustStaple = true
			f.V = "status_request (OCSP must-staple)"
		case oidPoison:
			x.Poison = true
			f.V = "precertificate (CT poison)"
		case oidSCT:
			x.SCT = true
			f.V = "ada (Certificate Transparency)"
		default:
			f.V = hexShort(v, 48)
		}
		fields = append(fields, f)
	}
	return fields, x
}

// tiny helper for small INTEGER contents
type asn1Int int

func (a *asn1Int) set(b []byte) asn1Int {
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	*a = asn1Int(v)
	return *a
}
