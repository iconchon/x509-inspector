package engine

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// ATV is one attribute of a distinguished name.
type ATV struct {
	OID     string
	Name    string
	Value   string
	Tag     int
	Problem string
}

// DN is a parsed distinguished name that keeps raw bytes for exact matching.
type DN struct {
	Raw  []byte
	RDNs [][]ATV
	Err  string
}

func parseDN(raw []byte) *DN {
	dn := &DN{Raw: raw}
	t, _, err := readTLV(raw)
	if err != nil || !t.is(clsUniversal, 16) {
		dn.Err = "Name bukan SEQUENCE yang valid"
		return dn
	}
	sets, err := children(t.Content)
	if err != nil {
		dn.Err = err.Error()
	}
	for _, s := range sets {
		if !s.is(clsUniversal, 17) {
			dn.Err = "RDN bukan SET"
			continue
		}
		seqs, _ := children(s.Content)
		var rdn []ATV
		for _, q := range seqs {
			kids, err := children(q.Content)
			if err != nil || len(kids) != 2 || !kids[0].is(clsUniversal, 6) {
				dn.Err = "AttributeTypeAndValue rusak"
				continue
			}
			oid, _ := oidString(kids[0].Content)
			a := ATV{OID: oid, Name: oidName(oid), Tag: kids[1].Tag}
			if a.Name == "" {
				a.Name = oid
			}
			a.Value, a.Problem = decodeString(kids[1].Tag, kids[1].Content)
			rdn = append(rdn, a)
		}
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn
}

func (d *DN) String() string {
	if d == nil {
		return ""
	}
	var parts []string
	for _, rdn := range d.RDNs {
		var ps []string
		for _, a := range rdn {
			ps = append(ps, a.Name+"="+a.Value)
		}
		parts = append(parts, strings.Join(ps, "+"))
	}
	return strings.Join(parts, ", ")
}

func (d *DN) Get(name string) string {
	if d == nil {
		return ""
	}
	for _, rdn := range d.RDNs {
		for _, a := range rdn {
			if a.Name == name {
				return a.Value
			}
		}
	}
	return ""
}

func (d *DN) Empty() bool { return d == nil || len(d.RDNs) == 0 }

func (d *DN) Short() string {
	if cn := d.Get("CN"); cn != "" {
		return cn
	}
	if ou := d.Get("OU"); ou != "" {
		return ou
	}
	if o := d.Get("O"); o != "" {
		return o
	}
	s := d.String()
	if s == "" {
		return "(nama kosong)"
	}
	return s
}

func (d *DN) canon() string {
	var parts []string
	for _, rdn := range d.RDNs {
		var ps []string
		for _, a := range rdn {
			v := strings.Join(strings.Fields(strings.ToLower(a.Value)), " ")
			ps = append(ps, a.OID+"="+v)
		}
		parts = append(parts, strings.Join(ps, "+"))
	}
	return strings.Join(parts, ",")
}

// sameName: byte-exact or RFC 5280 §7.1-ish caseless match.
func sameName(a, b *DN) (bool, bool) {
	if a == nil || b == nil {
		return false, false
	}
	if bytes.Equal(a.Raw, b.Raw) {
		return true, true
	}
	return a.canon() == b.canon() && len(a.RDNs) > 0, false
}

func dnField(label string, d *DN) Field {
	f := Field{N: label, V: d.String()}
	for _, rdn := range d.RDNs {
		for _, a := range rdn {
			f.K = append(f.K, Field{N: a.Name, V: a.Value + "  [" + tagNames[a.Tag] + "]"})
		}
	}
	return f
}

// dnFindings validates attribute encodings.
func dnFindings(o *Object, d *DN, label string) {
	if d.Err != "" {
		o.add(SevError, "Nama", label+": "+d.Err)
	}
	seen := map[string]int{}
	for _, rdn := range d.RDNs {
		if len(rdn) > 1 {
			o.add(SevInfo, "Nama", label+" berisi RDN multi-nilai (+)", "Didukung standar, tetapi sering menimbulkan masalah interoperabilitas.")
		}
		for _, a := range rdn {
			seen[a.Name]++
			if a.Problem != "" {
				o.add(SevWarn, "Nama", fmt.Sprintf("%s %s: %s", label, a.Name, a.Problem))
			}
			if strings.TrimSpace(a.Value) == "" {
				o.add(SevWarn, "Nama", fmt.Sprintf("%s: atribut %s kosong", label, a.Name))
			} else if a.Value != strings.TrimSpace(a.Value) {
				o.add(SevInfo, "Nama", fmt.Sprintf("%s: atribut %s diawali/diakhiri spasi", label, a.Name))
			}
			switch a.OID {
			case "2.5.4.6":
				if a.Tag != 19 {
					o.add(SevWarn, "Nama", label+": countryName harus PrintableString", "", "RFC 5280 App. A")
				}
				if len(a.Value) != 2 || strings.ToUpper(a.Value) != a.Value {
					o.add(SevWarn, "Nama", label+": countryName harus kode ISO 3166 2 huruf kapital (sekarang \""+a.Value+"\")")
				}
			case "1.2.840.113549.1.9.1":
				if a.Tag != 22 {
					o.add(SevWarn, "Nama", label+": emailAddress harus IA5String")
				}
				o.add(SevInfo, "Nama", label+" memakai emailAddress di DN (usang; sebaiknya di SubjectAltName)")
			case "0.9.2342.19200300.100.1.25":
				if a.Tag != 22 {
					o.add(SevWarn, "Nama", label+": domainComponent harus IA5String")
				}
			}
			if a.Tag == 20 || a.Tag == 28 {
				o.add(SevInfo, "Nama", fmt.Sprintf("%s %s memakai %s (usang)", label, a.Name, tagNames[a.Tag]))
			}
			if ub := upperBound(a.OID); ub > 0 && len([]rune(a.Value)) > ub {
				o.add(SevWarn, "Nama", fmt.Sprintf("%s %s melebihi batas panjang %d karakter", label, a.Name, ub), "", "RFC 5280 App. A")
			}
		}
	}
	for _, n := range []string{"C", "CN", "serialNumber"} {
		if seen[n] > 1 {
			o.add(SevInfo, "Nama", fmt.Sprintf("%s memiliki lebih dari satu atribut %s", label, n))
		}
	}
}

func upperBound(oid string) int {
	switch oid {
	case "2.5.4.3", "2.5.4.10", "2.5.4.11":
		return 64
	case "2.5.4.7", "2.5.4.8":
		return 128
	case "2.5.4.5":
		return 64
	case "1.2.840.113549.1.9.1":
		return 255
	}
	return 0
}

// ---------------- GeneralNames ----------------

type GenName struct {
	Type  string // email, dns, uri, ip, dirName, otherName, rid, x400, edi
	Value string
	Bad   string
}

func parseGeneralNames(content []byte) ([]GenName, error) {
	kids, err := children(content)
	var out []GenName
	for _, k := range kids {
		out = append(out, parseGeneralName(k))
	}
	return out, err
}

func parseGeneralName(k tlv) GenName {
	if k.Class != clsContext {
		return GenName{Type: "?", Value: hexShort(k.Full, 32), Bad: "bukan GeneralName"}
	}
	switch k.Tag {
	case 0:
		kids, _ := children(k.Content)
		g := GenName{Type: "otherName"}
		if len(kids) >= 1 && kids[0].is(clsUniversal, 6) {
			oid, _ := oidString(kids[0].Content)
			g.Value = oidLabelS(oid)
			if oid == "1.3.6.1.4.1.311.20.2.3" {
				g.Value = "UPN"
			}
			if len(kids) >= 2 {
				inner, _ := children(kids[1].Content)
				if len(inner) == 1 && isStringTag(inner[0].Tag) {
					s, _ := decodeString(inner[0].Tag, inner[0].Content)
					g.Value += ": " + s
				}
			}
		}
		return g
	case 1, 2, 6:
		typ := map[int]string{1: "email", 2: "dns", 6: "uri"}[k.Tag]
		g := GenName{Type: typ, Value: string(k.Content)}
		for _, c := range k.Content {
			if c > 0x7e || c < 0x20 {
				g.Bad = "karakter non-IA5"
			}
		}
		if g.Value == "" {
			g.Bad = "nilai kosong"
		}
		return g
	case 4:
		inner, _, err := readTLV(k.Content)
		if err != nil {
			return GenName{Type: "dirName", Bad: "Name rusak"}
		}
		return GenName{Type: "dirName", Value: parseDN(inner.Full).String()}
	case 7:
		g := GenName{Type: "ip"}
		switch len(k.Content) {
		case 4, 16:
			g.Value = net.IP(k.Content).String()
		case 8, 32:
			n := len(k.Content) / 2
			ipn := net.IPNet{IP: k.Content[:n], Mask: k.Content[n:]}
			g.Value = ipn.String()
		default:
			g.Value = hexShort(k.Content, 32)
			g.Bad = "panjang alamat IP tidak valid"
		}
		return g
	case 8:
		oid, _ := oidString(k.Content)
		return GenName{Type: "rid", Value: oid}
	case 3:
		return GenName{Type: "x400", Value: hexShort(k.Content, 32)}
	case 5:
		return GenName{Type: "edi", Value: hexShort(k.Content, 32)}
	}
	return GenName{Type: fmt.Sprintf("[%d]", k.Tag), Value: hexShort(k.Content, 32), Bad: "tag GeneralName tidak dikenal"}
}

var genLabel = map[string]string{"email": "Email", "dns": "DNS", "uri": "URI", "ip": "IP", "dirName": "DirName", "otherName": "OtherName", "rid": "RID"}

func (g GenName) String() string {
	l := genLabel[g.Type]
	if l == "" {
		l = g.Type
	}
	return l + ":" + g.Value
}

func genNamesField(label string, gs []GenName) Field {
	f := Field{N: label}
	var vs []string
	for _, g := range gs {
		vs = append(vs, g.String())
		f.K = append(f.K, Field{N: genLabel[g.Type], V: g.Value})
	}
	f.V = strings.Join(vs, ", ")
	return f
}

// ---------------- hostname matching ----------------

func matchHostname(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) {
			label := strings.TrimSuffix(host, suffix)
			return label != "" && !strings.Contains(label, ".")
		}
	}
	return false
}

var _ = asn1.TagOID
