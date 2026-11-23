package engine

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// tlv is a minimal BER/DER element.
type tlv struct {
	Class       int
	Constructed bool
	Tag         int
	Content     []byte
	Full        []byte
	Indefinite  bool
	NonMinimal  bool // non-minimal length encoding (BER, not DER)
}

const (
	clsUniversal = 0
	clsApp       = 1
	clsContext   = 2
)

var errTrunc = errors.New("data terpotong / panjang ASN.1 melebihi data")

func readTLV(b []byte) (tlv, []byte, error) {
	return readTLVDepth(b, 0)
}

func readTLVDepth(b []byte, depth int) (tlv, []byte, error) {
	var t tlv
	if depth > 64 {
		return t, nil, errors.New("ASN.1 terlalu dalam")
	}
	if len(b) < 2 {
		return t, nil, errTrunc
	}
	i := 0
	b0 := b[i]
	i++
	t.Class = int(b0 >> 6)
	t.Constructed = b0&0x20 != 0
	t.Tag = int(b0 & 0x1f)
	if t.Tag == 0x1f {
		t.Tag = 0
		for n := 0; ; n++ {
			if i >= len(b) || n > 4 {
				return t, nil, errTrunc
			}
			c := b[i]
			i++
			t.Tag = t.Tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return t, nil, errTrunc
	}
	l := int(b[i])
	i++
	if l == 0x80 {
		if !t.Constructed {
			return t, nil, errors.New("panjang indefinite pada tipe primitif")
		}
		t.Indefinite = true
		start := i
		rest := b[i:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				t.Content = b[start : len(b)-len(rest)]
				end := len(b) - len(rest) + 2
				t.Full = b[:end]
				return t, b[end:], nil
			}
			_, r2, err := readTLVDepth(rest, depth+1)
			if err != nil {
				return t, nil, err
			}
			rest = r2
		}
	}
	length := l
	if l > 0x80 {
		n := l & 0x7f
		if n > 4 || i+n > len(b) {
			return t, nil, errTrunc
		}
		length = 0
		for k := 0; k < n; k++ {
			length = length<<8 | int(b[i+k])
		}
		if length < 0x80 || (n > 1 && b[i] == 0) {
			t.NonMinimal = true
		}
		i += n
	}
	if length < 0 || i+length > len(b) {
		return t, nil, errTrunc
	}
	t.Content = b[i : i+length]
	t.Full = b[:i+length]
	return t, b[i+length:], nil
}

// children parses all elements inside a constructed value.
func children(content []byte) ([]tlv, error) {
	var out []tlv
	for len(content) > 0 {
		t, rest, err := readTLV(content)
		if err != nil {
			return out, err
		}
		out = append(out, t)
		content = rest
	}
	return out, nil
}

func (t tlv) is(class, tag int) bool { return t.Class == class && t.Tag == tag }

func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

func encodeTLV(firstByte byte, content []byte) []byte {
	out := []byte{firstByte}
	out = append(out, encodeLen(len(content))...)
	return append(out, content...)
}

// toDER converts BER (indefinite lengths, constructed strings) into DER-ish
// encoding so encoding/asn1 can read it. SET ordering is left untouched.
func toDER(b []byte) ([]byte, error) {
	t, rest, err := readTLV(b)
	if err != nil {
		return nil, err
	}
	out, err := normTLV(t, 0)
	if err != nil {
		return nil, err
	}
	return append(out, rest...), nil
}

func normTLV(t tlv, depth int) ([]byte, error) {
	if depth > 64 {
		return nil, errors.New("terlalu dalam")
	}
	hdrEnd := len(t.Full) - len(t.Content)
	if t.Indefinite {
		hdrEnd = len(t.Full) - len(t.Content) - 2
	}
	id := t.Full[:1]
	// keep multi-byte tag identifiers intact
	tagBytes := t.Full[:1]
	if t.Tag >= 0x1f {
		j := 1
		for j < hdrEnd && t.Full[j]&0x80 != 0 {
			j++
		}
		tagBytes = t.Full[:j+1]
	}
	_ = id
	if !t.Constructed {
		out := append([]byte{}, tagBytes...)
		out = append(out, encodeLen(len(t.Content))...)
		return append(out, t.Content...), nil
	}
	kids, err := children(t.Content)
	if err != nil {
		return nil, err
	}
	var body []byte
	if t.Class == clsUniversal && isStringTag(t.Tag) {
		for _, k := range kids {
			if k.Constructed {
				nb, err := normTLV(k, depth+1)
				if err != nil {
					return nil, err
				}
				kk, _, _ := readTLV(nb)
				body = append(body, kk.Content...)
			} else {
				body = append(body, k.Content...)
			}
		}
		out := []byte{tagBytes[0] &^ 0x20}
		out = append(out, encodeLen(len(body))...)
		return append(out, body...), nil
	}
	for _, k := range kids {
		nb, err := normTLV(k, depth+1)
		if err != nil {
			return nil, err
		}
		body = append(body, nb...)
	}
	out := append([]byte{}, tagBytes...)
	out = append(out, encodeLen(len(body))...)
	return append(out, body...), nil
}

func isStringTag(tag int) bool {
	switch tag {
	case 4, 12, 18, 19, 20, 21, 22, 25, 26, 27, 28, 30:
		return true
	}
	return false
}

// isBER reports whether the encoding uses BER-only features.
func isBER(b []byte) bool {
	t, _, err := readTLV(b)
	if err != nil {
		return false
	}
	return berWalk(t, 0)
}

func berWalk(t tlv, d int) bool {
	if t.Indefinite || t.NonMinimal {
		return true
	}
	if !t.Constructed || d > 40 {
		return false
	}
	if t.Class == clsUniversal && isStringTag(t.Tag) {
		return true
	}
	kids, _ := children(t.Content)
	for _, k := range kids {
		if berWalk(k, d+1) {
			return true
		}
	}
	return false
}

// ---------- primitive decoders ----------

func oidString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errors.New("OID kosong")
	}
	var parts []string
	val := new(big.Int)
	first := true
	for i := 0; i < len(b); i++ {
		val.Lsh(val, 7)
		val.Or(val, big.NewInt(int64(b[i]&0x7f)))
		if b[i]&0x80 == 0 {
			if first {
				first = false
				if val.Cmp(big.NewInt(80)) < 0 {
					v := val.Int64()
					parts = append(parts, fmt.Sprint(v/40), fmt.Sprint(v%40))
				} else {
					parts = append(parts, "2", new(big.Int).Sub(val, big.NewInt(80)).String())
				}
			} else {
				parts = append(parts, val.String())
			}
			val = new(big.Int)
		} else if i == len(b)-1 {
			return "", errors.New("OID terpotong")
		}
	}
	return strings.Join(parts, "."), nil
}

func decodeString(tag int, b []byte) (string, string) {
	switch tag {
	case 12: // UTF8String
		if !utf8.Valid(b) {
			return string(b), "UTF8String berisi byte UTF-8 tidak valid"
		}
		return string(b), ""
	case 19: // PrintableString
		for _, c := range b {
			if !isPrintableChar(c) {
				return string(b), fmt.Sprintf("PrintableString berisi karakter tidak sah %q", c)
			}
		}
		return string(b), ""
	case 22, 26: // IA5 / Visible
		for _, c := range b {
			if c > 0x7f {
				return string(b), "IA5/VisibleString berisi karakter non-ASCII"
			}
		}
		return string(b), ""
	case 18: // Numeric
		return string(b), ""
	case 20, 21, 25, 27: // Teletex, Videotex, Graphic, General
		return latin1(b), ""
	case 30: // BMPString
		if len(b)%2 != 0 {
			return hex.EncodeToString(b), "BMPString panjang ganjil"
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		return string(utf16.Decode(u)), ""
	case 28: // UniversalString
		if len(b)%4 != 0 {
			return hex.EncodeToString(b), "UniversalString panjang tidak kelipatan 4"
		}
		var rs []rune
		for i := 0; i < len(b); i += 4 {
			rs = append(rs, rune(uint32(b[i])<<24|uint32(b[i+1])<<16|uint32(b[i+2])<<8|uint32(b[i+3])))
		}
		return string(rs), ""
	}
	return hex.EncodeToString(b), ""
}

func latin1(b []byte) string {
	rs := make([]rune, len(b))
	for i, c := range b {
		rs[i] = rune(c)
	}
	return string(rs)
}

func isPrintableChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		strings.IndexByte(" '()+,-./:=?", c) >= 0
}

var tagNames = map[int]string{
	1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL", 6: "OBJECT IDENTIFIER",
	7: "ObjectDescriptor", 8: "EXTERNAL", 9: "REAL", 10: "ENUMERATED", 12: "UTF8String", 13: "RELATIVE-OID",
	16: "SEQUENCE", 17: "SET", 18: "NumericString", 19: "PrintableString", 20: "TeletexString",
	22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime", 26: "VisibleString", 28: "UniversalString", 30: "BMPString",
}

func hexShort(b []byte, max int) string {
	if len(b) <= max {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return strings.ToUpper(hex.EncodeToString(b[:max])) + fmt.Sprintf("… (%d byte)", len(b))
}

func hexColon(b []byte) string {
	s := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(s[i : i+2])
	}
	return sb.String()
}

// ---------- ASN.1 dump ----------

type dumper struct {
	nodes int
	limit int
}

func dumpASN1(b []byte) []Field {
	d := &dumper{limit: 6000}
	var out []Field
	off := 0
	for len(b) > 0 {
		t, rest, err := readTLV(b)
		if err != nil {
			out = append(out, Field{N: fmt.Sprintf("@%d ERROR", off), V: err.Error() + " — sisa " + fmt.Sprint(len(b)) + " byte: " + hexShort(b, 32)})
			break
		}
		out = append(out, d.node(t, off, 0))
		off += len(t.Full)
		b = rest
	}
	if d.nodes >= d.limit {
		out = append(out, Field{N: "…", V: fmt.Sprintf("tampilan dibatasi %d node", d.limit)})
	}
	return out
}

func (d *dumper) node(t tlv, off, depth int) Field {
	d.nodes++
	hdr := len(t.Full) - len(t.Content)
	var name string
	switch t.Class {
	case clsUniversal:
		name = tagNames[t.Tag]
		if name == "" {
			name = fmt.Sprintf("UNIVERSAL %d", t.Tag)
		}
	case clsApp:
		name = fmt.Sprintf("[APPLICATION %d]", t.Tag)
	case clsContext:
		name = fmt.Sprintf("[%d]", t.Tag)
	default:
		name = fmt.Sprintf("[PRIVATE %d]", t.Tag)
	}
	f := Field{N: fmt.Sprintf("@%d %s (%d)", off, name, len(t.Content))}
	if t.Indefinite {
		f.N += " indefinite"
	}
	if d.nodes >= d.limit || depth > 40 {
		return f
	}
	if t.Constructed {
		kids, err := children(t.Content)
		o := off + hdr
		for _, k := range kids {
			f.K = append(f.K, d.node(k, o, depth+1))
			o += len(k.Full)
			if d.nodes >= d.limit {
				break
			}
		}
		if err != nil {
			f.K = append(f.K, Field{N: "ERROR", V: err.Error()})
		}
		return f
	}
	c := t.Content
	if t.Class != clsUniversal {
		f.V = hexShort(c, 48)
		return f
	}
	switch t.Tag {
	case 1:
		f.V = "FALSE"
		if len(c) == 1 && c[0] != 0 {
			f.V = "TRUE"
		}
	case 2, 10:
		v := new(big.Int).SetBytes(c)
		if len(c) > 0 && c[0]&0x80 != 0 {
			v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(len(c)*8)))
		}
		if len(c) > 8 {
			f.V = hexShort(c, 64)
		} else {
			f.V = v.String()
		}
	case 5:
		f.V = ""
	case 6:
		s, err := oidString(c)
		if err != nil {
			f.V = "OID rusak"
		} else {
			f.V = s
			if n := oidName(s); n != "" {
				f.V += "  " + n
			}
		}
	case 23, 24:
		f.V = string(c)
	case 3:
		if len(c) > 1 && c[0] == 0 {
			if sub := d.encapsulated(c[1:], off+hdr+1, depth); sub != nil {
				f.K = sub
				f.V = "(berisi ASN.1)"
				return f
			}
		}
		if len(c) > 0 {
			f.V = fmt.Sprintf("unused=%d ", c[0]) + hexShort(c[1:], 48)
		}
	case 4:
		if sub := d.encapsulated(c, off+hdr, depth); sub != nil {
			f.K = sub
			f.V = "(berisi ASN.1)"
			return f
		}
		if isMostlyPrintable(c) {
			f.V = "\"" + string(c) + "\""
		} else {
			f.V = hexShort(c, 48)
		}
	default:
		if isStringTag(t.Tag) {
			s, _ := decodeString(t.Tag, c)
			f.V = s
		} else {
			f.V = hexShort(c, 48)
		}
	}
	return f
}

// encapsulated tries to decode content as a single constructed DER element.
func (d *dumper) encapsulated(c []byte, off, depth int) []Field {
	if len(c) < 2 || (c[0] != 0x30 && c[0] != 0x31) {
		return nil
	}
	t, rest, err := readTLV(c)
	if err != nil || len(rest) != 0 {
		return nil
	}
	if _, err := children(t.Content); err != nil {
		return nil
	}
	return []Field{d.node(t, off, depth+1)}
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 || len(b) > 200 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
