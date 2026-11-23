package engine

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
)

// Curve is a short-Weierstrass prime curve y^2 = x^3 + ax + b (mod p).
// Arithmetic is generic (math/big), so ICAO-style explicit parameters and
// Brainpool curves can be verified even though Go's crypto lacks them.
type Curve struct {
	Name           string
	OID            string
	P, A, B, N     *big.Int
	Gx, Gy         *big.Int
	H              int64
}

func (c *Curve) Bits() int { return c.N.BitLen() }

type ecPoint struct {
	X, Y *big.Int
	Inf  bool
}

func (c *Curve) onCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(c.P) >= 0 || y.Cmp(c.P) >= 0 {
		return false
	}
	l := new(big.Int).Mul(y, y)
	l.Mod(l, c.P)
	r := new(big.Int).Mul(x, x)
	r.Mul(r, x)
	ax := new(big.Int).Mul(c.A, x)
	r.Add(r, ax)
	r.Add(r, c.B)
	r.Mod(r, c.P)
	return l.Cmp(r) == 0
}

func (c *Curve) add(p, q ecPoint) ecPoint {
	if p.Inf {
		return q
	}
	if q.Inf {
		return p
	}
	if p.X.Cmp(q.X) == 0 {
		s := new(big.Int).Add(p.Y, q.Y)
		if s.Mod(s, c.P).Sign() == 0 {
			return ecPoint{Inf: true}
		}
		return c.double(p)
	}
	num := new(big.Int).Sub(q.Y, p.Y)
	den := new(big.Int).Sub(q.X, p.X)
	den.Mod(den, c.P)
	inv := new(big.Int).ModInverse(den, c.P)
	if inv == nil {
		return ecPoint{Inf: true}
	}
	l := num.Mul(num, inv)
	l.Mod(l, c.P)
	x3 := new(big.Int).Mul(l, l)
	x3.Sub(x3, p.X)
	x3.Sub(x3, q.X)
	x3.Mod(x3, c.P)
	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, l)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, c.P)
	return ecPoint{X: x3, Y: y3}
}

func (c *Curve) double(p ecPoint) ecPoint {
	if p.Inf || p.Y.Sign() == 0 {
		return ecPoint{Inf: true}
	}
	num := new(big.Int).Mul(p.X, p.X)
	num.Mul(num, big.NewInt(3))
	num.Add(num, c.A)
	den := new(big.Int).Lsh(p.Y, 1)
	den.Mod(den, c.P)
	inv := new(big.Int).ModInverse(den, c.P)
	if inv == nil {
		return ecPoint{Inf: true}
	}
	l := num.Mul(num, inv)
	l.Mod(l, c.P)
	x3 := new(big.Int).Mul(l, l)
	x3.Sub(x3, new(big.Int).Lsh(p.X, 1))
	x3.Mod(x3, c.P)
	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, l)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, c.P)
	return ecPoint{X: x3, Y: y3}
}

// Jacobian coordinates: x = X/Z^2, y = Y/Z^3 (Z == 0 means infinity).
type jac struct{ X, Y, Z *big.Int }

func (c *Curve) toJac(p ecPoint) jac {
	if p.Inf {
		return jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	}
	return jac{new(big.Int).Set(p.X), new(big.Int).Set(p.Y), big.NewInt(1)}
}

func (c *Curve) fromJac(j jac) ecPoint {
	if j.Z.Sign() == 0 {
		return ecPoint{Inf: true}
	}
	zi := new(big.Int).ModInverse(j.Z, c.P)
	if zi == nil {
		return ecPoint{Inf: true}
	}
	zi2 := new(big.Int).Mul(zi, zi)
	zi2.Mod(zi2, c.P)
	x := new(big.Int).Mul(j.X, zi2)
	x.Mod(x, c.P)
	zi3 := zi2.Mul(zi2, zi)
	y := new(big.Int).Mul(j.Y, zi3)
	y.Mod(y, c.P)
	return ecPoint{X: x, Y: y}
}

func (c *Curve) jDouble(p jac) jac {
	if p.Z.Sign() == 0 || p.Y.Sign() == 0 {
		return jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	}
	P := c.P
	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, P)
	s := new(big.Int).Mul(p.X, y2)
	s.Lsh(s, 2).Mod(s, P)
	z2 := new(big.Int).Mul(p.Z, p.Z)
	z2.Mod(z2, P)
	z4 := new(big.Int).Mul(z2, z2)
	z4.Mod(z4, P)
	m := new(big.Int).Mul(p.X, p.X)
	m.Mul(m, big.NewInt(3))
	m.Add(m, z4.Mul(z4, c.A))
	m.Mod(m, P)
	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, new(big.Int).Lsh(s, 1))
	x3.Mod(x3, P)
	y4 := new(big.Int).Mul(y2, y2)
	y4.Lsh(y4, 3)
	y3 := new(big.Int).Sub(s, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, y4)
	y3.Mod(y3, P)
	z3 := new(big.Int).Mul(p.Y, p.Z)
	z3.Lsh(z3, 1).Mod(z3, P)
	return jac{x3, y3, z3}
}

func (c *Curve) jAdd(p, q jac) jac {
	if p.Z.Sign() == 0 {
		return q
	}
	if q.Z.Sign() == 0 {
		return p
	}
	P := c.P
	z1z1 := new(big.Int).Mul(p.Z, p.Z)
	z1z1.Mod(z1z1, P)
	z2z2 := new(big.Int).Mul(q.Z, q.Z)
	z2z2.Mod(z2z2, P)
	u1 := new(big.Int).Mul(p.X, z2z2)
	u1.Mod(u1, P)
	u2 := new(big.Int).Mul(q.X, z1z1)
	u2.Mod(u2, P)
	s1 := new(big.Int).Mul(p.Y, z2z2)
	s1.Mul(s1, q.Z).Mod(s1, P)
	s2 := new(big.Int).Mul(q.Y, z1z1)
	s2.Mul(s2, p.Z).Mod(s2, P)
	if u1.Cmp(u2) == 0 {
		if s1.Cmp(s2) != 0 {
			return jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
		}
		return c.jDouble(p)
	}
	h := new(big.Int).Sub(u2, u1)
	h.Mod(h, P)
	r := new(big.Int).Sub(s2, s1)
	r.Mod(r, P)
	h2 := new(big.Int).Mul(h, h)
	h2.Mod(h2, P)
	h3 := new(big.Int).Mul(h2, h)
	h3.Mod(h3, P)
	u1h2 := new(big.Int).Mul(u1, h2)
	u1h2.Mod(u1h2, P)
	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, h3)
	x3.Sub(x3, new(big.Int).Lsh(u1h2, 1))
	x3.Mod(x3, P)
	y3 := new(big.Int).Sub(u1h2, x3)
	y3.Mul(y3, r)
	y3.Sub(y3, new(big.Int).Mul(s1, h3))
	y3.Mod(y3, P)
	z3 := new(big.Int).Mul(p.Z, q.Z)
	z3.Mul(z3, h).Mod(z3, P)
	return jac{x3, y3, z3}
}

func (c *Curve) jMul(k *big.Int, p ecPoint) jac {
	base := c.toJac(p)
	r := jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = c.jDouble(r)
		if k.Bit(i) == 1 {
			r = c.jAdd(r, base)
		}
	}
	return r
}

func (c *Curve) mul(k *big.Int, p ecPoint) ecPoint {
	return c.fromJac(c.jMul(k, p))
}

func (c *Curve) G() ecPoint { return ecPoint{X: c.Gx, Y: c.Gy} }

// decodePoint handles uncompressed (04) and compressed (02/03) points.
func (c *Curve) decodePoint(b []byte) (*big.Int, *big.Int, bool, error) {
	size := (c.P.BitLen() + 7) / 8
	if len(b) == 1+2*size && b[0] == 4 {
		x := new(big.Int).SetBytes(b[1 : 1+size])
		y := new(big.Int).SetBytes(b[1+size:])
		if !c.onCurve(x, y) {
			return x, y, false, errors.New("titik kunci publik tidak berada di kurva")
		}
		return x, y, false, nil
	}
	if len(b) == 1+size && (b[0] == 2 || b[0] == 3) {
		x := new(big.Int).SetBytes(b[1:])
		rhs := new(big.Int).Mul(x, x)
		rhs.Mul(rhs, x)
		rhs.Add(rhs, new(big.Int).Mul(c.A, x))
		rhs.Add(rhs, c.B)
		rhs.Mod(rhs, c.P)
		y := new(big.Int).ModSqrt(rhs, c.P)
		if y == nil {
			return x, nil, true, errors.New("titik terkompresi tidak valid")
		}
		if y.Bit(0) != uint(b[0]&1) {
			y.Sub(c.P, y)
		}
		return x, y, true, nil
	}
	return nil, nil, false, errors.New("format titik EC tidak dikenal / panjang salah")
}

// ecdsaVerify verifies (r,s) over digest with public point (x,y).
func (c *Curve) ecdsaVerify(x, y *big.Int, digest []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(c.N) >= 0 || s.Cmp(c.N) >= 0 {
		return false
	}
	e := new(big.Int).SetBytes(digest)
	if excess := len(digest)*8 - c.N.BitLen(); excess > 0 {
		e.Rsh(e, uint(excess))
	}
	w := new(big.Int).ModInverse(s, c.N)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, c.N)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, c.N)
	p := c.fromJac(c.jAdd(c.jMul(u1, c.G()), c.jMul(u2, ecPoint{X: x, Y: y})))
	if p.Inf {
		return false
	}
	v := new(big.Int).Mod(p.X, c.N)
	return v.Cmp(r) == 0
}

func hexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex " + s)
	}
	return v
}

func fromStd(name, oid string, e elliptic.Curve) *Curve {
	p := e.Params()
	a := new(big.Int).Sub(p.P, big.NewInt(3))
	return &Curve{Name: name, OID: oid, P: p.P, A: a, B: p.B, N: p.N, Gx: p.Gx, Gy: p.Gy, H: 1}
}

func hexCurve(name, oid, p, a, b, gx, gy, n string) *Curve {
	return &Curve{Name: name, OID: oid, P: hexInt(p), A: hexInt(a), B: hexInt(b), Gx: hexInt(gx), Gy: hexInt(gy), N: hexInt(n), H: 1}
}

var (
	curvesOnce sync.Once
	curves     []*Curve
	curveNotes []string
)

func knownCurves() []*Curve {
	curvesOnce.Do(func() {
		cand := []*Curve{
			fromStd("P-224", "1.3.132.0.33", elliptic.P224()),
			fromStd("P-256", "1.2.840.10045.3.1.7", elliptic.P256()),
			fromStd("P-384", "1.3.132.0.34", elliptic.P384()),
			fromStd("P-521", "1.3.132.0.35", elliptic.P521()),
			hexCurve("secp256k1", "1.3.132.0.10",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "0", "7",
				"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
				"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
			hexCurve("brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5",
				"D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
				"68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
				"2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
				"0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
				"58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
				"D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"),
			hexCurve("brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7",
				"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
				"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
				"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
				"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
				"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
				"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
			hexCurve("brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9",
				"D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
				"3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
				"520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
				"43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
				"14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
				"D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"),
			hexCurve("brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11",
				"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
				"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
				"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
				"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
				"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
				"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"),
			hexCurve("brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13",
				"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
				"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
				"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
				"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
				"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
				"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"),
		}
		// Self-test every table entry: G on curve and n*G = O. Entries that fail are dropped.
		for _, c := range cand {
			if c.onCurve(c.Gx, c.Gy) && c.mul(c.N, c.G()).Inf {
				curves = append(curves, c)
			} else {
				curveNotes = append(curveNotes, c.Name)
			}
		}
	})
	return curves
}

func curveByOID(oid string) *Curve {
	for _, c := range knownCurves() {
		if c.OID == oid {
			return c
		}
	}
	return nil
}

func matchCurve(c *Curve) *Curve {
	for _, k := range knownCurves() {
		if k.P.Cmp(c.P) == 0 && k.N.Cmp(c.N) == 0 && k.Gx.Cmp(c.Gx) == 0 && k.Gy.Cmp(c.Gy) == 0 &&
			new(big.Int).Mod(c.A, c.P).Cmp(new(big.Int).Mod(k.A, k.P)) == 0 && k.B.Cmp(c.B) == 0 {
			return k
		}
	}
	return nil
}

// ---- explicit ECParameters (RFC 3279) ----

type ecFieldID struct {
	FieldType asn1.ObjectIdentifier
	Params    asn1.RawValue
}
type ecCurveRaw struct {
	A, B []byte
	Seed asn1.BitString `asn1:"optional"`
}
type ecParamsRaw struct {
	Version  int
	FieldID  ecFieldID
	Curve    ecCurveRaw
	Base     []byte
	Order    *big.Int
	Cofactor *big.Int `asn1:"optional"`
}

func parseExplicitCurve(der []byte) (*Curve, []string, error) {
	var p ecParamsRaw
	rest, err := asn1.Unmarshal(der, &p)
	if err != nil {
		return nil, nil, err
	}
	var notes []string
	if len(rest) > 0 {
		notes = append(notes, "ada data sisa setelah ECParameters")
	}
	if p.FieldID.FieldType.String() != "1.2.840.10045.1.1" {
		return nil, notes, errors.New("hanya prime-field yang didukung (characteristic-two tidak)")
	}
	var prime *big.Int
	if _, err := asn1.Unmarshal(p.FieldID.Params.FullBytes, &prime); err != nil {
		return nil, notes, errors.New("prime field tidak bisa dibaca")
	}
	c := &Curve{Name: "eksplisit", P: prime, A: new(big.Int).SetBytes(p.Curve.A), B: new(big.Int).SetBytes(p.Curve.B), N: p.Order, H: 1}
	if p.Cofactor != nil {
		c.H = p.Cofactor.Int64()
	}
	x, y, _, err := c.decodePointRaw(p.Base)
	if err != nil {
		return nil, notes, errors.New("base point (G) tidak valid: " + err.Error())
	}
	c.Gx, c.Gy = x, y
	if !c.onCurve(x, y) {
		return c, notes, errors.New("base point G tidak berada di kurva")
	}
	if k := matchCurve(c); k != nil {
		c.Name = k.Name
		c.OID = k.OID
	}
	return c, notes, nil
}

// decodePointRaw is decodePoint without the on-curve requirement (used for G
// before we know the curve is sane).
func (c *Curve) decodePointRaw(b []byte) (*big.Int, *big.Int, bool, error) {
	x, y, comp, err := c.decodePoint(b)
	if err != nil && x != nil && y != nil {
		return x, y, comp, nil
	}
	return x, y, comp, err
}
