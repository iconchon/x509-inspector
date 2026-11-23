package engine

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

// PrivKey describes a private key without retaining more than needed.
type PrivKey struct {
	Obj       *Object
	Format    string // PKCS#8, PKCS#1, SEC1, PKCS#8 terenkripsi
	Pub       *PubKey
	Encrypted bool
	Valid     string
}

type pkcs8Raw struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func parsePrivKey(der []byte, hint string) (*PrivKey, error) {
	k := &PrivKey{}
	if hint == "ENCRYPTED PRIVATE KEY" {
		k.Format, k.Encrypted = "PKCS#8 terenkripsi", true
		return k, nil
	}
	// PKCS#8
	var p8 pkcs8Raw
	if rest, err := asn1.Unmarshal(der, &p8); err == nil && len(rest) == 0 && len(p8.Algo.Algorithm) > 0 {
		k.Format = "PKCS#8"
		alg := p8.Algo.Algorithm.String()
		if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			k.Pub = pubFromStd(key)
			if rk, ok := key.(*rsa.PrivateKey); ok {
				if rk.Validate() != nil {
					k.Valid = "kunci RSA tidak konsisten"
				}
			}
			return k, nil
		}
		if alg == "1.2.840.10045.2.1" {
			pk, err := ecPrivToPub(p8.PrivateKey, p8.Algo.Parameters)
			if err != nil {
				return nil, err
			}
			k.Pub = pk
			return k, nil
		}
		k.Pub = &PubKey{Algo: oidLabelS(alg), AlgOID: alg}
		return k, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		k.Format = "PKCS#1 (RSA)"
		k.Pub = pubFromStd(key)
		return k, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		k.Format = "SEC1 (EC)"
		k.Pub = pubFromStd(key)
		return k, nil
	}
	if t, rest, err := readTLV(der); err == nil && len(rest) == 0 && len(t.Content) > 3 && t.Content[0] == 2 && t.Content[1] == 1 && t.Content[2] == 1 {
		k.Format = "SEC1 (EC)"
		pk, err := ecPrivToPub(der, asn1.RawValue{})
		if err != nil {
			return nil, err
		}
		k.Pub = pk
		return k, nil
	}
	return nil, errors.New("bukan kunci privat yang dikenali")
}

func pubFromStd(key any) *PubKey {
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		if s, ok := key.(interface{ Public() any }); ok {
			pub = s.Public()
		}
	}
	if pub == nil {
		return &PubKey{Algo: "unknown"}
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return &PubKey{Algo: "unknown", Err: err.Error()}
	}
	return parseSPKI(der)
}

// ecPrivToPub derives the public point from a SEC1 key (handles explicit / brainpool curves).
func ecPrivToPub(sec1 []byte, outerParams asn1.RawValue) (*PubKey, error) {
	t, _, err := readTLV(sec1)
	if err != nil {
		return nil, errors.New("ECPrivateKey rusak")
	}
	kids, _ := children(t.Content)
	if len(kids) < 2 || !kids[1].is(clsUniversal, 4) {
		return nil, errors.New("ECPrivateKey rusak")
	}
	var ec struct {
		PrivateKey []byte
		PublicKey  asn1.BitString
	}
	ec.PrivateKey = kids[1].Content
	params := outerParams
	for _, k := range kids[2:] {
		if k.is(clsContext, 0) && len(params.FullBytes) == 0 {
			var rv asn1.RawValue
			if _, err := asn1.Unmarshal(k.Content, &rv); err != nil {
				return nil, errors.New("parameter kurva rusak")
			}
			params = rv
		}
		if k.is(clsContext, 1) {
			asn1.Unmarshal(k.Content, &ec.PublicKey)
		}
	}
	if len(params.FullBytes) == 0 {
		return nil, errors.New("parameter kurva tidak ada")
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: params}
	probe := parseKeyFrom(alg, nil, nil)
	if probe.EC == nil || probe.EC.Curve == nil {
		return nil, errors.New("kurva tidak didukung")
	}
	c := probe.EC.Curve
	d := new(big.Int).SetBytes(ec.PrivateKey)
	p := c.mul(d, c.G())
	if p.Inf {
		return nil, errors.New("skalar kunci privat tidak valid")
	}
	size := (c.P.BitLen() + 7) / 8
	pt := make([]byte, 1+2*size)
	pt[0] = 4
	p.X.FillBytes(pt[1 : 1+size])
	p.Y.FillBytes(pt[1+size:])
	pub := parseKeyFrom(alg, pt, nil)
	if len(ec.PublicKey.Bytes) > 0 {
		stored := parseKeyFrom(alg, ec.PublicKey.RightAlign(), nil)
		if !stored.Equal(pub) {
			pub.Warnings = append(pub.Warnings, "kunci publik yang tersimpan di file tidak cocok dengan kunci privat")
		}
	}
	return pub, nil
}

func buildPrivKeyObject(k *PrivKey) {
	o := k.Obj
	o.Label = "Kunci privat"
	o.sum("Format", k.Format)
	o.add(SevWarn, "Keamanan", "File berisi KUNCI PRIVAT", "Simpan dengan aman, jangan dibagikan. Inspector ini tidak menampilkan material kunci privat.")
	if k.Encrypted {
		o.Label = "Kunci privat (terenkripsi)"
		o.add(SevInfo, "Kunci", "Kunci privat terenkripsi — tidak didekripsi, jadi tidak bisa dicocokkan dengan sertifikat")
		o.Fields = []Field{{N: "Format", V: k.Format}}
		return
	}
	if k.Pub != nil {
		o.Label = "Kunci privat " + k.Pub.Describe()
		o.sum("Kunci", k.Pub.Describe())
		o.Fields = []Field{{N: "Format", V: k.Format}, keyFields(k.Pub)}
		keyFindings(o, k.Pub, "Kunci")
	}
	if k.Valid != "" {
		o.add(SevError, "Kunci", k.Valid)
	}
}
