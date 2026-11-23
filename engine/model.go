// Package engine parses and validates X.509-related files (certificates, CRLs,
// CSRs, keys, PKCS#7/CMS, PKCS#12, ICAO master lists / SOD).
//
// Design rule: nothing here ever aborts an analysis. Every problem becomes a
// Finding and the engine keeps going with whatever it could still decode.
package engine

import "time"

// Severity levels, ordered from worst to best.
const (
	SevError = "error"
	SevWarn  = "warn"
	SevInfo  = "info"
	SevOK    = "ok"
)

var sevRank = map[string]int{SevError: 3, SevWarn: 2, SevInfo: 1, SevOK: 0}

// Finding is one validation result.
type Finding struct {
	Sev    string `json:"sev"`
	Cat    string `json:"cat"`
	Msg    string `json:"msg"`
	Detail string `json:"detail,omitempty"`
	Ref    string `json:"ref,omitempty"`
}

// Field is a node in a display tree (decoded fields or raw ASN.1).
type Field struct {
	N string  `json:"n"`
	V string  `json:"v,omitempty"`
	K []Field `json:"k,omitempty"`
}

// KV is a summary line.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// ChainLink is one step of a built certification path.
type ChainLink struct {
	ID     string `json:"id,omitempty"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok | warn | error | info
	Note   string `json:"note,omitempty"`
}

// Object is one decoded item found inside a file.
type Object struct {
	ID       string         `json:"id"`
	FileID   string         `json:"fileId"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Where    string         `json:"where"`
	Role     string         `json:"role,omitempty"`
	Summary  []KV           `json:"summary"`
	Fields   []Field        `json:"fields"`
	Findings []Finding      `json:"findings"`
	Chain    []ChainLink    `json:"chain,omitempty"`
	PEM      string         `json:"pem,omitempty"`
	Worst    string         `json:"worst"`
	Counts   map[string]int `json:"counts"`

	der    []byte
	pemTyp string
}

func (o *Object) add(sev, cat, msg string, extra ...string) {
	f := Finding{Sev: sev, Cat: cat, Msg: msg}
	if len(extra) > 0 {
		f.Detail = extra[0]
	}
	if len(extra) > 1 {
		f.Ref = extra[1]
	}
	o.Findings = append(o.Findings, f)
}

func (o *Object) sum(k, v string) {
	if v != "" {
		o.Summary = append(o.Summary, KV{k, v})
	}
}

// FileEntry describes one input file.
type FileEntry struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Path          string    `json:"path,omitempty"`
	Origin        string    `json:"origin"`
	Size          int       `json:"size"`
	Format        string    `json:"format"`
	SHA256        string    `json:"sha256"`
	Findings      []Finding `json:"findings"`
	Objects       []string  `json:"objects"`
	NeedsPassword bool      `json:"needsPassword,omitempty"`
}

func (f *FileEntry) add(sev, cat, msg string, extra ...string) {
	fd := Finding{Sev: sev, Cat: cat, Msg: msg}
	if len(extra) > 0 {
		fd.Detail = extra[0]
	}
	f.Findings = append(f.Findings, fd)
}

// Input is raw data handed to the engine.
type Input struct {
	ID       string
	Name     string
	Path     string
	Origin   string // file | paste | online
	Data     []byte
	Password string
}

// Options tune the analysis.
type Options struct {
	Hostname       string `json:"hostname"`
	At             string `json:"at"`          // RFC3339 / "2006-01-02 15:04"; empty = now
	Online         bool   `json:"online"`      // fetch CRL / OCSP / AIA
	SystemTrust    bool   `json:"systemTrust"` // ask the OS trust store
	Profile        string `json:"profile"`     // auto | generic | icao | tls
	ExpiryWarnDays int    `json:"expiryWarnDays"`
}

// Report is the full result.
type Report struct {
	Version   int            `json:"version"`
	Generated string         `json:"generated"`
	At        string         `json:"at"`
	Options   Options        `json:"options"`
	Files     []*FileEntry   `json:"files"`
	Objects   []*Object      `json:"objects"`
	Counts    map[string]int `json:"counts"`
	Notes     []Finding      `json:"notes,omitempty"`

	at time.Time
}

// ObjectDER returns the DER bytes and PEM type of an object (nil for private keys).
func (r *Report) ObjectDER(id string) ([]byte, string) {
	for _, o := range r.Objects {
		if o.ID == id && o.Kind != "private-key" {
			return o.der, o.pemTyp
		}
	}
	return nil, ""
}

// ObjectASN1 builds the raw ASN.1 tree lazily (can be big).
func (r *Report) ObjectASN1(id string) []Field {
	for _, o := range r.Objects {
		if o.ID == id {
			if o.Kind == "private-key" {
				return []Field{{N: "Disembunyikan", V: "struktur kunci privat tidak ditampilkan demi keamanan"}}
			}
			if o.der == nil {
				return nil
			}
			return dumpASN1(o.der)
		}
	}
	for _, f := range r.Files {
		if f.ID == id {
			return []Field{{N: "Pilih objek di dalam file untuk melihat ASN.1"}}
		}
	}
	return nil
}

func worst(fs []Finding) string {
	w := SevOK
	for _, f := range fs {
		if sevRank[f.Sev] > sevRank[w] {
			w = f.Sev
		}
	}
	return w
}

func countSev(fs []Finding) map[string]int {
	m := map[string]int{SevError: 0, SevWarn: 0, SevInfo: 0, SevOK: 0}
	for _, f := range fs {
		m[f.Sev]++
	}
	return m
}
