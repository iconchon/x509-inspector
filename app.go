package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"x509inspector/engine"
)

const maxFileSize = 64 << 20

// App is bound to the frontend. Every method is safe to call concurrently;
// long work (online checks) runs without blocking the UI.
type App struct {
	ctx     context.Context
	mu      sync.Mutex
	inputs  []engine.Input
	opts    engine.Options
	nextID  int
	gen     int // bumps on every change, lets the UI drop stale results
	last    *engine.Report
	fetcher engine.Fetcher
}

func NewApp() *App {
	return &App{
		opts:    engine.Options{Profile: "auto", SystemTrust: true, ExpiryWarnDays: 30},
		fetcher: engine.HTTPFetcher(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	runtime.OnFileDrop(ctx, func(x, y int, paths []string) {
		r := a.AddPaths(paths)
		wailsEmit(ctx, "result", r)
	})
}

func wailsEmit(ctx context.Context, name string, data any) { runtime.EventsEmit(ctx, name, data) }

// Result is what every call returns to the UI.
type Result struct {
	Gen    int            `json:"gen"`
	Report *engine.Report `json:"report"`
	Error  string         `json:"error,omitempty"`
}

func (a *App) analyze(online bool) Result {
	a.mu.Lock()
	inputs := append([]engine.Input(nil), a.inputs...)
	opts := a.opts
	gen := a.gen
	a.mu.Unlock()
	opts.Online = online
	rep := engine.Analyze(inputs, opts, a.fetcher)
	a.mu.Lock()
	if gen == a.gen {
		a.last = rep
	}
	a.mu.Unlock()
	return Result{Gen: gen, Report: rep}
}

func (a *App) addInput(in engine.Input) {
	a.nextID++
	in.ID = fmt.Sprintf("f%d", a.nextID)
	a.inputs = append(a.inputs, in)
	a.gen++
}

// OpenFiles shows a native file dialog and analyzes the selected files.
func (a *App) OpenFiles() Result {
	paths, err := runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Pilih file sertifikat / CRL / CSR / kunci / PKCS#7 / PKCS#12",
		Filters: []runtime.FileFilter{
			{DisplayName: "File PKI", Pattern: "*.pem;*.crt;*.cer;*.der;*.cert;*.ca-bundle;*.crl;*.csr;*.req;*.key;*.pub;*.p7b;*.p7c;*.p7s;*.p7m;*.spc;*.p12;*.pfx;*.ml;*.sod;*.bin;*.txt"},
			{DisplayName: "Semua file", Pattern: "*.*"},
		},
	})
	if err != nil {
		return Result{Gen: -1, Error: err.Error()}
	}
	if len(paths) == 0 {
		return Result{Gen: -1}
	}
	return a.AddPaths(paths)
}

// AddPaths reads files from disk (used by dialog, drag & drop and "open with").
func (a *App) AddPaths(paths []string) Result {
	var errs []string
	a.mu.Lock()
	for i := 0; i < len(paths); i++ {
		p := paths[i]
		st, err := os.Stat(p)
		if err != nil {
			errs = append(errs, p+": "+err.Error())
			continue
		}
		if st.IsDir() {
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				if !e.IsDir() && len(paths) < 2000 {
					paths = append(paths, filepath.Join(p, e.Name()))
				}
			}
			continue
		}
		if st.Size() > maxFileSize {
			errs = append(errs, p+": file terlalu besar (>64 MB)")
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, p+": "+err.Error())
			continue
		}
		a.addInput(engine.Input{Name: filepath.Base(p), Path: p, Origin: "file", Data: b})
	}
	a.mu.Unlock()
	r := a.analyze(false)
	r.Error = strings.Join(errs, "\n")
	return r
}

// AddData receives a file dropped into the window (base64 content).
func (a *App) AddData(name, b64 string) Result {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Result{Gen: -1, Error: "data file tidak valid"}
	}
	if len(b) > maxFileSize {
		return Result{Gen: -1, Error: name + ": file terlalu besar"}
	}
	a.mu.Lock()
	a.addInput(engine.Input{Name: name, Origin: "file", Data: b})
	a.mu.Unlock()
	return a.analyze(false)
}

// AddText analyzes pasted text (PEM, base64 or hex).
func (a *App) AddText(text string) Result {
	if strings.TrimSpace(text) == "" {
		return Result{Gen: -1, Error: "teks kosong"}
	}
	a.mu.Lock()
	a.addInput(engine.Input{Name: fmt.Sprintf("Tempelan %s", time.Now().Format("15:04:05")), Origin: "paste", Data: []byte(text)})
	a.mu.Unlock()
	return a.analyze(false)
}

// Remove drops one input file.
func (a *App) Remove(fileID string) Result {
	a.mu.Lock()
	var out []engine.Input
	for _, in := range a.inputs {
		if in.ID != fileID {
			out = append(out, in)
		}
	}
	a.inputs = out
	a.gen++
	a.mu.Unlock()
	return a.analyze(false)
}

// Clear removes everything.
func (a *App) Clear() Result {
	a.mu.Lock()
	a.inputs = nil
	a.gen++
	a.mu.Unlock()
	return a.analyze(false)
}

// SetPassword sets the PKCS#12 password for one file and re-analyzes.
func (a *App) SetPassword(fileID, pw string) Result {
	a.mu.Lock()
	for i := range a.inputs {
		if a.inputs[i].ID == fileID {
			a.inputs[i].Password = pw
		}
	}
	a.gen++
	a.mu.Unlock()
	return a.analyze(false)
}

// GetOptions returns current options.
func (a *App) GetOptions() engine.Options {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.opts
}

// SetOptions updates options and re-analyzes.
func (a *App) SetOptions(o engine.Options) Result {
	a.mu.Lock()
	o.Online = false
	a.opts = o
	a.gen++
	a.mu.Unlock()
	return a.analyze(false)
}

// Analyze re-runs the analysis; online=true also fetches CRL/OCSP/AIA.
func (a *App) Analyze(online bool) Result { return a.analyze(online) }

// ASN1 returns the raw ASN.1 tree of an object.
func (a *App) ASN1(objID string) []engine.Field {
	a.mu.Lock()
	r := a.last
	a.mu.Unlock()
	if r == nil {
		return nil
	}
	return r.ObjectASN1(objID)
}

// ExportObject saves one object as PEM or DER.
func (a *App) ExportObject(objID, format string) string {
	a.mu.Lock()
	r := a.last
	a.mu.Unlock()
	if r == nil {
		return "tidak ada data"
	}
	der, typ := r.ObjectDER(objID)
	if der == nil {
		return "objek ini tidak bisa diekspor"
	}
	ext := ".pem"
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if format == "der" {
		ext, data = ".der", der
		if typ == "CERTIFICATE" {
			ext = ".cer"
		}
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "Simpan objek", DefaultFilename: "objek" + ext})
	if err != nil || path == "" {
		return ""
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err.Error()
	}
	return "Tersimpan: " + path
}

// ExportReport saves the last report as JSON or text.
func (a *App) ExportReport(format string) string {
	a.mu.Lock()
	r := a.last
	a.mu.Unlock()
	if r == nil {
		return "tidak ada laporan"
	}
	name := "laporan-x509-" + time.Now().Format("20060102-150405")
	var data []byte
	if format == "json" {
		data, _ = json.MarshalIndent(r, "", "  ")
		name += ".json"
	} else {
		data = []byte(TextReport(r, true))
		name += ".txt"
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "Simpan laporan", DefaultFilename: name})
	if err != nil || path == "" {
		return ""
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err.Error()
	}
	return "Laporan tersimpan: " + path
}

// CopyText puts text on the clipboard.
func (a *App) CopyText(s string) bool {
	return runtime.ClipboardSetText(a.ctx, s) == nil
}

// Version info for the UI.
func (a *App) Version() string { return version }
