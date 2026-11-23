package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"x509inspector/engine"
)

func isCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "check", "inspect", "version", "-v", "--version", "help", "-h", "--help":
		return true
	}
	return false
}

// runCLI implements: x509-inspector check [flags] FILE...
func runCLI(args []string) int {
	attachConsole()
	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println("x509-inspector", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	}
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "keluaran JSON")
	host := fs.String("host", "", "hostname yang harus cocok dengan sertifikat")
	at := fs.String("at", "", "waktu validasi (mis. 2027-01-31 10:00), default sekarang")
	online := fs.Bool("online", false, "unduh CRL / OCSP / issuer (AIA)")
	noTrust := fs.Bool("no-system-trust", false, "jangan cek trust store OS")
	profile := fs.String("profile", "auto", "profil: auto | generic | icao | tls")
	pass := fs.String("password", "", "password PKCS#12")
	failOn := fs.String("fail-on", "", "exit code 2 jika ada temuan: error | warn")
	verbose := fs.Bool("all", false, "tampilkan juga temuan OK")
	fs.Usage = usage
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	if fs.NArg() == 0 {
		usage()
		return 1
	}
	var inputs []engine.Input
	for i, p := range fs.Args() {
		matches, _ := filepath.Glob(p)
		if len(matches) == 0 {
			matches = []string{p}
		}
		for j, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				fmt.Fprintln(os.Stderr, "tidak bisa membaca", m+":", err)
				continue
			}
			inputs = append(inputs, engine.Input{ID: fmt.Sprintf("f%d_%d", i, j), Name: filepath.Base(m), Path: m, Origin: "file", Data: b, Password: *pass})
		}
	}
	opts := engine.Options{Hostname: *host, At: *at, Online: *online, SystemTrust: !*noTrust, Profile: *profile, ExpiryWarnDays: 30}
	rep := engine.Analyze(inputs, opts, engine.HTTPFetcher())
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		fmt.Print(TextReport(rep, *verbose))
	}
	switch *failOn {
	case "error":
		if rep.Counts[engine.SevError] > 0 {
			return 2
		}
	case "warn":
		if rep.Counts[engine.SevError]+rep.Counts[engine.SevWarn] > 0 {
			return 2
		}
	}
	return 0
}

func usage() {
	fmt.Print(`X.509 Inspector ` + version + `

Tanpa argumen: membuka aplikasi desktop.

Mode baris perintah:
  x509-inspector check [opsi] FILE...      periksa file (PEM, DER, P7B, P12, CRL, CSR, kunci, ML, SOD)
  x509-inspector version

Opsi:
  -json                keluaran JSON
  -all                 tampilkan juga hasil OK
  -host NAMA           cek kecocokan hostname
  -at "2027-01-31 10:00"   waktu validasi (default: sekarang)
  -online              unduh CRL, OCSP, dan sertifikat issuer (AIA)
  -no-system-trust     jangan bertanya ke trust store OS
  -profile auto|generic|icao|tls
  -password PW         password PKCS#12
  -fail-on error|warn  exit code 2 bila ada temuan (untuk CI)
`)
}
