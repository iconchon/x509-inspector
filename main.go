package main

import (
	"context"
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

var version = "1.0.0"

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	args := os.Args[1:]
	if isCLI(args) {
		os.Exit(runCLI(args))
	}
	app := NewApp()
	err := wails.Run(&options.App{
		Title:     "X.509 Inspector",
		Width:     1280,
		Height:    820,
		MinWidth:  900,
		MinHeight: 560,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 248, G: 248, B: 246, A: 1},
		OnStartup:        app.startup,
		OnDomReady: func(ctx context.Context) {
			// files passed on the command line (e.g. "Open with")
			if len(args) > 0 {
				go func() {
					r := app.AddPaths(args)
					wailsEmit(ctx, "result", r)
				}()
			}
		},
		DragAndDrop: &options.DragAndDrop{EnableFileDrop: true, DisableWebViewDrop: true},
		Bind:        []interface{}{app},
		Windows:     &windows.Options{Theme: windows.SystemDefault},
		Mac:         &mac.Options{About: &mac.AboutInfo{Title: "X.509 Inspector", Message: "Pemeriksa file sertifikat X.509 " + version}},
		Linux:       &linux.Options{ProgramName: "x509-inspector"},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
