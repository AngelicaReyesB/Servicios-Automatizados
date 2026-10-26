// Command server arranca la consola de automatización de servicios.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"consola/internal/config"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/web"
)

func main() {
	cfgPath := flag.String("config", "config.json", "ruta del archivo de configuración")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	opLog, err := oplog.New(filepath.Join(cfg.DataDir, "logs", "operaciones.jsonl"))
	if err != nil {
		log.Fatal(err)
	}
	defer opLog.Close()

	mgr, err := runner.NewManager(cfg)
	if err != nil {
		log.Fatal(err)
	}
	app, err := web.New(cfg, mgr, opLog)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      20 * time.Minute, // apt install puede tardar
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("Consola disponible en http://%s", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
