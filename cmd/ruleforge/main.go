// ruleforge is the RuleForge product binary: multivendor firewall migration.
//
//	ruleforge                # dashboard on 127.0.0.1:8428
//	ruleforge -listen :8428  # listen on all interfaces (put a proxy in front)
//
// Upload a firewall configuration (Cisco ASA/FTD, Palo Alto PAN-OS/Panorama,
// Fortinet FortiGate incl. VDOMs, Check Point), get a deep analysis, review
// and edit the source→target mapping, convert to any other supported vendor,
// and walk the before/after review with the two report documents.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/ruleforge/store"
	"github.com/nizartuanku/ruleforge/webui"
)

// version is stamped by the release process.
var version = "0.1.0"

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

func main() {
	listen := flag.String("listen", "127.0.0.1:8428", "dashboard listen address")
	dbPath := flag.String("db", "ruleforge.db", "SQLite database path")
	licFile := flag.String("license", "ruleforge-license.key", "license key file")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLite(db)
	if err != nil {
		fatal(err.Error())
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	srv := webui.New(st, pub, *licFile, version)

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		fmt.Printf("RuleForge %s — dashboard on http://%s (tier: %s)\n", version, *listen, srv.Activation().Tier)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal(err.Error())
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "ruleforge: "+msg)
	os.Exit(1)
}
