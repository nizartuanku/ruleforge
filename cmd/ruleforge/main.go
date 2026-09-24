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
	maxUpload := flag.Int64("max-upload", webui.DefaultMaxUploadBytes, "maximum bytes accepted in one configuration upload request")
	tmpDir := flag.String("tmp", "", "directory for uploads while they are parsed (default: system temporary directory)")
	aiURL := flag.String("ai-assist-url", os.Getenv("RULEFORGE_AI_ASSIST_URL"), "optional hexward-ai sidecar URL for AI-narrated explanations of conversion issues, e.g. http://127.0.0.1:8435 (off when empty)")
	aiKeyFile := flag.String("ai-assist-key-file", os.Getenv("RULEFORGE_AI_ASSIST_KEY_FILE"), "API key file for a dedicated AI host or your own OpenAI-compatible endpoint (Pro/Team)")
	aiLang := flag.String("ai-assist-lang", os.Getenv("RULEFORGE_AI_ASSIST_LANG"), "language of AI explanations: en (default) or id")
	aiNoThinking := flag.Bool("ai-assist-no-thinking", os.Getenv("RULEFORGE_AI_ASSIST_NO_THINKING") == "1", "disable reasoning mode (Qwen3 enterprise profiles)")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	// Job payloads (Config/Results/Review/reports) live as gzip files next to
	// the DB, not as SQLite blob columns -- see store/jobs.go for why.
	st, err := store.NewSQLite(db, *dbPath+"-data")
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
	srv.MaxUploadBytes = *maxUpload
	srv.TempDir = *tmpDir

	aiAssist, err := webui.NewAIAssist(webui.AIConfig{URL: *aiURL, KeyFile: *aiKeyFile, Language: *aiLang, NoThinking: *aiNoThinking})
	if err != nil {
		fatal(err.Error())
	}
	srv.AI = aiAssist
	if aiAssist != nil {
		fmt.Fprintf(os.Stderr, "ruleforge: AI Assist on — explanations from %s (language %s)\n", aiAssist.Endpoint, aiAssist.Language)
	}

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
