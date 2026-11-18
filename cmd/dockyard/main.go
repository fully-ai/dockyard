package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fully-ai/dockyard/internal/api"
	"github.com/fully-ai/dockyard/internal/docker"
	"github.com/fully-ai/dockyard/internal/store"
)

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func randomSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func main() {
	addr := flag.String("addr", envOr("DOCKYARD_ADDR", "127.0.0.1:8091"), "HTTP listen address")
	dockerHost := flag.String("docker-host", envOr("DOCKYARD_DOCKER_HOST", envOr("DOCKER_HOST", "unix:///var/run/docker.sock")), "Docker Engine socket/TCP URI")
	dataDir := flag.String("data", envOr("DOCKYARD_DATA_DIR", "./data"), "SQLite data directory")
	jwtSecret := flag.String("jwt-secret", envOr("DOCKYARD_JWT_SECRET", ""), "HMAC JWT signing secret")
	allowSensitive := flag.Bool("allow-sensitive-mounts", envOr("DOCKYARD_ALLOW_SENSITIVE_MOUNTS", "false") == "true", "Allow privileged containers and sensitive host bind mounts")
	flag.Parse()

	secret := *jwtSecret
	if secret == "" {
		secret = randomSecret()
		fmt.Fprintln(os.Stderr, "warning: DOCKYARD_JWT_SECRET not set, generated ephemeral signing key for this session")
	}

	dc, err := docker.NewClient(*dockerHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "docker client init error: %v\n", err)
		os.Exit(1)
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite init error: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	srv := api.NewServer(dc, st, secret, *allowSensitive)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Printf("Dockyard listening on http://%s (engine=%s)\n", *addr, *dockerHost)
	if err := httpSrv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
