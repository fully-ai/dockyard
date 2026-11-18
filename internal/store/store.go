package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fully-ai/dockyard/internal/docker"
	_ "modernc.org/sqlite"
)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	CreatedAt    string `json:"created_at"`
}

type AuditEntry struct {
	ID        string `json:"id"`
	Actor     string `json:"actor"`
	Role      string `json:"role"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Details   string `json:"details"`
	CreatedAt string `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "dockyard.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	schema := `
	PRAGMA journal_mode = WAL;
	PRAGMA foreign_keys = ON;
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		actor TEXT NOT NULL,
		role TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		status TEXT NOT NULL,
		details TEXT NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
	CREATE TABLE IF NOT EXISTS container_stats (
		id TEXT PRIMARY KEY,
		container_id TEXT NOT NULL,
		cpu_percent REAL NOT NULL,
		mem_used_mb REAL NOT NULL,
		mem_limit_mb REAL NOT NULL,
		mem_percent REAL NOT NULL,
		net_rx_bytes INTEGER NOT NULL,
		net_tx_bytes INTEGER NOT NULL,
		recorded_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_stats_container ON container_stats(container_id, recorded_at DESC);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Store) CreateUser(username, passwordHash string) (User, error) {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return User{}, err
	}
	role := "viewer"
	if count == 0 {
		role = "admin"
	}
	u := User{
		ID:           newID(),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	_, err := s.db.Exec(
		"INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
		u.ID, u.Username, u.PasswordHash, u.Role, u.CreatedAt,
	)
	return u, err
}

func (s *Store) GetUserByUsername(username string) (User, error) {
	var u User
	err := s.db.QueryRow(
		"SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt)
	return u, err
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, username, role, created_at FROM users ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUserRole(userID, role string) error {
	res, err := s.db.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RecordAudit(actor, role, action, target, status, details string) {
	_, _ = s.db.Exec(
		"INSERT INTO audit_logs (id, actor, role, action, target, status, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		newID(), actor, role, action, target, status, details, time.Now().UTC().Format(time.RFC3339),
	)
}

func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		"SELECT id, actor, role, action, target, status, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Actor, &e.Role, &e.Action, &e.Target, &e.Status, &e.Details, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) RecordMetricSample(m docker.ContainerMetrics) error {
	_, err := s.db.Exec(
		`INSERT INTO container_stats (id, container_id, cpu_percent, mem_used_mb, mem_limit_mb, mem_percent, net_rx_bytes, net_tx_bytes, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID(), m.ContainerID, m.CPUPercent, m.MemUsedMB, m.MemLimitMB, m.MemPercent, m.NetRxBytes, m.NetTxBytes, m.RecordedAt,
	)
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(
		`DELETE FROM container_stats WHERE container_id = ? AND id NOT IN (
			SELECT id FROM container_stats WHERE container_id = ? ORDER BY recorded_at DESC LIMIT 60
		)`,
		m.ContainerID, m.ContainerID,
	)
	return nil
}

func (s *Store) ListMetricHistory(containerID string) ([]docker.ContainerMetrics, error) {
	rows, err := s.db.Query(
		`SELECT container_id, cpu_percent, mem_used_mb, mem_limit_mb, mem_percent, net_rx_bytes, net_tx_bytes, recorded_at
		 FROM container_stats WHERE container_id = ? ORDER BY recorded_at ASC LIMIT 60`,
		containerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []docker.ContainerMetrics
	for rows.Next() {
		var m docker.ContainerMetrics
		if err := rows.Scan(&m.ContainerID, &m.CPUPercent, &m.MemUsedMB, &m.MemLimitMB, &m.MemPercent, &m.NetRxBytes, &m.NetTxBytes, &m.RecordedAt); err != nil {
			return nil, fmt.Errorf("scan metric: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
