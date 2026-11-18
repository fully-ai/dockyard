package api

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fully-ai/dockyard/internal/auth"
	"github.com/fully-ai/dockyard/internal/docker"
	"github.com/fully-ai/dockyard/internal/store"
)

//go:embed index.html
var indexHTML []byte

var (
	validUserRe  = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)
	validNameRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	validImageRe = regexp.MustCompile(`^[a-zA-Z0-9._:/@-]{1,200}$`)
	validIDRe    = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)
)

type Server struct {
	docker              *docker.Client
	store               *store.Store
	jwtSecret           string
	allowSensitiveMount bool
	authLimiter         *auth.RateLimiter
}

func NewServer(dc *docker.Client, st *store.Store, jwtSecret string, allowSensitiveMount bool) *Server {
	return &Server{
		docker:              dc,
		store:               st,
		jwtSecret:           jwtSecret,
		allowSensitiveMount: allowSensitiveMount,
		authLimiter:         auth.NewRateLimiter(20, time.Minute),
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireRole(minRole string, next func(http.ResponseWriter, *http.Request, auth.Claims)) http.HandlerFunc {
	rank := map[string]int{"viewer": 1, "operator": 2, "admin": 3}
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if !strings.HasPrefix(header, "Bearer ") || token == "" {
			if q := r.URL.Query().Get("token"); q != "" && r.Method == http.MethodGet {
				token = q
			}
		}
		claims, err := auth.VerifyJWT(token, s.jwtSecret)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if rank[claims.Role] < rank[minRole] {
			writeErr(w, http.StatusForbidden, "insufficient role privileges")
			return
		}
		next(w, r, claims)
	}
}

func (s *Server) validateCreateSpec(spec *docker.CreateContainerSpec) error {
	if !validImageRe.MatchString(spec.Image) {
		return errors.New("invalid image reference")
	}
	if spec.Name != "" && !validNameRe.MatchString(spec.Name) {
		return errors.New("invalid container name")
	}
	if spec.Privileged && !s.allowSensitiveMount {
		return errors.New("privileged containers are disabled by security policy")
	}
	if spec.Network != "" && !validIDRe.MatchString(spec.Network) {
		return errors.New("invalid network identifier")
	}
	for _, b := range spec.Binds {
		parts := strings.Split(b, ":")
		if len(parts) < 2 {
			return fmt.Errorf("invalid bind mount %q", b)
		}
		hostPath := filepath.Clean(parts[0])
		if !s.allowSensitiveMount && strings.HasPrefix(hostPath, "/") {
			blocked := []string{"/", "/etc", "/root", "/proc", "/sys", "/dev", "/var/run/docker.sock", "/run/docker.sock"}
			for _, bad := range blocked {
				if hostPath == bad || (bad != "/" && strings.HasPrefix(hostPath, bad+"/")) {
					return fmt.Errorf("host path %q is blocked by mount security policy", hostPath)
				}
			}
		}
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/auth/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.authLimiter.Allow(r.RemoteAddr) {
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if !validUserRe.MatchString(req.Username) || len(req.Password) < 8 {
			writeErr(w, http.StatusBadRequest, "username must be 3-32 chars and password >= 8 chars")
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "hashing failure")
			return
		}
		u, err := s.store.CreateUser(req.Username, hash)
		if err != nil {
			writeErr(w, http.StatusConflict, "username already exists")
			return
		}
		tok, _ := auth.SignJWT(auth.Claims{Sub: u.ID, Username: u.Username, Role: u.Role}, s.jwtSecret)
		s.store.RecordAudit(u.Username, u.Role, "user.register", u.Username, "ok", "Registered user with role "+u.Role)
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "user": u})
	})

	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.authLimiter.Allow(r.RemoteAddr) {
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		u, err := s.store.GetUserByUsername(strings.TrimSpace(req.Username))
		if err != nil || !auth.VerifyPassword(req.Password, u.PasswordHash) {
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		tok, _ := auth.SignJWT(auth.Claims{Sub: u.ID, Username: u.Username, Role: u.Role}, s.jwtSecret)
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "user": u})
	})

	mux.HandleFunc("/api/users", s.requireRole("admin", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		users, err := s.store.ListUsers()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	}))

	mux.HandleFunc("/api/users/", s.requireRole("admin", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method != http.MethodPatch || !strings.HasSuffix(r.URL.Path, "/role") {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		uid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/role")
		var req struct {
			Role string `json:"role"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.Role != "viewer" && req.Role != "operator" && req.Role != "admin" {
			writeErr(w, http.StatusBadRequest, "role must be viewer, operator, or admin")
			return
		}
		if err := s.store.UpdateUserRole(uid, req.Role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeErr(w, http.StatusNotFound, "user not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.store.RecordAudit(claims.Username, claims.Role, "user.role", uid, "ok", "Updated role to "+req.Role)
		writeJSON(w, http.StatusOK, map[string]string{"id": uid, "role": req.Role})
	}))

	mux.HandleFunc("/api/system/info", s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
		info, err := s.docker.SystemInfo(r.Context())
		if err != nil {
			writeDockerErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	}))

	mux.HandleFunc("/api/audit", s.requireRole("viewer", func(w http.ResponseWriter, _ *http.Request, _ auth.Claims) {
		logs, err := s.store.ListAudit(100)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"audit": logs})
	}))

	mux.HandleFunc("/api/containers", s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method == http.MethodGet {
			all := r.URL.Query().Get("all") != "0"
			list, err := s.docker.ListContainers(r.Context(), all)
			if err != nil {
				writeDockerErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"containers": list})
			return
		}
		if r.Method == http.MethodPost {
			if claims.Role != "admin" {
				writeErr(w, http.StatusForbidden, "admin role required to create containers")
				return
			}
			var spec docker.CreateContainerSpec
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&spec); err != nil {
				writeErr(w, http.StatusBadRequest, "invalid container spec")
				return
			}
			if err := s.validateCreateSpec(&spec); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			id, err := s.docker.CreateContainer(r.Context(), spec)
			if err != nil {
				s.store.RecordAudit(claims.Username, claims.Role, "container.create", spec.Image, "error", err.Error())
				writeDockerErr(w, err)
				return
			}
			s.store.RecordAudit(claims.Username, claims.Role, "container.create", id, "ok", "Image: "+spec.Image)
			writeJSON(w, http.StatusCreated, map[string]string{"id": id})
			return
		}
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}))

	mux.HandleFunc("/api/containers/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/containers/")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) == 0 || !validIDRe.MatchString(parts[0]) {
			writeErr(w, http.StatusBadRequest, "invalid container id")
			return
		}
		cid := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}

		if len(parts) == 1 && r.Method == http.MethodGet {
			s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
				info, err := s.docker.InspectContainer(r.Context(), cid)
				if err != nil {
					writeDockerErr(w, err)
					return
				}
				writeJSON(w, http.StatusOK, info)
			})(w, r)
			return
		}

		if len(parts) == 1 && r.Method == http.MethodDelete {
			s.requireRole("admin", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
				force := r.URL.Query().Get("force") == "true" || r.URL.Query().Get("force") == "1"
				if err := s.docker.RemoveContainer(r.Context(), cid, force); err != nil {
					s.store.RecordAudit(claims.Username, claims.Role, "container.remove", cid, "error", err.Error())
					writeDockerErr(w, err)
					return
				}
				s.store.RecordAudit(claims.Username, claims.Role, "container.remove", cid, "ok", "force="+strconv.FormatBool(force))
				writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
			})(w, r)
			return
		}

		switch action {
		case "start", "stop", "restart":
			if r.Method != http.MethodPost {
				writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.requireRole("operator", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
				var err error
				switch action {
				case "start":
					err = s.docker.StartContainer(r.Context(), cid)
				case "stop":
					err = s.docker.StopContainer(r.Context(), cid)
				case "restart":
					err = s.docker.RestartContainer(r.Context(), cid)
				}
				if err != nil {
					s.store.RecordAudit(claims.Username, claims.Role, "container."+action, cid, "error", err.Error())
					writeDockerErr(w, err)
					return
				}
				s.store.RecordAudit(claims.Username, claims.Role, "container."+action, cid, "ok", "")
				writeJSON(w, http.StatusOK, map[string]string{"status": action + "ed"})
			})(w, r)
		case "stats":
			s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
				m, err := s.docker.ContainerStats(r.Context(), cid)
				if err != nil {
					writeDockerErr(w, err)
					return
				}
				_ = s.store.RecordMetricSample(m)
				hist, _ := s.store.ListMetricHistory(cid)
				writeJSON(w, http.StatusOK, map[string]any{"current": m, "history": hist})
			})(w, r)
		case "logs":
			s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
				tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
				if r.URL.Query().Get("stream") == "1" {
					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Cache-Control", "no-cache")
					flusher, ok := w.(http.Flusher)
					if !ok {
						writeErr(w, http.StatusInternalServerError, "streaming unsupported")
						return
					}
					logs, err := s.docker.ContainerLogs(r.Context(), cid, tail)
					if err != nil {
						fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
						flusher.Flush()
						return
					}
					for _, ln := range strings.Split(strings.TrimRight(logs, "\n"), "\n") {
						b, _ := json.Marshal(ln)
						fmt.Fprintf(w, "data: %s\n\n", b)
					}
					flusher.Flush()
					return
				}
				logs, err := s.docker.ContainerLogs(r.Context(), cid, tail)
				if err != nil {
					writeDockerErr(w, err)
					return
				}
				writeJSON(w, http.StatusOK, map[string]string{"logs": logs})
			})(w, r)
		default:
			writeErr(w, http.StatusNotFound, "unknown container endpoint")
		}
	})

	mux.HandleFunc("/api/images", s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
		imgs, err := s.docker.ListImages(r.Context())
		if err != nil {
			writeDockerErr(w, err)
			return
		}
		var totalBytes int64
		var dangling int
		for _, img := range imgs {
			totalBytes += img.Size
			if len(img.RepoTags) == 0 || (len(img.RepoTags) == 1 && img.RepoTags[0] == "<none>:<none>") {
				dangling++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"images":      imgs,
			"total_bytes": totalBytes,
			"dangling":    dangling,
		})
	}))

	mux.HandleFunc("/api/images/pull", s.requireRole("operator", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Image string `json:"image"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || !validImageRe.MatchString(req.Image) {
			writeErr(w, http.StatusBadRequest, "valid image reference required")
			return
		}
		status, err := s.docker.PullImage(r.Context(), req.Image)
		if err != nil {
			s.store.RecordAudit(claims.Username, claims.Role, "image.pull", req.Image, "error", err.Error())
			writeDockerErr(w, err)
			return
		}
		s.store.RecordAudit(claims.Username, claims.Role, "image.pull", req.Image, "ok", status)
		writeJSON(w, http.StatusOK, map[string]string{"status": "pulled", "detail": status})
	}))

	mux.HandleFunc("/api/images/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/images/")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) == 0 || !validIDRe.MatchString(strings.ReplaceAll(parts[0], ":", "")) {
			writeErr(w, http.StatusBadRequest, "invalid image id")
			return
		}
		imgID := parts[0]
		if len(parts) == 2 && parts[1] == "tag" && r.Method == http.MethodPost {
			s.requireRole("operator", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
				var req struct {
					Repo string `json:"repo"`
					Tag  string `json:"tag"`
				}
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || !validImageRe.MatchString(req.Repo) || !validNameRe.MatchString(req.Tag) {
					writeErr(w, http.StatusBadRequest, "valid repo and tag required")
					return
				}
				if err := s.docker.TagImage(r.Context(), imgID, req.Repo, req.Tag); err != nil {
					writeDockerErr(w, err)
					return
				}
				s.store.RecordAudit(claims.Username, claims.Role, "image.tag", imgID, "ok", req.Repo+":"+req.Tag)
				writeJSON(w, http.StatusOK, map[string]string{"status": "tagged"})
			})(w, r)
			return
		}
		if len(parts) == 1 && r.Method == http.MethodDelete {
			s.requireRole("admin", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
				force := r.URL.Query().Get("force") == "true" || r.URL.Query().Get("force") == "1"
				if err := s.docker.RemoveImage(r.Context(), imgID, force); err != nil {
					writeDockerErr(w, err)
					return
				}
				s.store.RecordAudit(claims.Username, claims.Role, "image.remove", imgID, "ok", "")
				writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
			})(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "unknown image endpoint")
	})

	mux.HandleFunc("/api/networks", s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method == http.MethodGet {
			nets, err := s.docker.ListNetworks(r.Context())
			if err != nil {
				writeDockerErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"networks": nets})
			return
		}
		if r.Method == http.MethodPost {
			if claims.Role != "admin" {
				writeErr(w, http.StatusForbidden, "admin role required")
				return
			}
			var req struct {
				Name     string `json:"name"`
				Driver   string `json:"driver"`
				Internal bool   `json:"internal"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || !validNameRe.MatchString(req.Name) {
				writeErr(w, http.StatusBadRequest, "valid network name required")
				return
			}
			id, err := s.docker.CreateNetwork(r.Context(), req.Name, req.Driver, req.Internal)
			if err != nil {
				writeDockerErr(w, err)
				return
			}
			s.store.RecordAudit(claims.Username, claims.Role, "network.create", req.Name, "ok", id)
			writeJSON(w, http.StatusCreated, map[string]string{"id": id})
			return
		}
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}))

	mux.HandleFunc("/api/networks/", s.requireRole("admin", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method != http.MethodDelete {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		nid := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/networks/"), "/")
		if !validIDRe.MatchString(nid) {
			writeErr(w, http.StatusBadRequest, "invalid network id")
			return
		}
		if err := s.docker.RemoveNetwork(r.Context(), nid); err != nil {
			writeDockerErr(w, err)
			return
		}
		s.store.RecordAudit(claims.Username, claims.Role, "network.remove", nid, "ok", "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	}))

	mux.HandleFunc("/api/volumes", s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method == http.MethodGet {
			vols, err := s.docker.ListVolumes(r.Context())
			if err != nil {
				writeDockerErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"volumes": vols})
			return
		}
		if r.Method == http.MethodPost {
			if claims.Role != "admin" {
				writeErr(w, http.StatusForbidden, "admin role required")
				return
			}
			var req struct {
				Name   string `json:"name"`
				Driver string `json:"driver"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || !validNameRe.MatchString(req.Name) {
				writeErr(w, http.StatusBadRequest, "valid volume name required")
				return
			}
			vol, err := s.docker.CreateVolume(r.Context(), req.Name, req.Driver)
			if err != nil {
				writeDockerErr(w, err)
				return
			}
			s.store.RecordAudit(claims.Username, claims.Role, "volume.create", req.Name, "ok", vol.Driver)
			writeJSON(w, http.StatusCreated, vol)
			return
		}
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}))

	mux.HandleFunc("/api/volumes/", s.requireRole("admin", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method != http.MethodDelete {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		vname := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/volumes/"), "/")
		if !validNameRe.MatchString(vname) {
			writeErr(w, http.StatusBadRequest, "invalid volume name")
			return
		}
		force := r.URL.Query().Get("force") == "true"
		if err := s.docker.RemoveVolume(r.Context(), vname, force); err != nil {
			writeDockerErr(w, err)
			return
		}
		s.store.RecordAudit(claims.Username, claims.Role, "volume.remove", vname, "ok", "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	}))

	mux.HandleFunc("/api/stacks", s.requireRole("viewer", func(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
		containers, err := s.docker.ListContainers(r.Context(), true)
		if err != nil {
			writeDockerErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stacks": docker.GroupComposeStacks(containers)})
	}))

	mux.HandleFunc("/api/stacks/", s.requireRole("operator", func(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/stacks/")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) != 2 || !validNameRe.MatchString(parts[0]) {
			writeErr(w, http.StatusBadRequest, "expected /api/stacks/{project}/{start|stop|restart}")
			return
		}
		proj, action := parts[0], parts[1]
		if action != "start" && action != "stop" && action != "restart" {
			writeErr(w, http.StatusBadRequest, "invalid stack action")
			return
		}
		containers, err := s.docker.ListContainers(r.Context(), true)
		if err != nil {
			writeDockerErr(w, err)
			return
		}
		affected := 0
		for _, c := range containers {
			if c.Labels["com.docker.compose.project"] != proj {
				continue
			}
			var opErr error
			switch action {
			case "start":
				opErr = s.docker.StartContainer(r.Context(), c.ID)
			case "stop":
				opErr = s.docker.StopContainer(r.Context(), c.ID)
			case "restart":
				opErr = s.docker.RestartContainer(r.Context(), c.ID)
			}
			if opErr != nil {
				writeDockerErr(w, opErr)
				return
			}
			affected++
		}
		s.store.RecordAudit(claims.Username, claims.Role, "stack."+action, proj, "ok", fmt.Sprintf("affected=%d", affected))
		writeJSON(w, http.StatusOK, map[string]any{"project": proj, "action": action, "affected": affected})
	}))

	return withSecurityHeaders(mux)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeDockerErr(w http.ResponseWriter, err error) {
	var apiErr *docker.APIError
	if errors.As(err, &apiErr) {
		writeErr(w, apiErr.StatusCode, apiErr.Message)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "docker daemon timeout")
		return
	}
	writeErr(w, http.StatusBadGateway, "docker engine unreachable: "+err.Error())
}
