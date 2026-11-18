package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fully-ai/dockyard/internal/docker"
	"github.com/fully-ai/dockyard/internal/store"
)

type fakeEngineState struct {
	mu         sync.Mutex
	containers map[string]docker.ContainerSummary
	images     []docker.ImageSummary
	networks   map[string]docker.NetworkSummary
	volumes    map[string]docker.VolumeSummary
	actions    []string
}

func newFakeDockerEngine(t *testing.T) (*httptest.Server, *fakeEngineState) {
	t.Helper()
	st := &fakeEngineState{
		containers: map[string]docker.ContainerSummary{
			"c1": {
				ID: "c1", Names: []string{"/web-1"}, Image: "nginx:1.27", State: "running",
				Status: "Up 2 minutes (healthy)",
				Labels: map[string]string{"com.docker.compose.project": "webapp", "com.docker.compose.project.working_dir": "/srv/webapp"},
			},
			"c2": {
				ID: "c2", Names: []string{"/worker-1"}, Image: "redis:7", State: "running",
				Status: "Up 2 minutes",
				Labels: map[string]string{"com.docker.compose.project": "webapp", "com.docker.compose.project.working_dir": "/srv/webapp"},
			},
		},
		images: []docker.ImageSummary{
			{ID: "sha256:aaa111", RepoTags: []string{"nginx:1.27"}, Size: 64 << 20},
		},
		networks: map[string]docker.NetworkSummary{
			"net1": {ID: "net1", Name: "bridge", Driver: "bridge", Scope: "local"},
		},
		volumes: map[string]docker.VolumeSummary{
			"pgdata": {Name: "pgdata", Driver: "local", Mountpoint: "/var/lib/docker/volumes/pgdata/_data"},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.SystemInfo{
			ServerVersion: "27.3.1", NCPU: 8, MemTotal: 16 << 30, Containers: len(st.containers), ContainersRunning: len(st.containers), Images: len(st.images),
		})
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		out := make([]docker.ContainerSummary, 0, len(st.containers))
		for _, c := range st.containers {
			out = append(out, c)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Image string `json:"Image"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "c3"
		}
		st.mu.Lock()
		st.containers["c3"] = docker.ContainerSummary{ID: "c3", Names: []string{"/" + name}, Image: body.Image, State: "created", Status: "Created"}
		st.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c3"})
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/containers/")
		parts := strings.Split(rest, "/")
		id := parts[0]
		st.mu.Lock()
		defer st.mu.Unlock()
		if len(parts) == 2 && parts[1] == "stats" {
			var raw docker.ContainerStatsRaw
			raw.PreCPUStats.CPUUsage.TotalUsage = 100
			raw.PreCPUStats.SystemCPUUsage = 1000
			raw.CPUStats.CPUUsage.TotalUsage = 200
			raw.CPUStats.SystemCPUUsage = 2000
			raw.CPUStats.OnlineCPUs = 2
			raw.MemoryStats.Usage = 128 << 20
			raw.MemoryStats.Limit = 512 << 20
			_ = json.NewEncoder(w).Encode(raw)
			return
		}
		if len(parts) == 2 && parts[1] == "logs" {
			msg := []byte("2026-11-18T10:00:00Z server started\n")
			hdr := []byte{1, 0, 0, 0, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(hdr[4:8], uint32(len(msg)))
			_, _ = w.Write(append(hdr, msg...))
			return
		}
		if len(parts) == 2 && (parts[1] == "start" || parts[1] == "stop" || parts[1] == "restart") {
			c := st.containers[id]
			if parts[1] == "stop" {
				c.State = "exited"
			} else {
				c.State = "running"
			}
			st.containers[id] = c
			st.actions = append(st.actions, id+":"+parts[1])
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if len(parts) == 1 && r.Method == http.MethodDelete {
			delete(st.containers, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(docker.ContainerInspect{ID: id, Name: "/web-1"})
	})
	mux.HandleFunc("/images/json", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(st.images)
	})
	mux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		img := r.URL.Query().Get("fromImage")
		st.mu.Lock()
		st.images = append(st.images, docker.ImageSummary{ID: "sha256:bbb222", RepoTags: []string{img}, Size: 12 << 20})
		st.mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"Pull complete"}` + "\n"))
	})
	mux.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tag") {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/networks", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		var out []docker.NetworkSummary
		for _, n := range st.networks {
			out = append(out, n)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/networks/create", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name, Driver string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		st.mu.Lock()
		st.networks["net2"] = docker.NetworkSummary{ID: "net2", Name: req.Name, Driver: req.Driver, Scope: "local"}
		st.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "net2"})
	})
	mux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/networks/")
		st.mu.Lock()
		delete(st.networks, id)
		st.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/volumes", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		var out []docker.VolumeSummary
		for _, v := range st.volumes {
			out = append(out, v)
		}
		_ = json.NewEncoder(w).Encode(docker.VolumeListResponse{Volumes: out})
	})
	mux.HandleFunc("/volumes/create", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name, Driver string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		v := docker.VolumeSummary{Name: req.Name, Driver: req.Driver}
		st.mu.Lock()
		st.volumes[req.Name] = v
		st.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("/volumes/", func(w http.ResponseWriter, r *http.Request) {
		nm := strings.TrimPrefix(r.URL.Path, "/volumes/")
		st.mu.Lock()
		delete(st.volumes, nm)
		st.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	return httptest.NewServer(mux), st
}

func doReq(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestDockyardContainersImagesNetworksVolumesStacksRBACAndAudit(t *testing.T) {
	engSrv, engState := newFakeDockerEngine(t)
	defer engSrv.Close()

	dc, err := docker.NewClient(engSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := NewServer(dc, st, "dockyard-test-jwt-secret", false)
	h := srv.Handler()

	// Unauthenticated access rejected
	if w := doReq(t, h, http.MethodGet, "/api/containers", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// Register admin (first user) and viewer (second user)
	wAdmin := doReq(t, h, http.MethodPost, "/api/auth/register", "", map[string]string{"username": "admin1", "password": "strongpassword1"})
	if wAdmin.Code != http.StatusCreated {
		t.Fatalf("register admin failed: %d %s", wAdmin.Code, wAdmin.Body.String())
	}
	var adminAuth struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(wAdmin.Body.Bytes(), &adminAuth)

	wViewer := doReq(t, h, http.MethodPost, "/api/auth/register", "", map[string]string{"username": "viewer1", "password": "strongpassword2"})
	var viewerAuth struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(wViewer.Body.Bytes(), &viewerAuth)

	// Viewer cannot restart containers or create networks
	if w := doReq(t, h, http.MethodPost, "/api/containers/c1/restart", viewerAuth.Token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer restart, got %d", w.Code)
	}

	// Sensitive mount guard blocks /var/run/docker.sock bind mount
	badSpec := docker.CreateContainerSpec{
		Name: "evil", Image: "alpine:3.20", Binds: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	}
	if w := doReq(t, h, http.MethodPost, "/api/containers", adminAuth.Token, badSpec); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 blocking docker.sock mount, got %d", w.Code)
	}

	// Safe container create + auto_start
	goodSpec := docker.CreateContainerSpec{
		Name: "api-svc", Image: "alpine:3.20", Ports: map[string]string{"8080": "80"}, AutoStart: true,
	}
	if w := doReq(t, h, http.MethodPost, "/api/containers", adminAuth.Token, goodSpec); w.Code != http.StatusCreated {
		t.Fatalf("create container failed: %d %s", w.Code, w.Body.String())
	}

	// Container stats compute CPU/RAM & persist in SQLite history
	wStats := doReq(t, h, http.MethodGet, "/api/containers/c1/stats", viewerAuth.Token, nil)
	if wStats.Code != http.StatusOK || !strings.Contains(wStats.Body.String(), `"mem_percent":25`) {
		t.Fatalf("unexpected stats response: %d %s", wStats.Code, wStats.Body.String())
	}

	// Container logs decode 8-byte Docker stream header cleanly
	wLogs := doReq(t, h, http.MethodGet, "/api/containers/c1/logs?tail=50", viewerAuth.Token, nil)
	if wLogs.Code != http.StatusOK || !strings.Contains(wLogs.Body.String(), "server started") {
		t.Fatalf("unexpected logs response: %d %s", wLogs.Code, wLogs.Body.String())
	}

	// Compose stacks grouping + bulk restart
	wStacks := doReq(t, h, http.MethodGet, "/api/stacks", viewerAuth.Token, nil)
	if wStacks.Code != http.StatusOK || !strings.Contains(wStacks.Body.String(), `"project":"webapp"`) {
		t.Fatalf("expected webapp compose stack, got %s", wStacks.Body.String())
	}
	if w := doReq(t, h, http.MethodPost, "/api/stacks/webapp/restart", adminAuth.Token, nil); w.Code != http.StatusOK {
		t.Fatalf("stack restart failed: %d %s", w.Code, w.Body.String())
	}
	if len(engState.actions) < 3 {
		t.Fatalf("expected stack restart to trigger container actions, got %v", engState.actions)
	}

	// Images pull, tag, delete
	if w := doReq(t, h, http.MethodPost, "/api/images/pull", adminAuth.Token, map[string]string{"image": "busybox:latest"}); w.Code != http.StatusOK {
		t.Fatalf("image pull failed: %d", w.Code)
	}
	if w := doReq(t, h, http.MethodPost, "/api/images/sha256:aaa111/tag", adminAuth.Token, map[string]string{"repo": "myorg/web", "tag": "v1"}); w.Code != http.StatusOK {
		t.Fatalf("image tag failed: %d", w.Code)
	}

	// Network create/delete & Volume create/delete
	if w := doReq(t, h, http.MethodPost, "/api/networks", adminAuth.Token, map[string]any{"name": "app-net", "driver": "bridge", "internal": true}); w.Code != http.StatusCreated {
		t.Fatalf("network create failed: %d", w.Code)
	}
	if w := doReq(t, h, http.MethodPost, "/api/volumes", adminAuth.Token, map[string]string{"name": "cache-vol"}); w.Code != http.StatusCreated {
		t.Fatalf("volume create failed: %d", w.Code)
	}

	// Audit log contains recorded mutations
	wAudit := doReq(t, h, http.MethodGet, "/api/audit", viewerAuth.Token, nil)
	if wAudit.Code != http.StatusOK || !strings.Contains(wAudit.Body.String(), "stack.restart") {
		t.Fatalf("expected audit log entries, got %s", wAudit.Body.String())
	}
}
