package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client speaks Docker Engine HTTP API over unix:// or http(s):// / tcp://.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Docker Engine API client from a host URI such as
// unix:///var/run/docker.sock or tcp://127.0.0.1:2375.
func NewClient(dockerHost string) (*Client, error) {
	host := strings.TrimSpace(dockerHost)
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}

	if strings.HasPrefix(host, "unix://") {
		sockPath := strings.TrimPrefix(host, "unix://")
		if sockPath == "" {
			sockPath = "/var/run/docker.sock"
		}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sockPath)
			},
		}
		return &Client{
			baseURL:    "http://docker",
			httpClient: &http.Client{Transport: tr, Timeout: 60 * time.Second},
		}, nil
	}

	normalized := host
	if strings.HasPrefix(host, "tcp://") {
		normalized = "http://" + strings.TrimPrefix(host, "tcp://")
	}
	u, err := url.Parse(normalized)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid DOCKER_HOST URI: %q", dockerHost)
	}
	return &Client{
		baseURL:    strings.TrimRight(u.String(), "/"),
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

type PortBinding struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Command string            `json:"Command"`
	Created int64             `json:"Created"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Ports   []PortBinding     `json:"Ports"`
}

type ContainerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health,omitempty"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Env    []string          `json:"Env"`
		Cmd    []string          `json:"Cmd"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string   `json:"NetworkMode"`
		Binds       []string `json:"Binds"`
		Privileged  bool     `json:"Privileged"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
			Gateway   string `json:"Gateway"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type ContainerStatsRaw struct {
	Read     string `json:"read"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
}

type ContainerMetrics struct {
	ContainerID string  `json:"container_id"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemUsedMB   float64 `json:"mem_used_mb"`
	MemLimitMB  float64 `json:"mem_limit_mb"`
	MemPercent  float64 `json:"mem_percent"`
	NetRxBytes  uint64  `json:"net_rx_bytes"`
	NetTxBytes  uint64  `json:"net_tx_bytes"`
	RecordedAt  string  `json:"recorded_at"`
}

type ImageSummary struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	Created     int64    `json:"Created"`
	Size        int64    `json:"Size"`
	VirtualSize int64    `json:"VirtualSize"`
	Containers  int64    `json:"Containers"`
}

type NetworkSummary struct {
	ID         string                 `json:"Id"`
	Name       string                 `json:"Name"`
	Driver     string                 `json:"Driver"`
	Scope      string                 `json:"Scope"`
	Internal   bool                   `json:"Internal"`
	Containers map[string]interface{} `json:"Containers"`
}

type VolumeSummary struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Scope      string            `json:"Scope"`
	Labels     map[string]string `json:"Labels"`
	UsageData  *struct {
		Size     int64 `json:"Size"`
		RefCount int64 `json:"RefCount"`
	} `json:"UsageData,omitempty"`
}

type VolumeListResponse struct {
	Volumes  []VolumeSummary `json:"Volumes"`
	Warnings []string        `json:"Warnings"`
}

type SystemInfo struct {
	ID                string `json:"ID"`
	Name              string `json:"Name"`
	ServerVersion     string `json:"ServerVersion"`
	OperatingSystem   string `json:"OperatingSystem"`
	Architecture      string `json:"Architecture"`
	NCPU              int    `json:"NCPU"`
	MemTotal          int64  `json:"MemTotal"`
	Containers        int    `json:"Containers"`
	ContainersRunning int    `json:"ContainersRunning"`
	ContainersPaused  int    `json:"ContainersPaused"`
	ContainersStopped int    `json:"ContainersStopped"`
	Images            int    `json:"Images"`
}

type CreateContainerSpec struct {
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Cmd        []string          `json:"cmd,omitempty"`
	Env        []string          `json:"env,omitempty"`
	Ports      map[string]string `json:"ports,omitempty"` // hostPort -> containerPort/proto
	Binds      []string          `json:"binds,omitempty"`
	Network    string            `json:"network,omitempty"`
	AutoStart  bool              `json:"auto_start"`
	Restart    string            `json:"restart,omitempty"`
	Privileged bool              `json:"privileged,omitempty"`
}

type ComposeStack struct {
	Project     string             `json:"project"`
	WorkingDir  string             `json:"working_dir"`
	Total       int                `json:"total"`
	Running     int                `json:"running"`
	Healthy     int                `json:"healthy"`
	Containers  []ContainerSummary `json:"containers"`
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("docker engine error (%d): %s", e.StatusCode, e.Message)
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, out any) error {
	var body io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var msgObj struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &msgObj) == nil && msgObj.Message != "" {
			msg = msgObj.Message
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) SystemInfo(ctx context.Context) (SystemInfo, error) {
	var info SystemInfo
	err := c.doJSON(ctx, http.MethodGet, "/info", nil, &info)
	return info, err
}

func (c *Client) ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	q := "0"
	if all {
		q = "1"
	}
	var out []ContainerSummary
	err := c.doJSON(ctx, http.MethodGet, "/containers/json?all="+q, nil, &out)
	return out, err
}

func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerInspect, error) {
	var out ContainerInspect
	err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, &out)
	return out, err
}

func (c *Client) CreateContainer(ctx context.Context, spec CreateContainerSpec) (string, error) {
	exposed := map[string]struct{}{}
	portBindings := map[string][]map[string]string{}
	for hostPort, containerSpec := range spec.Ports {
		key := containerSpec
		if !strings.Contains(key, "/") {
			key += "/tcp"
		}
		exposed[key] = struct{}{}
		portBindings[key] = []map[string]string{{"HostIp": "127.0.0.1", "HostPort": hostPort}}
	}
	hostCfg := map[string]any{
		"Binds":        spec.Binds,
		"PortBindings": portBindings,
		"Privileged":   spec.Privileged,
	}
	if spec.Network != "" {
		hostCfg["NetworkMode"] = spec.Network
	}
	if spec.Restart != "" {
		hostCfg["RestartPolicy"] = map[string]any{"Name": spec.Restart}
	}
	payload := map[string]any{
		"Image":        spec.Image,
		"Cmd":          spec.Cmd,
		"Env":          spec.Env,
		"ExposedPorts": exposed,
		"HostConfig":   hostCfg,
	}
	endpoint := "/containers/create"
	if spec.Name != "" {
		endpoint += "?name=" + url.QueryEscape(spec.Name)
	}
	var res struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, endpoint, payload, &res); err != nil {
		return "", err
	}
	if spec.AutoStart {
		if err := c.StartContainer(ctx, res.ID); err != nil {
			return res.ID, err
		}
	}
	return res.ID, nil
}

func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil)
}

func (c *Client) StopContainer(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop?t=10", nil, nil)
}

func (c *Client) RestartContainer(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/restart?t=10", nil, nil)
}

func (c *Client) RemoveContainer(ctx context.Context, id string, force bool) error {
	f := "0"
	if force {
		f = "1"
	}
	return c.doJSON(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id)+"?force="+f, nil, nil)
}

func (c *Client) ContainerStats(ctx context.Context, id string) (ContainerMetrics, error) {
	var raw ContainerStatsRaw
	if err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/stats?stream=false", nil, &raw); err != nil {
		return ContainerMetrics{}, err
	}
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
	online := raw.CPUStats.OnlineCPUs
	if online <= 0 {
		online = 1
	}
	cpuPct := 0.0
	if sysDelta > 0 && cpuDelta > 0 {
		cpuPct = (cpuDelta / sysDelta) * float64(online) * 100.0
	}
	memPct := 0.0
	if raw.MemoryStats.Limit > 0 {
		memPct = (float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit)) * 100.0
	}
	var rx, tx uint64
	for _, nw := range raw.Networks {
		rx += nw.RxBytes
		tx += nw.TxBytes
	}
	return ContainerMetrics{
		ContainerID: id,
		CPUPercent:  cpuPct,
		MemUsedMB:   float64(raw.MemoryStats.Usage) / (1024 * 1024),
		MemLimitMB:  float64(raw.MemoryStats.Limit) / (1024 * 1024),
		MemPercent:  memPct,
		NetRxBytes:  rx,
		NetTxBytes:  tx,
		RecordedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ContainerLogs fetches container stdout/stderr and strips Docker's 8-byte multiplex framing when present.
func (c *Client) ContainerLogs(ctx context.Context, id string, tail int) (string, error) {
	if tail <= 0 || tail > 2000 {
		tail = 200
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/containers/%s/logs?stdout=1&stderr=1&timestamps=1&tail=%d", c.baseURL, url.PathEscape(id), tail),
		nil,
	)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", &APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}
	return DecodeDockerStream(raw), nil
}

// DecodeDockerStream strips Docker multiplexed 8-byte frame headers ([stream,0,0,0,size32]) if present.
func DecodeDockerStream(raw []byte) string {
	if len(raw) < 8 || (raw[0] != 1 && raw[0] != 2 && raw[0] != 0) || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return string(raw)
	}
	var out strings.Builder
	r := bytes.NewReader(raw)
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			break
		}
		sz := binary.BigEndian.Uint32(hdr[4:8])
		if sz == 0 || int64(sz) > int64(r.Len()) {
			rest, _ := io.ReadAll(r)
			out.Write(rest)
			break
		}
		frame := make([]byte, sz)
		if _, err := io.ReadFull(r, frame); err != nil {
			break
		}
		out.Write(frame)
	}
	return out.String()
}

func (c *Client) ListImages(ctx context.Context) ([]ImageSummary, error) {
	var out []ImageSummary
	err := c.doJSON(ctx, http.MethodGet, "/images/json?all=0", nil, &out)
	return out, err
}

func (c *Client) PullImage(ctx context.Context, imageRef string) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/images/create?fromImage="+url.QueryEscape(imageRef),
		nil,
	)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 2<<20))
	var lastLine string
	for sc.Scan() {
		lastLine = sc.Text()
	}
	if resp.StatusCode >= 400 {
		return "", &APIError{StatusCode: resp.StatusCode, Message: lastLine}
	}
	return lastLine, nil
}

func (c *Client) TagImage(ctx context.Context, id, repo, tag string) error {
	endpoint := fmt.Sprintf("/images/%s/tag?repo=%s&tag=%s", url.PathEscape(id), url.QueryEscape(repo), url.QueryEscape(tag))
	return c.doJSON(ctx, http.MethodPost, endpoint, nil, nil)
}

func (c *Client) RemoveImage(ctx context.Context, id string, force bool) error {
	f := "0"
	if force {
		f = "1"
	}
	return c.doJSON(ctx, http.MethodDelete, "/images/"+url.PathEscape(id)+"?force="+f, nil, nil)
}

func (c *Client) ListNetworks(ctx context.Context) ([]NetworkSummary, error) {
	var out []NetworkSummary
	err := c.doJSON(ctx, http.MethodGet, "/networks", nil, &out)
	return out, err
}

func (c *Client) CreateNetwork(ctx context.Context, name, driver string, internal bool) (string, error) {
	if driver == "" {
		driver = "bridge"
	}
	var res struct {
		ID string `json:"Id"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/networks/create", map[string]any{
		"Name":     name,
		"Driver":   driver,
		"Internal": internal,
	}, &res)
	return res.ID, err
}

func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(id), nil, nil)
}

func (c *Client) ListVolumes(ctx context.Context) ([]VolumeSummary, error) {
	var res VolumeListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/volumes", nil, &res); err != nil {
		return nil, err
	}
	return res.Volumes, nil
}

func (c *Client) CreateVolume(ctx context.Context, name, driver string) (VolumeSummary, error) {
	if driver == "" {
		driver = "local"
	}
	var res VolumeSummary
	err := c.doJSON(ctx, http.MethodPost, "/volumes/create", map[string]any{
		"Name":   name,
		"Driver": driver,
	}, &res)
	return res, err
}

func (c *Client) RemoveVolume(ctx context.Context, name string, force bool) error {
	f := "0"
	if force {
		f = "1"
	}
	return c.doJSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name)+"?force="+f, nil, nil)
}

// GroupComposeStacks aggregates containers carrying com.docker.compose.project labels.
func GroupComposeStacks(containers []ContainerSummary) []ComposeStack {
	byProj := map[string]*ComposeStack{}
	for _, c := range containers {
		proj := c.Labels["com.docker.compose.project"]
		if proj == "" {
			continue
		}
		st, ok := byProj[proj]
		if !ok {
			st = &ComposeStack{
				Project:    proj,
				WorkingDir: c.Labels["com.docker.compose.project.working_dir"],
			}
			byProj[proj] = st
		}
		st.Total++
		if strings.EqualFold(c.State, "running") {
			st.Running++
		}
		if strings.Contains(strings.ToLower(c.Status), "(healthy)") {
			st.Healthy++
		}
		st.Containers = append(st.Containers, c)
	}
	out := make([]ComposeStack, 0, len(byProj))
	for _, st := range byProj {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out
}
