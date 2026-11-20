package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	fanoutTagPrefix   = "fanout-"
	fanoutUserRemark  = "fanout:managed"
	listenerTagPrefix = "listener-"
)

// Inbound 是 fanout 展示和绑定使用的一个 3m-ui Listener。
type Inbound struct {
	ID       int    `json:"id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Remark   string `json:"remark"`
	Enable   bool   `json:"enable"`
	Tag      string `json:"tag"`
	BoundTo  string `json:"bound_to"`
	BoundUp  bool   `json:"bound_up"`
}

// InboundDetail 是 Listener、代理用户和分享链接的完整详情。
type InboundDetail struct {
	Inbound
	Clients []ClientInfo `json:"clients"`
	Links   []string     `json:"links"`
	Listen  string       `json:"listen"`
	Network string       `json:"network"`
	TLS     string       `json:"tls"`
}

type ClientInfo struct {
	Email  string `json:"email"`
	ID     string `json:"id"`
	Enable bool   `json:"enable"`
}

// NewInboundSpec 只保留 3m-ui QuickCreate 所需的参数，端口与协议配置由面板生成。
type NewInboundSpec struct {
	Protocol string
	Remark   string
}

// 出站名格式：国旗 国家-fanout-端口，靠 fanout 分配的 SOCKS5 端口保证唯一；
// 识别靠尾部 fanout-<数字>，避免与用户自建出站（可能国旗开头）冲突。
func tunnelTag(t *Tunnel) string {
	return nodeLabel(t.Node) + "-fanout-" + strconv.Itoa(t.Port)
}

// isFanoutOutbound 判断出站是否由 fanout 管理：新格式尾部 fanout-<数字>，或兼容旧 fanout- 前缀。
func isFanoutOutbound(name string) bool {
	if strings.HasPrefix(name, fanoutTagPrefix) {
		return true
	}
	idx := strings.LastIndex(name, "-fanout-")
	if idx < 0 {
		return false
	}
	suffix := name[idx+len("-fanout-"):]
	if suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// outboundPort 从 fanout 出站名尾部提取 SOCKS5 端口，非 fanout 出站返回 false。
func outboundPort(name string) (int, bool) {
	idx := strings.LastIndex(name, "-fanout-")
	if idx < 0 {
		return 0, false
	}
	port, err := strconv.Atoi(name[idx+len("-fanout-"):])
	if err != nil || port <= 0 {
		return 0, false
	}
	return port, true
}

// remarkHost 从 Listener 备注（exitLabel 格式「🇯🇵 日本 jp-home」）末段取 sanitize 后的 hostname。
func remarkHost(remark string) string {
	fields := strings.Fields(remark)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func listenerTag(id int) string { return fmt.Sprintf("%s%d", listenerTagPrefix, id) }

func sanitizeTag(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// exitLabel 用国家与出口 IP 末段生成易读且通常唯一的 Listener 名称。
func exitLabel(t *Tunnel) string {
	place := nodeLabel(t.Node)
	suffix := t.Node.HostName
	if t.ExitIP != "" {
		if i := strings.LastIndex(t.ExitIP, "."); i >= 0 {
			suffix = t.ExitIP[i+1:]
		} else {
			suffix = t.ExitIP
		}
	}
	if place == "" {
		return suffix
	}
	return place + " " + suffix
}

func renameExitLabel(remark, newLabel string) string {
	if newLabel == "" || !isGeneratedLabel(remark) {
		return remark
	}
	return newLabel
}

// threeMUIConfig 对应工作目录下的 panel.yaml；环境变量优先级更高。
type threeMUIConfig struct {
	URL                string `yaml:"url"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	TOTPCode           string `yaml:"totp_code"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// threeMUIConfigPath 是 3m-ui 自身配置文件的固定路径，用于在用户未显式配置 url 时自动探测。
const threeMUIConfigPath = "/etc/3m-ui/config.yaml"

// probeThreeMUIURL 在用户未显式配置 url 时自动探测 3m-ui 实际地址：
// 优先做 live 探测（真实监听端口 + 连通性测试），失败则回退到从 config 拼接 http 地址。
// 探测失败返回空字符串，交由上层报错提示手动配置。
func probeThreeMUIURL() string {
	if u := probeThreeMUIURLLive(); u != "" {
		return u
	}
	return probeThreeMUIURLFromPath(threeMUIConfigPath)
}

// probeThreeMUIURLLive 检测 3m-ui 实际监听端口并逐个测连通性，策略与 install.sh 对齐：
// 候选端口 = 真实监听端口（/proc/net/tcp + tcp6）+ config 的 server.port；先 https 后 http，
// 取首个 2xx/3xx。https 命中时调用方应同步开启 InsecureSkipVerify。
func probeThreeMUIURLLive() string {
	return probeThreeMUIURLLiveFromConfig(threeMUIConfigPath)
}

// probeThreeMUIURLLiveFromConfig 拆出 config 路径参数，便于单元测试注入临时 config。
func probeThreeMUIURLLiveFromConfig(path string) string {
	webPath, cfgPort := readThreeMUIWebPathAndPort(path)
	ports := appendUniqueInt(listenPortsFn(), cfgPort)
	return probeReachableURL(ports, webPath)
}

// readThreeMUIWebPathAndPort 从 3m-ui config.yaml 读出 web_path（已清理首尾斜杠）与 server.port。
// 解析失败或缺字段时对应返回空串/0，不报错。
func readThreeMUIWebPathAndPort(path string) (webPath string, port int) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", 0
	}
	var raw struct {
		Server struct {
			Port    int    `yaml:"port"`
			WebPath string `yaml:"web_path"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(blob, &raw); err != nil {
		return "", 0
	}
	return strings.Trim(raw.Server.WebPath, "/"), raw.Server.Port
}

// probeThreeMUIURLFromPath 从 config 拼出 http 地址（不做连通性测试），作为 live 探测失败后的回退，
// 也拆出参数便于单元测试 config 解析。
func probeThreeMUIURLFromPath(path string) string {
	webPath, port := readThreeMUIWebPathAndPort(path)
	if port <= 0 {
		return ""
	}
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	if webPath != "" {
		return base + "/" + webPath
	}
	return base
}

// 探测依赖可替换，便于单元测试（默认指向真实实现）。
var (
	listenPortsFn   = listenPorts
	httpProbeStatus = probeHTTPStatus
)

// listenPorts 读取 /proc/net/tcp 与 /proc/net/tcp6 中所有 LISTEN（状态 0A）端口，去重保序。
// 非 Linux 或文件不存在时返回空切片（不报错），此时仅靠 config 的 server.port 兜底。
func listenPorts() []int {
	return listenPortsFromFiles([]string{"/proc/net/tcp", "/proc/net/tcp6"})
}

func listenPortsFromFiles(files []string) []int {
	var ports []int
	seen := make(map[int]bool)
	for _, f := range files {
		blob, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(blob), "\n") {
			fields := strings.Fields(line)
			// /proc/net/tcp 第 2 列是 local_address:port，第 4 列是状态，0A = LISTEN
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			local := fields[1]
			idx := strings.LastIndex(local, ":")
			if idx < 0 {
				continue
			}
			port, err := strconv.ParseInt(local[idx+1:], 16, 32)
			if err != nil || port <= 0 {
				continue
			}
			p := int(port)
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// appendUniqueInt 把补充端口追加到切片（已存在则跳过），保持原顺序。
func appendUniqueInt(ports []int, extra int) []int {
	if extra <= 0 {
		return ports
	}
	for _, p := range ports {
		if p == extra {
			return ports
		}
	}
	return append(ports, extra)
}

// probeReachableURL 对候选端口先 https 后 http 逐个测连通性，返回首个 2xx/3xx 的完整 url。
// 两轮而非逐端口交替，避免 http 301 跳 https 抢先命中，确保启用 TLS 时优先选中 https。
func probeReachableURL(ports []int, webPath string) string {
	base := ""
	if webPath != "" {
		base = "/" + webPath
	}
	for _, scheme := range []string{"https", "http"} {
		insecure := scheme == "https"
		for _, p := range ports {
			u := fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, p, base)
			code, err := httpProbeStatus(u, insecure)
			if err == nil && code >= 200 && code < 400 {
				return u
			}
		}
	}
	return ""
}

// probeHTTPStatus 对目标 url 发一次 GET，返回 HTTP 状态码；insecure 为真时跳过 TLS 证书校验
// （用于本地 3m-ui 自签证书探测）。连接失败返回 error。
func probeHTTPStatus(rawURL string, insecure bool) (int, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	if insecure {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- 仅本地探测自签证书
		client.Transport = tr
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func loadThreeMUIConfig(workDir string) (threeMUIConfig, error) {
	var cfg threeMUIConfig
	if workDir != "" {
		blob, err := os.ReadFile(filepath.Join(workDir, "panel.yaml"))
		if err != nil && !os.IsNotExist(err) {
			return cfg, fmt.Errorf("读取 3m-ui 配置失败: %w", err)
		}
		if len(blob) > 0 {
			if err := yaml.Unmarshal(blob, &cfg); err != nil {
				return cfg, fmt.Errorf("解析 panel.yaml 失败: %w", err)
			}
		}
	}
	override := func(dst *string, key string) {
		if value, ok := os.LookupEnv(key); ok {
			*dst = strings.TrimSpace(value)
		}
	}
	override(&cfg.URL, "FANOUT_3M_UI_URL")
	override(&cfg.Username, "FANOUT_3M_UI_USERNAME")
	override(&cfg.Password, "FANOUT_3M_UI_PASSWORD")
	override(&cfg.TOTPCode, "FANOUT_3M_UI_TOTP_CODE")
	if value, ok := os.LookupEnv("FANOUT_3M_UI_INSECURE_SKIP_VERIFY"); ok {
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return cfg, fmt.Errorf("FANOUT_3M_UI_INSECURE_SKIP_VERIFY 必须是布尔值")
		}
		cfg.InsecureSkipVerify = parsed
	}
	// 显式配置（panel.yaml / 环境变量）优先；都没给 url 时自动探测 3m-ui 实际地址。
	// 自动探测到本地 https 时，自签证书需跳过校验，否则后续登录会 TLS 握手失败；
	// 用户显式配置的 url 不强制覆盖其 insecure_skip_verify 设置。
	if cfg.URL == "" {
		cfg.URL = probeThreeMUIURL()
		if strings.HasPrefix(cfg.URL, "https://") {
			cfg.InsecureSkipVerify = true
		}
	}
	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	cfg.Username = strings.TrimSpace(cfg.Username)
	if cfg.URL == "" || cfg.Username == "" || cfg.Password == "" {
		return cfg, fmt.Errorf("请在 panel.yaml 或 FANOUT_3M_UI_* 环境变量中配置 3m-ui 地址、用户名和密码")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return cfg, fmt.Errorf("3m-ui 地址必须是有效的 http/https URL")
	}
	return cfg, nil
}

// ThreeMUI 仅通过 3m-ui REST API 管理配置，不直接改它的数据库或 YAML 文件。
type ThreeMUI struct {
	baseURL  string
	username string
	password string
	totpCode string
	client   *http.Client

	authMu sync.Mutex
	token  string
	// opMu 串行化路由写入及“临时改 PublicHost—导出—恢复”操作。
	opMu sync.Mutex
}

func openThreeMUI(workDir string) (*ThreeMUI, error) {
	cfg, err := loadThreeMUIConfig(workDir)
	if err != nil {
		return nil, err
	}
	return newThreeMUI(cfg)
}

func newThreeMUI(cfg threeMUIConfig) (*ThreeMUI, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if !strings.HasSuffix(base, "/api/v1") {
		base += "/api/v1"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- 仅按用户显式配置跳过
	}
	return &ThreeMUI{
		baseURL: base, username: cfg.Username, password: cfg.Password, totpCode: cfg.TOTPCode,
		client: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

func (x *ThreeMUI) Kind() string { return "3m-ui" }
func (x *ThreeMUI) Describe() string {
	return "3m-ui 面板（" + strings.TrimSuffix(x.baseURL, "/api/v1") + "，Mihomo 服务端路由）"
}
func (x *ThreeMUI) Close() {}

func (x *ThreeMUI) currentToken() string {
	x.authMu.Lock()
	defer x.authMu.Unlock()
	return x.token
}

func (x *ThreeMUI) login() error {
	x.authMu.Lock()
	defer x.authMu.Unlock()
	if x.token != "" {
		return nil
	}
	payload := map[string]string{"username": x.username, "password": x.password, "totp_code": x.totpCode}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, x.baseURL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := x.client.Do(req)
	if err != nil {
		return fmt.Errorf("登录 3m-ui 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("登录 3m-ui 返回 HTTP %d: %s", resp.StatusCode, apiError(raw))
	}
	var result struct {
		Token        string `json:"token"`
		TOTPRequired bool   `json:"totp_required"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("解析 3m-ui 登录响应失败: %w", err)
	}
	if result.TOTPRequired {
		return fmt.Errorf("3m-ui 要求动态验证码，请配置 FANOUT_3M_UI_TOTP_CODE 或 panel.yaml 的 totp_code")
	}
	if result.Token == "" {
		return fmt.Errorf("3m-ui 登录响应没有 token；若启用了动态验证码，请检查 totp_code")
	}
	x.token = result.Token
	return nil
}

func apiError(raw []byte) string {
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) == nil {
		if body.Error != "" {
			return body.Error
		}
		if body.Message != "" {
			return body.Message
		}
	}
	return strings.TrimSpace(string(raw))
}

// do 调用普通 JSON API；401 时重新登录并重试一次。
func (x *ThreeMUI) do(method, path string, payload, out any) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if x.currentToken() == "" {
			if err := x.login(); err != nil {
				return err
			}
		}
		token := x.currentToken()
		req, err := http.NewRequest(method, x.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := x.client.Do(req)
		if err != nil {
			return fmt.Errorf("调用 3m-ui %s 失败: %w", path, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			x.authMu.Lock()
			if x.token == token {
				x.token = ""
			}
			x.authMu.Unlock()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("3m-ui %s 返回 HTTP %d: %s", path, resp.StatusCode, apiError(raw))
		}
		if out != nil && len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("解析 3m-ui %s 响应失败: %w", path, err)
			}
		}
		return nil
	}
	return fmt.Errorf("3m-ui 登录已过期，重试失败")
}

type threeMListener struct {
	ID                int     `json:"id"`
	CreatedAt         string  `json:"created_at,omitempty"`
	UpdatedAt         string  `json:"updated_at,omitempty"`
	Name              string  `json:"name"`
	Protocol          string  `json:"protocol"`
	Type              string  `json:"type"`
	Port              string  `json:"port"`
	BindAddress       string  `json:"bind_address"`
	Listen            string  `json:"listen"`
	TLS               bool    `json:"tls"`
	UDP               bool    `json:"udp"`
	Enabled           bool    `json:"enabled"`
	Proxy             string  `json:"proxy,omitempty"`
	Rule              string  `json:"rule,omitempty"`
	Config            string  `json:"config"`
	Status            string  `json:"status"`
	RoutingMark       int     `json:"routing_mark,omitempty"`
	PublicHost        string  `json:"public_host,omitempty"`
	PublicPort        string  `json:"public_port,omitempty"`
	AccessSNI         string  `json:"access_sni,omitempty"`
	ClientFingerprint string  `json:"client_fingerprint,omitempty"`
	AccessALPN        string  `json:"access_alpn,omitempty"`
	TrafficMultiplier float64 `json:"traffic_multiplier"`
}

func (x *ThreeMUI) listeners() ([]threeMListener, error) {
	var list []threeMListener
	if err := x.do(http.MethodGet, "/listeners", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (x *ThreeMUI) listener(id int) (threeMListener, error) {
	var l threeMListener
	err := x.do(http.MethodGet, fmt.Sprintf("/listeners/%d", id), nil, &l)
	return l, err
}

func listenerPort(l threeMListener) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(l.Port))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("Listener %d 的端口 %q 不是单端口，fanout 仅支持单端口", l.ID, l.Port)
	}
	return port, nil
}

func inboundOf(l threeMListener) (Inbound, error) {
	port, err := listenerPort(l)
	if err != nil {
		return Inbound{}, err
	}
	return Inbound{
		ID: l.ID, Port: port, Protocol: l.Protocol, Remark: l.Name,
		Enable: l.Enabled, Tag: listenerTag(l.ID),
	}, nil
}

type threeMProxy map[string]any

type threeMServerOutbound struct {
	Proxy   threeMProxy `json:"proxy"`
	Enabled bool        `json:"enabled"`
	Managed bool        `json:"managed"`
}

type threeMRouting struct {
	DisabledOutboundNames []string      `json:"disabledOutboundNames,omitempty"`
	Proxies               []threeMProxy `json:"proxies,omitempty"`
	Groups                []struct {
		Name    string   `json:"name"`
		Proxies []string `json:"proxies"`
	} `json:"proxyGroups,omitempty"`
	Rules         []string `json:"rules"`
	WarpDomains   []string `json:"warpDomains,omitempty"`
	WarpGlobal    bool     `json:"warpGlobal,omitempty"`
	RuleProviders []struct {
		Name  string `json:"name"`
		Proxy string `json:"proxy,omitempty"`
	} `json:"ruleProviders,omitempty"`
}

func (x *ThreeMUI) routing() (threeMRouting, error) {
	var cfg threeMRouting
	if err := x.do(http.MethodGet, "/config/server-routing", nil, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (x *ThreeMUI) outbounds() ([]threeMServerOutbound, error) {
	var list []threeMServerOutbound
	if err := x.do(http.MethodGet, "/config/server-outbounds", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func proxyName(p threeMProxy) string {
	name, _ := p["name"].(string)
	return name
}

func socksProxy(t *Tunnel) threeMProxy {
	cred := t.credential()
	return threeMProxy{
		"name": tunnelTag(t), "type": "socks5", "server": "127.0.0.1", "port": t.Port,
		"username": cred.User, "password": cred.Pass,
	}
}

func sameProxy(a, b threeMProxy) bool { return reflect.DeepEqual(a, b) }

// syncOutbounds 更新所有连通隧道的 SOCKS5 出站，并只清理无引用的旧 fanout 出站。
func (x *ThreeMUI) syncOutbounds(tunnels []*Tunnel, cleanup bool) error {
	existing, err := x.outbounds()
	if err != nil {
		return err
	}
	byName := make(map[string]threeMProxy, len(existing))
	for _, entry := range existing {
		byName[proxyName(entry.Proxy)] = entry.Proxy
	}
	desired := map[string]bool{}
	for _, t := range tunnels {
		if t.Status != "up" {
			continue
		}
		proxy := socksProxy(t)
		name := proxyName(proxy)
		desired[name] = true
		payload := map[string]any{"proxy": proxy, "enabled": true}
		if old, ok := byName[name]; ok {
			if sameProxy(old, proxy) {
				continue
			}
			if err := x.do(http.MethodPut, "/config/server-outbounds?name="+url.QueryEscape(name), payload, nil); err != nil {
				return fmt.Errorf("更新出口 %s 失败: %w", name, err)
			}
		} else if err := x.do(http.MethodPost, "/config/server-outbounds", payload, nil); err != nil {
			return fmt.Errorf("创建出口 %s 失败: %w", name, err)
		}
	}
	if !cleanup {
		return nil
	}
	cfg, err := x.routing()
	if err != nil {
		return err
	}
	for _, entry := range existing {
		name := proxyName(entry.Proxy)
		if !isFanoutOutbound(name) || desired[name] || routingReferences(cfg, name) {
			continue
		}
		if err := x.do(http.MethodDelete, "/config/server-outbounds?name="+url.QueryEscape(name), nil, nil); err != nil {
			return fmt.Errorf("清理出口 %s 失败: %w", name, err)
		}
	}
	return nil
}

// routingReferences 保守检查组、规则、rule-provider 和 dialer-proxy 是否引用出站。
func routingReferences(cfg threeMRouting, name string) bool {
	for _, rule := range cfg.Rules {
		parts := strings.Split(rule, ",")
		for _, part := range parts[1:] {
			if strings.TrimSpace(part) == name {
				return true
			}
		}
	}
	for _, group := range cfg.Groups {
		for _, proxy := range group.Proxies {
			if proxy == name {
				return true
			}
		}
	}
	for _, provider := range cfg.RuleProviders {
		if provider.Proxy == name {
			return true
		}
	}
	for _, proxy := range cfg.Proxies {
		if target, _ := proxy["dialer-proxy"].(string); target == name {
			return true
		}
	}
	return false
}

func fanoutRule(rule string) (port int, target string, ok bool) {
	parts := strings.Split(rule, ",")
	if len(parts) != 3 || !strings.EqualFold(strings.TrimSpace(parts[0]), "IN-PORT") {
		return 0, "", false
	}
	target = strings.TrimSpace(parts[2])
	if !isFanoutOutbound(target) {
		return 0, "", false
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, "", false
	}
	return port, target, true
}

func putBeforeMatch(rules []string, rule string) []string {
	for i, current := range rules {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(current)), "MATCH,") {
			out := make([]string, 0, len(rules)+1)
			out = append(out, rules[:i]...)
			out = append(out, rule)
			out = append(out, rules[i:]...)
			return out
		}
	}
	return append(rules, rule)
}

func (x *ThreeMUI) patchRules(rules []string) error {
	// PATCH 只写 rules，避免覆盖用户在 3m-ui 中配置的组、providers 与 WARP。
	return x.do(http.MethodPatch, "/config/server-routing", map[string]any{"rules": rules}, nil)
}

// apply 让 3m-ui 从数据库重新生成 config.yaml 并重载 Mihomo 内核。
// server-outbounds 与 server-routing 的写入只落库，必须显式 apply 才会生效；
// 空体会让 3m-ui 自行从 DB 生成最新配置，失败时它会回滚上一份。
func (x *ThreeMUI) apply() error {
	if err := x.do(http.MethodPost, "/config/apply", nil, nil); err != nil {
		return fmt.Errorf("应用 3m-ui 配置失败: %w", err)
	}
	return nil
}

func boundListeners(list []threeMListener, cfg threeMRouting) map[string]string {
	// 收集有 fanout 路由规则的 listener 端口
	managedPorts := map[int]bool{}
	for _, rule := range cfg.Rules {
		if port, _, ok := fanoutRule(rule); ok {
			managedPorts[port] = true
		}
	}
	bound := map[string]string{}
	for _, l := range list {
		port, err := listenerPort(l)
		if err != nil || !managedPorts[port] {
			continue
		}
		// 出站名不再含 hostname，从 Listener 备注（exitLabel 格式「🇯🇵 日本 jp-home」）末段反推
		bound[listenerTag(l.ID)] = remarkHost(l.Name)
	}
	return bound
}

func (x *ThreeMUI) Inbounds(live map[string]bool) ([]Inbound, error) {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	list, err := x.listeners()
	if err != nil {
		return nil, err
	}
	cfg, err := x.routing()
	if err != nil {
		return nil, err
	}
	bound := boundListeners(list, cfg)
	out := make([]Inbound, 0, len(list))
	for _, l := range list {
		ib, err := inboundOf(l)
		if err != nil {
			return nil, err
		}
		ib.BoundTo = bound[ib.Tag]
		ib.BoundUp = live[ib.BoundTo]
		out = append(out, ib)
	}
	return out, nil
}

func findTunnel(tunnels []*Tunnel, hostname string) *Tunnel {
	for _, t := range tunnels {
		if t.Node.HostName == hostname {
			return t
		}
	}
	return nil
}

func (x *ThreeMUI) bind(inboundTag, hostname string, tunnels []*Tunnel) error {
	var target *Tunnel
	if hostname != "" {
		target = findTunnel(tunnels, hostname)
		if target == nil || target.Status != "up" {
			return fmt.Errorf("节点 %s 没有已连通的隧道", hostname)
		}
	}
	list, err := x.listeners()
	if err != nil {
		return err
	}
	var selected *threeMListener
	alivePorts := map[int]bool{}
	for i := range list {
		port, err := listenerPort(list[i])
		if err != nil {
			return err
		}
		alivePorts[port] = true
		if listenerTag(list[i].ID) == inboundTag {
			selected = &list[i]
		}
	}
	if selected == nil {
		return fmt.Errorf("Listener %s 不存在", inboundTag)
	}
	if err := x.syncOutbounds(tunnels, false); err != nil {
		return err
	}
	cfg, err := x.routing()
	if err != nil {
		return err
	}
	selectedPort, _ := listenerPort(*selected)
	rules := make([]string, 0, len(cfg.Rules)+1)
	for _, rule := range cfg.Rules {
		port, _, managed := fanoutRule(rule)
		if managed && (!alivePorts[port] || port == selectedPort) {
			continue
		}
		rules = append(rules, rule)
	}
	if target != nil {
		rules = putBeforeMatch(rules, fmt.Sprintf("IN-PORT,%d,%s", selectedPort, tunnelTag(target)))
	}
	return x.patchRules(rules)
}

func (x *ThreeMUI) Bind(inboundTag, hostname string, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	if err := x.bind(inboundTag, hostname, tunnels); err != nil {
		return err
	}
	return x.apply()
}

func (x *ThreeMUI) Rebind(oldHost string, target *Tunnel, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	list, err := x.listeners()
	if err != nil {
		return err
	}
	cfg, err := x.routing()
	if err != nil {
		return err
	}
	bound := boundListeners(list, cfg)
	newLabel := exitLabel(target)
	for _, l := range list {
		tag := listenerTag(l.ID)
		if bound[tag] != sanitizeTag(oldHost) {
			continue
		}
		if err := x.bind(tag, target.Node.HostName, tunnels); err != nil {
			return err
		}
		if renamed := renameExitLabel(l.Name, newLabel); renamed != l.Name {
			l.Name = renamed
			if err := x.do(http.MethodPut, fmt.Sprintf("/listeners/%d", l.ID), l, nil); err != nil {
				return err
			}
		}
	}
	return x.apply()
}

func (x *ThreeMUI) ResyncOutbound(t *Tunnel, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	if err := x.syncOutbounds(tunnels, false); err != nil {
		return err
	}
	return x.apply()
}

func (x *ThreeMUI) OnTunnelsChanged(tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	if err := x.syncOutbounds(tunnels, true); err != nil {
		return err
	}
	return x.apply()
}

type threeMUser struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	UUIDMasked string `json:"uuid_masked"`
	Enabled    bool   `json:"enabled"`
	Blocked    bool   `json:"blocked"`
	Remark     string `json:"remark"`
}

type threeMUserBinding struct {
	User        threeMUser
	ListenerIDs []int
}

func managedUser(u threeMUser) bool { return strings.HasPrefix(u.Remark, "fanout:") }

func (x *ThreeMUI) users() ([]threeMUser, error) {
	var users []threeMUser
	if err := x.do(http.MethodGet, "/users", nil, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (x *ThreeMUI) userBindings(userID int) ([]int, error) {
	var listeners []threeMListener
	if err := x.do(http.MethodGet, fmt.Sprintf("/users/%d/listeners", userID), nil, &listeners); err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(listeners))
	for _, l := range listeners {
		ids = append(ids, l.ID)
	}
	return ids, nil
}

func (x *ThreeMUI) allBindings() ([]threeMUserBinding, error) {
	users, err := x.users()
	if err != nil {
		return nil, err
	}
	out := make([]threeMUserBinding, 0, len(users))
	for _, u := range users {
		ids, err := x.userBindings(u.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, threeMUserBinding{User: u, ListenerIDs: ids})
	}
	return out, nil
}

func containsID(ids []int, id int) bool {
	for _, current := range ids {
		if current == id {
			return true
		}
	}
	return false
}

func mergeID(ids []int, id int) []int {
	if containsID(ids, id) {
		return ids
	}
	return append(ids, id)
}

func (x *ThreeMUI) bindUser(userID int, ids []int) error {
	// 3m-ui 的绑定接口是整组替换，调用前必须读取并合并旧集合。
	return x.do(http.MethodPost, fmt.Sprintf("/users/%d/listeners", userID), map[string]any{"listener_ids": ids}, nil)
}

func (x *ThreeMUI) quickUser(username string) (threeMUser, error) {
	var result struct {
		User     threeMUser `json:"user"`
		Password string     `json:"password"`
		UUID     string     `json:"uuid"`
	}
	err := x.do(http.MethodPost, "/users/quick", map[string]any{
		"username": username, "remark": fanoutUserRemark, "bind_all_listeners": false,
	}, &result)
	return result.User, err
}

func (x *ThreeMUI) CloneToTunnels(templateID int, hosts []string, tunnels []*Tunnel) ([]int, error) {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	list, err := x.listeners()
	if err != nil {
		return nil, err
	}
	used := map[int]bool{}
	takenNames := map[string]bool{}
	foundTemplate := false
	for _, l := range list {
		port, err := listenerPort(l)
		if err != nil {
			return nil, err
		}
		used[port] = true
		takenNames[strings.TrimSpace(l.Name)] = true
		if l.ID == templateID {
			foundTemplate = true
		}
	}
	if !foundTemplate {
		return nil, fmt.Errorf("模板 Listener %d 不存在", templateID)
	}
	bindings, err := x.allBindings()
	if err != nil {
		return nil, err
	}
	templateUsers := []threeMUserBinding{}
	for _, binding := range bindings {
		if containsID(binding.ListenerIDs, templateID) {
			templateUsers = append(templateUsers, binding)
		}
	}
	created := []int{}
	for _, host := range hosts {
		t := findTunnel(tunnels, host)
		if t == nil || t.Status != "up" {
			continue
		}
		port, err := freeRandomPort(used)
		if err != nil {
			return created, err
		}
		used[port] = true
		name := uniqueRemark(exitLabel(t), takenNames)
		takenNames[name] = true
		var clone threeMListener
		if err := x.do(http.MethodPost, fmt.Sprintf("/listeners/%d/clone", templateID), map[string]string{
			"name": name, "port": strconv.Itoa(port),
		}, &clone); err != nil {
			return created, fmt.Errorf("复制到端口 %d 失败: %w", port, err)
		}
		created = append(created, port)
		// Clone 不复制用户关系；逐个合并，保留用户在其他 Listener 上的绑定。
		for _, binding := range templateUsers {
			ids := mergeID(append([]int(nil), binding.ListenerIDs...), clone.ID)
			if err := x.bindUser(binding.User.ID, ids); err != nil {
				return created, fmt.Errorf("给端口 %d 复制用户绑定失败: %w", port, err)
			}
			for i := range templateUsers {
				if templateUsers[i].User.ID == binding.User.ID {
					templateUsers[i].ListenerIDs = ids
				}
			}
		}
		if err := x.bind(listenerTag(clone.ID), host, tunnels); err != nil {
			return created, fmt.Errorf("端口 %d 绑定出口失败: %w", port, err)
		}
	}
	if err := x.apply(); err != nil {
		return created, err
	}
	return created, nil
}

var threeMProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	"hysteria2": true, "tuic": true, "tuic-v4": true, "tuic-v5": true,
}

func (x *ThreeMUI) CreateInbound(spec NewInboundSpec, tunnels []*Tunnel) (*CreatedInbound, error) {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	protocol := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if protocol == "" {
		protocol = "vless"
	}
	if !threeMProtocols[protocol] {
		return nil, fmt.Errorf("3m-ui QuickCreate 不支持协议 %q", spec.Protocol)
	}
	name := strings.TrimSpace(spec.Remark)
	if name == "" {
		name = protocol + "-" + randomHex(3)
	}
	var listener threeMListener
	if err := x.do(http.MethodPost, "/listeners/quick", map[string]string{
		"name": name, "protocol": protocol,
	}, &listener); err != nil {
		return nil, err
	}
	user, err := x.quickUser(fmt.Sprintf("fanout-%d-%s", listener.ID, randomHex(3)))
	if err != nil {
		_ = x.do(http.MethodDelete, fmt.Sprintf("/listeners/%d", listener.ID), nil, nil)
		return nil, fmt.Errorf("Listener 已创建，但创建代理用户失败: %w", err)
	}
	if err := x.bindUser(user.ID, []int{listener.ID}); err != nil {
		_ = x.do(http.MethodDelete, fmt.Sprintf("/users/%d", user.ID), nil, nil)
		_ = x.do(http.MethodDelete, fmt.Sprintf("/listeners/%d", listener.ID), nil, nil)
		return nil, fmt.Errorf("Listener 已创建，但绑定代理用户失败: %w", err)
	}
	port, err := listenerPort(listener)
	if err != nil {
		return nil, err
	}
	return &CreatedInbound{ID: listener.ID, Port: port, Protocol: listener.Protocol, Remark: listener.Name}, nil
}

func (x *ThreeMUI) UpdateInbound(id int, patch InboundPatch, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	listener, err := x.listener(id)
	if err != nil {
		return err
	}
	oldPort, err := listenerPort(listener)
	if err != nil {
		return err
	}
	newPort := oldPort
	if patch.Port != nil {
		newPort = *patch.Port
		if newPort < 1 || newPort > 65535 {
			return fmt.Errorf("端口必须在 1-65535 之间")
		}
		if newPort != oldPort {
			list, err := x.listeners()
			if err != nil {
				return err
			}
			for _, other := range list {
				if other.ID == id {
					continue
				}
				port, err := listenerPort(other)
				if err != nil {
					return err
				}
				if port == newPort {
					return fmt.Errorf("端口 %d 已被其他 Listener 占用", newPort)
				}
			}
			listener.Port = strconv.Itoa(newPort)
		}
	}
	if patch.Remark != nil {
		if strings.TrimSpace(*patch.Remark) == "" {
			return fmt.Errorf("备注不能为空")
		}
		listener.Name = strings.TrimSpace(*patch.Remark)
	}
	if patch.Enable != nil {
		listener.Enabled = *patch.Enable
	}
	if err := x.do(http.MethodPut, fmt.Sprintf("/listeners/%d", id), listener, nil); err != nil {
		return err
	}
	if newPort == oldPort {
		return nil
	}
	cfg, err := x.routing()
	if err != nil {
		return err
	}
	rules := make([]string, 0, len(cfg.Rules))
	seen := map[string]bool{}
	for _, rule := range cfg.Rules {
		port, target, managed := fanoutRule(rule)
		if managed && port == oldPort {
			rule = fmt.Sprintf("IN-PORT,%d,%s", newPort, target)
		}
		if seen[rule] {
			continue
		}
		seen[rule] = true
		rules = append(rules, rule)
	}
	if err := x.patchRules(rules); err != nil {
		return err
	}
	return x.apply()
}

func (x *ThreeMUI) DeleteInbounds(ids []int, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	deleted := map[int]bool{}
	for _, id := range ids {
		deleted[id] = true
	}
	bindings, err := x.allBindings()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := x.do(http.MethodDelete, fmt.Sprintf("/listeners/%d", id), nil, nil); err != nil {
			return fmt.Errorf("删除 Listener %d 失败: %w", id, err)
		}
	}
	list, err := x.listeners()
	if err != nil {
		return err
	}
	alivePorts := map[int]bool{}
	for _, l := range list {
		port, err := listenerPort(l)
		if err != nil {
			return err
		}
		alivePorts[port] = true
	}
	cfg, err := x.routing()
	if err != nil {
		return err
	}
	rules := make([]string, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		port, _, managed := fanoutRule(rule)
		if managed && !alivePorts[port] {
			continue
		}
		rules = append(rules, rule)
	}
	// 先移除引用规则，再允许后续清理出站。
	if err := x.patchRules(rules); err != nil {
		return err
	}
	for _, binding := range bindings {
		if !managedUser(binding.User) {
			continue
		}
		affected := false
		remaining := make([]int, 0, len(binding.ListenerIDs))
		for _, listenerID := range binding.ListenerIDs {
			if deleted[listenerID] {
				affected = true
				continue
			}
			remaining = append(remaining, listenerID)
		}
		if !affected {
			continue
		}
		if len(remaining) == 0 {
			if err := x.do(http.MethodDelete, fmt.Sprintf("/users/%d", binding.User.ID), nil, nil); err != nil {
				return fmt.Errorf("清理 fanout 用户 %s 失败: %w", binding.User.Username, err)
			}
		} else if err := x.bindUser(binding.User.ID, remaining); err != nil {
			return err
		}
	}
	if err := x.syncOutbounds(tunnels, true); err != nil {
		return err
	}
	return x.apply()
}

func (x *ThreeMUI) AddClient(id int, email string, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	email = strings.TrimSpace(email)
	if email == "" {
		email = fmt.Sprintf("fanout-%d-%s", id, randomHex(3))
	}
	users, err := x.users()
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Username == email {
			return fmt.Errorf("代理用户 %s 已存在", email)
		}
	}
	user, err := x.quickUser(email)
	if err != nil {
		return err
	}
	if err := x.bindUser(user.ID, []int{id}); err != nil {
		_ = x.do(http.MethodDelete, fmt.Sprintf("/users/%d", user.ID), nil, nil)
		return err
	}
	return nil
}

func (x *ThreeMUI) DeleteClient(id int, email string, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	bindings, err := x.allBindings()
	if err != nil {
		return err
	}
	count := 0
	var selected *threeMUserBinding
	for i := range bindings {
		if containsID(bindings[i].ListenerIDs, id) {
			count++
			if bindings[i].User.Username == email {
				selected = &bindings[i]
			}
		}
	}
	if selected == nil {
		return fmt.Errorf("客户端 %s 不存在", email)
	}
	if count <= 1 {
		return fmt.Errorf("这是最后一个客户端，删掉 Listener 就没人能连了")
	}
	if managedUser(selected.User) && len(selected.ListenerIDs) == 1 {
		return x.do(http.MethodDelete, fmt.Sprintf("/users/%d", selected.User.ID), nil, nil)
	}
	remaining := make([]int, 0, len(selected.ListenerIDs))
	for _, listenerID := range selected.ListenerIDs {
		if listenerID != id {
			remaining = append(remaining, listenerID)
		}
	}
	return x.bindUser(selected.User.ID, remaining)
}

func (x *ThreeMUI) ResetClient(id int, email string, tunnels []*Tunnel) error {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	users, err := x.users()
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Username != email {
			continue
		}
		ids, err := x.userBindings(u.ID)
		if err != nil {
			return err
		}
		if !containsID(ids, id) {
			break
		}
		// UUID 与密码一起更新，兼容 VLESS/VMess/Trojan 等不同协议。
		return x.do(http.MethodPut, fmt.Sprintf("/users/%d", u.ID), map[string]string{
			"uuid": newUUID(), "password": randomHex(12),
		}, nil)
	}
	return fmt.Errorf("客户端 %s 不存在", email)
}

type threeMExport struct {
	URI        string   `json:"uri"`
	URIs       []string `json:"uris"`
	ClientYAML string   `json:"client_yaml"`
	Hint       string   `json:"hint"`
}

// export 临时覆盖 Listener 的 PublicHost，确保导出地址使用 fanout 的公网主机。
func (x *ThreeMUI) export(id int, publicHost string) (threeMExport, error) {
	var result threeMExport
	listener, err := x.listener(id)
	if err != nil {
		return result, err
	}
	originalHost := listener.PublicHost
	if publicHost != "" && originalHost != publicHost {
		listener.PublicHost = publicHost
		if err := x.do(http.MethodPut, fmt.Sprintf("/listeners/%d", id), listener, nil); err != nil {
			return result, fmt.Errorf("临时设置导出主机失败: %w", err)
		}
	}
	exportErr := x.do(http.MethodGet, fmt.Sprintf("/nodes/%d/uri", id), nil, &result)
	if publicHost != "" && originalHost != publicHost {
		listener.PublicHost = originalHost
		if restoreErr := x.do(http.MethodPut, fmt.Sprintf("/listeners/%d", id), listener, nil); restoreErr != nil {
			if exportErr != nil {
				return result, fmt.Errorf("导出失败: %v；恢复 PublicHost 也失败: %w", exportErr, restoreErr)
			}
			return result, fmt.Errorf("导出完成，但恢复 PublicHost 失败: %w", restoreErr)
		}
	}
	if exportErr != nil {
		return result, exportErr
	}
	if len(result.URIs) == 0 && result.URI != "" {
		result.URIs = []string{result.URI}
	}
	if len(result.URIs) == 0 && result.ClientYAML == "" && result.Hint != "" {
		return result, fmt.Errorf("Listener %d 无法导出: %s", id, result.Hint)
	}
	return result, nil
}

func (x *ThreeMUI) InboundDetail(id int, publicHost string) (*InboundDetail, error) {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	listener, err := x.listener(id)
	if err != nil {
		return nil, err
	}
	ib, err := inboundOf(listener)
	if err != nil {
		return nil, err
	}
	list, err := x.listeners()
	if err != nil {
		return nil, err
	}
	cfg, err := x.routing()
	if err != nil {
		return nil, err
	}
	ib.BoundTo = boundListeners(list, cfg)[ib.Tag]
	detail := &InboundDetail{Inbound: ib, Listen: listener.Listen}
	if detail.Listen == "" {
		detail.Listen = listener.BindAddress
	}
	var listenerConfig map[string]any
	if json.Unmarshal([]byte(listener.Config), &listenerConfig) == nil {
		detail.Network, _ = listenerConfig["transport_layer"].(string)
		detail.TLS, _ = listenerConfig["security_layer"].(string)
	}
	bindings, err := x.allBindings()
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if !containsID(binding.ListenerIDs, id) {
			continue
		}
		detail.Clients = append(detail.Clients, ClientInfo{
			Email: binding.User.Username, ID: binding.User.UUIDMasked, Enable: binding.User.Enabled,
		})
	}
	if listener.Enabled {
		exported, err := x.export(id, publicHost)
		if err != nil {
			return nil, err
		}
		detail.Links = exported.URIs
	}
	return detail, nil
}

func (x *ThreeMUI) InboundLinks(ids []int, publicHost string) ([]string, error) {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	var out []string
	for _, id := range ids {
		listener, err := x.listener(id)
		if err != nil {
			return out, err
		}
		if !listener.Enabled {
			continue
		}
		exported, err := x.export(id, publicHost)
		if err != nil {
			return out, err
		}
		out = append(out, exported.URIs...)
	}
	return out, nil
}

// clientProxies 兼容单 proxy 文档和包含 proxies 的完整 Mihomo 文档。
func clientProxies(raw string) ([]map[string]any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
		return nil, err
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = *root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("client_yaml 不是 YAML 对象")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "proxies" {
			continue
		}
		var proxies []map[string]any
		if err := root.Content[i+1].Decode(&proxies); err != nil {
			return nil, err
		}
		return proxies, nil
	}
	var proxy map[string]any
	if err := root.Decode(&proxy); err != nil {
		return nil, err
	}
	if proxy["name"] == nil || proxy["type"] == nil {
		return nil, fmt.Errorf("client_yaml 既没有 proxies，也不是单个 proxy")
	}
	return []map[string]any{proxy}, nil
}

func (x *ThreeMUI) InboundYAML(ids []int, publicHost string) (string, error) {
	x.opMu.Lock()
	defer x.opMu.Unlock()
	proxies := []map[string]any{}
	names := map[string]bool{}
	for _, id := range ids {
		listener, err := x.listener(id)
		if err != nil {
			return "", err
		}
		if !listener.Enabled {
			continue
		}
		exported, err := x.export(id, publicHost)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(exported.ClientYAML) == "" {
			return "", fmt.Errorf("Listener %d 没有可导出的 Mihomo YAML", id)
		}
		items, err := clientProxies(exported.ClientYAML)
		if err != nil {
			return "", fmt.Errorf("解析 Listener %d 的 client_yaml 失败: %w", id, err)
		}
		for _, proxy := range items {
			name, _ := proxy["name"].(string)
			if name == "" {
				return "", fmt.Errorf("Listener %d 的 YAML proxy 缺少 name", id)
			}
			if names[name] {
				return "", fmt.Errorf("Mihomo 节点名 %q 重复，请在 3m-ui 中调整 Listener 名称", name)
			}
			names[name] = true
			proxies = append(proxies, proxy)
		}
	}
	if len(proxies) == 0 {
		return "", nil
	}
	blob, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprint(os.Getpid())))
	}
	return hex.EncodeToString(b)
}
