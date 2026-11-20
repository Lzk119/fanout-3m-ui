package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// threeMMock 是有状态的 3m-ui REST API mock，用于验证 fanout 的请求契约。
type threeMMock struct {
	t      *testing.T
	server *httptest.Server

	mu             sync.Mutex
	listeners      map[int]threeMListener
	users          map[int]threeMUser
	bindings       map[int][]int
	exports        map[int]threeMExport
	routing        threeMRouting
	outbounds      map[string]threeMProxy
	requests       []string
	publicHostLog  []string
	loginCount     int
	applyCount     int
	expireFirst    bool
	expired        bool
	failRestore    bool
	quickSpec      map[string]string
	cloneSpec      map[string]string
	boundListeners map[int][][]int
}

func newThreeMMock(t *testing.T) *threeMMock {
	t.Helper()
	m := &threeMMock{
		t: t, listeners: map[int]threeMListener{}, users: map[int]threeMUser{},
		bindings: map[int][]int{}, exports: map[int]threeMExport{},
		outbounds: map[string]threeMProxy{}, boundListeners: map[int][][]int{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.serveHTTP))
	t.Cleanup(m.server.Close)
	return m
}

func (m *threeMMock) panel() *ThreeMUI {
	m.t.Helper()
	p, err := newThreeMUI(threeMUIConfig{URL: m.server.URL, Username: "admin", Password: "secret"})
	if err != nil {
		m.t.Fatal(err)
	}
	return p
}

func mockJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func mockError(w http.ResponseWriter, status int, message string) {
	mockJSON(w, status, map[string]string{"error": message})
}

func pathID(part string) int {
	id, _ := strconv.Atoi(part)
	return id
}

func nextListenerID(listeners map[int]threeMListener) int {
	id := 1
	for current := range listeners {
		if current >= id {
			id = current + 1
		}
	}
	return id
}

func nextUserID(users map[int]threeMUser) int {
	id := 1
	for current := range users {
		if current >= id {
			id = current + 1
		}
	}
	return id
}

func (m *threeMMock) serveHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		mockError(w, http.StatusNotFound, "bad prefix")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	m.requests = append(m.requests, r.Method+" "+r.URL.RequestURI())
	if path == "/auth/login" && r.Method == http.MethodPost {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "admin" || body["password"] != "secret" {
			mockError(w, http.StatusUnauthorized, "bad credentials")
			return
		}
		m.loginCount++
		mockJSON(w, http.StatusOK, map[string]string{"token": fmt.Sprintf("token-%d", m.loginCount)})
		return
	}

	// 第一张 token 首次使用时失效，验证客户端会重新登录并重试原请求。
	if m.expireFirst && !m.expired && r.Header.Get("Authorization") == "Bearer token-1" {
		m.expired = true
		mockError(w, http.StatusUnauthorized, "expired")
		return
	}
	wantToken := fmt.Sprintf("Bearer token-%d", m.loginCount)
	if m.loginCount == 0 || r.Header.Get("Authorization") != wantToken {
		mockError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch parts[0] {
	case "listeners":
		m.serveListeners(w, r, parts)
	case "users":
		m.serveUsers(w, r, parts)
	case "nodes":
		m.serveNodes(w, r, parts)
	case "config":
		m.serveConfig(w, r, path)
	default:
		mockError(w, http.StatusNotFound, "unknown path "+path)
	}
}

func (m *threeMMock) serveListeners(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 && r.Method == http.MethodGet {
		ids := make([]int, 0, len(m.listeners))
		for id := range m.listeners {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		list := make([]threeMListener, 0, len(ids))
		for _, id := range ids {
			list = append(list, m.listeners[id])
		}
		mockJSON(w, http.StatusOK, list)
		return
	}
	if len(parts) == 2 && parts[1] == "quick" && r.Method == http.MethodPost {
		m.quickSpec = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&m.quickSpec)
		id := nextListenerID(m.listeners)
		listener := threeMListener{
			ID: id, Name: m.quickSpec["name"], Protocol: m.quickSpec["protocol"],
			Port: strconv.Itoa(10000 + id), Enabled: true,
		}
		m.listeners[id] = listener
		mockJSON(w, http.StatusCreated, listener)
		return
	}
	if len(parts) < 2 {
		mockError(w, http.StatusNotFound, "listener required")
		return
	}
	id := pathID(parts[1])
	listener, ok := m.listeners[id]
	if !ok {
		mockError(w, http.StatusNotFound, "listener not found")
		return
	}
	if len(parts) == 3 && parts[2] == "clone" && r.Method == http.MethodPost {
		m.cloneSpec = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&m.cloneSpec)
		cloneID := nextListenerID(m.listeners)
		clone := listener
		clone.ID, clone.Name, clone.Port = cloneID, m.cloneSpec["name"], m.cloneSpec["port"]
		m.listeners[cloneID] = clone // 与 3m-ui 一样，Clone 不复制用户绑定。
		mockJSON(w, http.StatusCreated, clone)
		return
	}
	if len(parts) != 2 {
		mockError(w, http.StatusNotFound, "unknown listener action")
		return
	}
	switch r.Method {
	case http.MethodGet:
		mockJSON(w, http.StatusOK, listener)
	case http.MethodPut:
		var updated threeMListener
		_ = json.NewDecoder(r.Body).Decode(&updated)
		m.publicHostLog = append(m.publicHostLog, updated.PublicHost)
		if m.failRestore && listener.PublicHost == "new.example" && updated.PublicHost == "old.example" {
			mockError(w, http.StatusInternalServerError, "restore failed")
			return
		}
		m.listeners[id] = updated
		mockJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		delete(m.listeners, id)
		mockJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		mockError(w, http.StatusMethodNotAllowed, "method")
	}
}

func (m *threeMMock) serveUsers(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 && r.Method == http.MethodGet {
		ids := make([]int, 0, len(m.users))
		for id := range m.users {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		list := make([]threeMUser, 0, len(ids))
		for _, id := range ids {
			list = append(list, m.users[id])
		}
		mockJSON(w, http.StatusOK, list)
		return
	}
	if len(parts) == 2 && parts[1] == "quick" && r.Method == http.MethodPost {
		var body struct {
			Username string `json:"username"`
			Remark   string `json:"remark"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := nextUserID(m.users)
		user := threeMUser{ID: id, Username: body.Username, Remark: body.Remark, Enabled: true, UUIDMasked: "uuid-****"}
		m.users[id] = user
		mockJSON(w, http.StatusCreated, map[string]any{"user": user, "password": "generated", "uuid": "uuid-full"})
		return
	}
	if len(parts) < 2 {
		mockError(w, http.StatusNotFound, "user required")
		return
	}
	id := pathID(parts[1])
	user, ok := m.users[id]
	if !ok {
		mockError(w, http.StatusNotFound, "user not found")
		return
	}
	if len(parts) == 3 && parts[2] == "listeners" {
		switch r.Method {
		case http.MethodGet:
			list := []threeMListener{}
			for _, listenerID := range m.bindings[id] {
				if listener, exists := m.listeners[listenerID]; exists {
					list = append(list, listener)
				}
			}
			mockJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var body struct {
				ListenerIDs []int `json:"listener_ids"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.bindings[id] = append([]int(nil), body.ListenerIDs...)
			m.boundListeners[id] = append(m.boundListeners[id], append([]int(nil), body.ListenerIDs...))
			mockJSON(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			mockError(w, http.StatusMethodNotAllowed, "method")
		}
		return
	}
	if len(parts) == 2 && r.Method == http.MethodDelete {
		delete(m.users, id)
		delete(m.bindings, id)
		mockJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if len(parts) == 2 && r.Method == http.MethodPut {
		mockJSON(w, http.StatusOK, user)
		return
	}
	mockError(w, http.StatusNotFound, "unknown user action")
}

func (m *threeMMock) serveNodes(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) != 3 || parts[2] != "uri" || r.Method != http.MethodGet {
		mockError(w, http.StatusNotFound, "unknown node action")
		return
	}
	id := pathID(parts[1])
	listener, ok := m.listeners[id]
	if !ok {
		mockError(w, http.StatusNotFound, "listener not found")
		return
	}
	if exported, exists := m.exports[id]; exists {
		mockJSON(w, http.StatusOK, exported)
		return
	}
	host := listener.PublicHost
	if host == "" {
		host = "127.0.0.1"
	}
	mockJSON(w, http.StatusOK, threeMExport{
		URI: "vless://uuid@" + host + ":" + listener.Port,
		ClientYAML: fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %s\nuuid: uuid\n",
			listener.Name, host, listener.Port),
	})
}

func (m *threeMMock) serveConfig(w http.ResponseWriter, r *http.Request, path string) {
	switch path {
	case "/config/server-routing":
		switch r.Method {
		case http.MethodGet:
			mockJSON(w, http.StatusOK, m.routing)
		case http.MethodPatch:
			var body struct {
				Rules *[]string `json:"rules"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Rules != nil {
				m.routing.Rules = append([]string(nil), (*body.Rules)...)
			}
			mockJSON(w, http.StatusOK, m.routing)
		default:
			mockError(w, http.StatusMethodNotAllowed, "method")
		}
	case "/config/server-outbounds":
		switch r.Method {
		case http.MethodGet:
			names := make([]string, 0, len(m.outbounds))
			for name := range m.outbounds {
				names = append(names, name)
			}
			sort.Strings(names)
			list := make([]threeMServerOutbound, 0, len(names))
			for _, name := range names {
				list = append(list, threeMServerOutbound{Proxy: m.outbounds[name], Enabled: true})
			}
			mockJSON(w, http.StatusOK, list)
		case http.MethodPost, http.MethodPut:
			var body threeMServerOutbound
			_ = json.NewDecoder(r.Body).Decode(&body)
			name := proxyName(body.Proxy)
			if r.Method == http.MethodPut {
				name = r.URL.Query().Get("name")
			}
			m.outbounds[name] = body.Proxy
			mockJSON(w, http.StatusOK, body)
		case http.MethodDelete:
			delete(m.outbounds, r.URL.Query().Get("name"))
			mockJSON(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			mockError(w, http.StatusMethodNotAllowed, "method")
		}
	case "/config/apply":
		if r.Method != http.MethodPost {
			mockError(w, http.StatusMethodNotAllowed, "method")
			return
		}
		m.applyCount++
		mockJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		mockError(w, http.StatusNotFound, "unknown config")
	}
}

func TestThreeMUIReLoginOn401(t *testing.T) {
	m := newThreeMMock(t)
	m.expireFirst = true
	p := m.panel()
	if _, err := p.listeners(); err != nil {
		t.Fatal(err)
	}
	if m.loginCount != 2 || !m.expired {
		t.Fatalf("应当在 401 后重新登录一次：login=%d expired=%v", m.loginCount, m.expired)
	}
}

func TestThreeMUICreateInboundQuickContract(t *testing.T) {
	m := newThreeMMock(t)
	created, err := m.panel().CreateInbound(NewInboundSpec{Protocol: "vless", Remark: "家宽"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != 1 || created.Port != 10001 || created.Protocol != "vless" || created.Remark != "家宽" {
		t.Fatalf("创建结果不对：%+v", created)
	}
	if !reflect.DeepEqual(m.quickSpec, map[string]string{"name": "家宽", "protocol": "vless"}) {
		t.Fatalf("QuickCreate 请求不对：%v", m.quickSpec)
	}
	if !reflect.DeepEqual(m.bindings[1], []int{1}) || m.users[1].Remark != fanoutUserRemark {
		t.Fatalf("代理用户或绑定不对：user=%+v bindings=%v", m.users[1], m.bindings[1])
	}
}

func TestThreeMUICloneMergesBindingsAndWritesRoute(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "模板", Protocol: "vless", Port: "10001", Enabled: true}
	m.listeners[2] = threeMListener{ID: 2, Name: "其他", Protocol: "vless", Port: "10002", Enabled: true}
	m.users[7] = threeMUser{ID: 7, Username: "alice", Enabled: true}
	m.bindings[7] = []int{1, 2}
	m.routing.Rules = []string{"MATCH,DIRECT"}
	tunnel := &Tunnel{Node: Node{HostName: "jp-home"}, Port: 23000, Status: "up", Cred: SocksCred{User: "u", Pass: "p"}}

	ports, err := m.panel().CloneToTunnels(1, []string{"jp-home"}, []*Tunnel{tunnel})
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || m.listeners[3].Port != strconv.Itoa(ports[0]) {
		t.Fatalf("Clone 端口不对：ports=%v listener=%+v", ports, m.listeners[3])
	}
	// 整组替换接口必须保留旧绑定 1、2，再加入新 Listener 3。
	if !reflect.DeepEqual(m.bindings[7], []int{1, 2, 3}) {
		t.Fatalf("旧用户绑定被覆盖：%v", m.bindings[7])
	}
	wantRule := fmt.Sprintf("IN-PORT,%d,fanout-jp-home", ports[0])
	if !reflect.DeepEqual(m.routing.Rules, []string{wantRule, "MATCH,DIRECT"}) {
		t.Fatalf("IN-PORT 应插到 MATCH 前：%v", m.routing.Rules)
	}
	proxy := m.outbounds["fanout-jp-home"]
	if proxy["server"] != "127.0.0.1" || proxy["username"] != "u" || proxy["password"] != "p" {
		t.Fatalf("SOCKS5 出站不对：%v", proxy)
	}
	if m.applyCount != 1 {
		t.Fatalf("批量克隆后应只 apply 一次：%d", m.applyCount)
	}
}

func TestThreeMUIUpdateInboundMigratesPortRule(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "旧名", Protocol: "vless", Port: "10001", Enabled: true}
	m.routing.Rules = []string{"IN-PORT,10001,fanout-jp-home", "MATCH,DIRECT"}
	newPort, newName := 12000, "新名"
	if err := m.panel().UpdateInbound(1, InboundPatch{Port: &newPort, Remark: &newName}, nil); err != nil {
		t.Fatal(err)
	}
	if m.listeners[1].Port != "12000" || m.listeners[1].Name != "新名" {
		t.Fatalf("Listener 未完整更新：%+v", m.listeners[1])
	}
	want := []string{"IN-PORT,12000,fanout-jp-home", "MATCH,DIRECT"}
	if !reflect.DeepEqual(m.routing.Rules, want) {
		t.Fatalf("旧端口路由未迁移：%v", m.routing.Rules)
	}
	if m.applyCount != 1 {
		t.Fatalf("改端口迁移规则后应 apply 一次：%d", m.applyCount)
	}
}

func TestThreeMUIExportRestoresPublicHost(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "节点", Protocol: "vless", Port: "10001", Enabled: true, PublicHost: "old.example"}
	links, err := m.panel().InboundLinks([]int{1}, "new.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || !strings.Contains(links[0], "new.example") {
		t.Fatalf("导出地址未使用临时主机：%v", links)
	}
	if !reflect.DeepEqual(m.publicHostLog, []string{"new.example", "old.example"}) || m.listeners[1].PublicHost != "old.example" {
		t.Fatalf("PublicHost 未恢复：log=%v final=%q", m.publicHostLog, m.listeners[1].PublicHost)
	}
}

func TestThreeMUIExportRestoreFailureIsReported(t *testing.T) {
	m := newThreeMMock(t)
	m.failRestore = true
	m.listeners[1] = threeMListener{ID: 1, Name: "节点", Protocol: "vless", Port: "10001", Enabled: true, PublicHost: "old.example"}
	_, err := m.panel().InboundLinks([]int{1}, "new.example")
	if err == nil || !strings.Contains(err.Error(), "恢复 PublicHost 失败") {
		t.Fatalf("恢复失败必须明确返回：%v", err)
	}
}

func TestThreeMUIInboundYAMLMergesProxyDocuments(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "one", Protocol: "vless", Port: "10001", Enabled: true}
	m.listeners[2] = threeMListener{ID: 2, Name: "two", Protocol: "trojan", Port: "10002", Enabled: true}
	m.exports[1] = threeMExport{ClientYAML: "name: one\ntype: vless\nserver: one.example\nport: 10001\nuuid: uuid\n"}
	m.exports[2] = threeMExport{ClientYAML: "mixed-port: 7890\nproxies:\n  - name: two\n    type: trojan\n    server: two.example\n    port: 10002\n    password: pass\n"}

	raw, err := m.panel().InboundYAML([]int{1, 2}, "")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Proxies) != 2 || doc.Proxies[0]["name"] != "one" || doc.Proxies[1]["name"] != "two" {
		t.Fatalf("单 proxy 与完整文档合并不对：%s", raw)
	}
	var root map[string]any
	_ = yaml.Unmarshal([]byte(raw), &root)
	if _, exists := root["mixed-port"]; exists {
		t.Fatal("订阅只能合并 proxies，不应带上单个节点的完整客户端配置")
	}

	exported := m.exports[2]
	exported.ClientYAML = strings.Replace(exported.ClientYAML, "name: two", "name: one", 1)
	m.exports[2] = exported
	if _, err := m.panel().InboundYAML([]int{1, 2}, ""); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复节点名必须报错：%v", err)
	}
	exported.ClientYAML = ""
	m.exports[2] = exported
	if _, err := m.panel().InboundYAML([]int{2}, ""); err == nil || !strings.Contains(err.Error(), "没有可导出") {
		t.Fatalf("空 client_yaml 必须报错：%v", err)
	}
}

func TestThreeMUIDeleteRemovesRulesBeforeOutbounds(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "删除", Port: "10001", Enabled: true}
	m.listeners[2] = threeMListener{ID: 2, Name: "保留", Port: "10002", Enabled: true}
	m.routing.Rules = []string{"IN-PORT,10001,fanout-old", "IN-PORT,10002,fanout-keep", "MATCH,DIRECT"}
	m.outbounds["fanout-old"] = threeMProxy{"name": "fanout-old", "type": "socks5"}
	m.outbounds["fanout-keep"] = threeMProxy{"name": "fanout-keep", "type": "socks5"}

	if err := m.panel().DeleteInbounds([]int{1}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.routing.Rules, []string{"IN-PORT,10002,fanout-keep", "MATCH,DIRECT"}) {
		t.Fatalf("失效路由未删除：%v", m.routing.Rules)
	}
	if _, exists := m.outbounds["fanout-old"]; exists {
		t.Fatal("无引用的旧出站应删除")
	}
	if _, exists := m.outbounds["fanout-keep"]; !exists {
		t.Fatal("仍被路由引用的出站位不能删除")
	}
	patchAt, deleteAt := -1, -1
	for i, request := range m.requests {
		if strings.HasPrefix(request, "PATCH /api/v1/config/server-routing") {
			patchAt = i
		}
		if strings.HasPrefix(request, "DELETE /api/v1/config/server-outbounds?name=fanout-old") {
			deleteAt = i
		}
	}
	if patchAt < 0 || deleteAt < 0 || patchAt > deleteAt {
		t.Fatalf("必须先删规则再删出站：%v", m.requests)
	}
	if m.applyCount != 1 {
		t.Fatalf("删除后应 apply 一次：%d", m.applyCount)
	}
	applyAt := -1
	for i, request := range m.requests {
		if request == "POST /api/v1/config/apply" {
			applyAt = i
			break
		}
	}
	if applyAt < 0 || applyAt < deleteAt {
		t.Fatalf("apply 必须在删出站之后：%v", m.requests)
	}
}

func TestManagerReconcileOutboundsUses3MUIBackend(t *testing.T) {
	p := &fakePanel{}
	usePanel(t, p)
	m := NewManager(20, t.TempDir())
	m.tunnels[1] = &Tunnel{Slot: 1, Node: Node{HostName: "jp-home"}, Status: "up"}
	m.ReconcileOutbounds()
	if p.resyncCalls != 1 {
		t.Fatalf("3m-ui 启动恢复后必须对账一次，实际 %d 次", p.resyncCalls)
	}
}

func TestRoutingReferences(t *testing.T) {
	base := func() threeMRouting { return threeMRouting{Rules: []string{"MATCH,DIRECT"}} }
	tests := []struct {
		name   string
		mutate func(*threeMRouting)
	}{
		{"规则", func(c *threeMRouting) { c.Rules = []string{"DOMAIN,example.com,fanout-old"} }},
		{"代理组", func(c *threeMRouting) {
			c.Groups = append(c.Groups, struct {
				Name    string   `json:"name"`
				Proxies []string `json:"proxies"`
			}{Name: "group", Proxies: []string{"fanout-old"}})
		}},
		{"规则提供者", func(c *threeMRouting) {
			c.RuleProviders = append(c.RuleProviders, struct {
				Name  string `json:"name"`
				Proxy string `json:"proxy,omitempty"`
			}{Name: "provider", Proxy: "fanout-old"})
		}},
		{"dialer-proxy", func(c *threeMRouting) {
			c.Proxies = []threeMProxy{{"name": "relay", "dialer-proxy": "fanout-old"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(&cfg)
			if !routingReferences(cfg, "fanout-old") {
				t.Fatal("引用未识别，删除出站会破坏现有 Mihomo 配置")
			}
		})
	}
	if routingReferences(base(), "fanout-old") {
		t.Fatal("无引用时不应阻止清理")
	}
}

func TestThreeMUIBindAppliesAfterRoute(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "入口", Protocol: "vless", Port: "10001", Enabled: true}
	m.routing.Rules = []string{"MATCH,DIRECT"}
	tunnel := &Tunnel{Node: Node{HostName: "us-home"}, Port: 23001, Status: "up", Cred: SocksCred{User: "u", Pass: "p"}}

	if err := m.panel().Bind(listenerTag(1), "us-home", []*Tunnel{tunnel}); err != nil {
		t.Fatal(err)
	}
	if m.applyCount != 1 {
		t.Fatalf("Bind 后应 apply 一次：%d", m.applyCount)
	}
	// 顺序：先同步出站、再写规则，最后才重载内核，避免部分生效。
	outboundAt, patchAt, applyAt := -1, -1, -1
	for i, request := range m.requests {
		switch {
		case strings.HasPrefix(request, "POST /api/v1/config/server-outbounds"):
			outboundAt = i
		case strings.HasPrefix(request, "PATCH /api/v1/config/server-routing"):
			patchAt = i
		case request == "POST /api/v1/config/apply":
			applyAt = i
		}
	}
	if outboundAt < 0 || patchAt < 0 || applyAt < 0 {
		t.Fatalf("缺少关键请求：%v", m.requests)
	}
	if !(outboundAt < patchAt && patchAt < applyAt) {
		t.Fatalf("请求顺序应为 出站→规则→apply：%v", m.requests)
	}
	want := []string{"IN-PORT,10001,fanout-us-home", "MATCH,DIRECT"}
	if !reflect.DeepEqual(m.routing.Rules, want) {
		t.Fatalf("绑定规则不对：%v", m.routing.Rules)
	}
}

// TestProbeThreeMUIURLFromPath 验证从 3m-ui config.yaml 自动探测本地地址的各种分支。
func TestProbeThreeMUIURLFromPath(t *testing.T) {
	writeCfg := func(t *testing.T, content string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "port+web_path",
			content: `
server:
    port: 8080
    web_path: /8a27cdfe1eda567f3593be4e1da527ad
`,
			want: "http://127.0.0.1:8080/8a27cdfe1eda567f3593be4e1da527ad",
		},
		{
			name: "web_path 带首尾斜杠应被清理",
			content: `
server:
    port: 9000
    web_path: /abc/
`,
			want: "http://127.0.0.1:9000/abc",
		},
		{
			name: "无 web_path",
			content: `
server:
    port: 8080
`,
			want: "http://127.0.0.1:8080",
		},
		{
			name: "port 缺失返回空",
			content: `
server:
    web_path: /abc
`,
			want: "",
		},
		{
			name:    "非 YAML 返回空",
			content: "this is: not: valid: yaml: [[[",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probeThreeMUIURLFromPath(writeCfg(t, tt.content))
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}

	// 文件不存在应返回空，而不是 panic
	if got := probeThreeMUIURLFromPath(filepath.Join(t.TempDir(), "nope.yaml")); got != "" {
		t.Fatalf("不存在的文件应返回空，got %q", got)
	}
}
