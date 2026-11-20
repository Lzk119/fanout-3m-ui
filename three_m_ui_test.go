package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	tunnel := &Tunnel{Node: Node{HostName: "jp-home", CountryCode: "JP"}, Port: 23000, Status: "up", Cred: SocksCred{User: "u", Pass: "p"}}

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
	wantRule := fmt.Sprintf("IN-NAME,%s,%s", m.listeners[3].Name, tunnelTag(tunnel))
	if !reflect.DeepEqual(m.routing.Rules, []string{wantRule, "MATCH,DIRECT"}) {
		t.Fatalf("IN-NAME 应插到最顶部：%v", m.routing.Rules)
	}
	proxy := m.outbounds["🇯🇵 日本-fanout-23000"]
	if proxy["server"] != "127.0.0.1" || proxy["username"] != "u" || proxy["password"] != "p" {
		t.Fatalf("SOCKS5 出站不对：%v", proxy)
	}
	if m.applyCount != 1 {
		t.Fatalf("批量克隆后应只 apply 一次：%d", m.applyCount)
	}
}

func TestThreeMUIUpdateInboundRenamesRuleInbound(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "旧名", Protocol: "vless", Port: "10001", Enabled: true}
	outbound := "🇯🇵 日本-fanout-23000"
	m.routing.Rules = []string{fmt.Sprintf("IN-NAME,旧名,%s", outbound), "MATCH,DIRECT"}
	// 改备注：应同步更新 IN-NAME 规则的入站名，出站保持不变
	newName := "新名"
	if err := m.panel().UpdateInbound(1, InboundPatch{Remark: &newName}, nil); err != nil {
		t.Fatal(err)
	}
	if m.listeners[1].Name != "新名" {
		t.Fatalf("Listener 名称未更新：%+v", m.listeners[1])
	}
	want := []string{fmt.Sprintf("IN-NAME,新名,%s", outbound), "MATCH,DIRECT"}
	if !reflect.DeepEqual(m.routing.Rules, want) {
		t.Fatalf("入站名未同步到规则：%v", m.routing.Rules)
	}
	// 仅改端口不依赖入站名，不应变动 IN-NAME 规则
	newPort := 12000
	if err := m.panel().UpdateInbound(1, InboundPatch{Port: &newPort}, nil); err != nil {
		t.Fatal(err)
	}
	if m.listeners[1].Port != "12000" {
		t.Fatalf("端口未更新：%+v", m.listeners[1])
	}
	if !reflect.DeepEqual(m.routing.Rules, want) {
		t.Fatalf("改端口不应变动规则：%v", m.routing.Rules)
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
	m.routing.Rules = []string{"IN-NAME,删除,fanout-old", "IN-NAME,保留,fanout-keep", "MATCH,DIRECT"}
	m.outbounds["fanout-old"] = threeMProxy{"name": "fanout-old", "type": "socks5"}
	m.outbounds["fanout-keep"] = threeMProxy{"name": "fanout-keep", "type": "socks5"}
	// 新格式出站（国旗-fanout-端口），无规则引用，应被识别并清理
	m.outbounds["🇯🇵 日本-fanout-99999"] = threeMProxy{"name": "🇯🇵 日本-fanout-99999", "type": "socks5"}

	if err := m.panel().DeleteInbounds([]int{1}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.routing.Rules, []string{"IN-NAME,保留,fanout-keep", "MATCH,DIRECT"}) {
		t.Fatalf("失效入站的规则未删除：%v", m.routing.Rules)
	}
	if _, exists := m.outbounds["fanout-old"]; exists {
		t.Fatal("无引用的旧出站应删除")
	}
	if _, exists := m.outbounds["fanout-keep"]; !exists {
		t.Fatal("仍被路由引用的出站位不能删除")
	}
	if _, exists := m.outbounds["🇯🇵 日本-fanout-99999"]; exists {
		t.Fatal("新格式无引用出站应被识别并删除")
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
	tunnel := &Tunnel{Node: Node{HostName: "us-home", CountryCode: "US"}, Port: 23001, Status: "up", Cred: SocksCred{User: "u", Pass: "p"}}

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
	want := []string{
		fmt.Sprintf("IN-NAME,入口,%s", tunnelTag(tunnel)),
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(m.routing.Rules, want) {
		t.Fatalf("绑定规则不对：%v", m.routing.Rules)
	}
}

// TestUnescapeFlagEmoji 验证历史遗留的 \Uxxxxxxxx 字面规则能还原为真实 emoji，非转义字符串保持不变。
func TestUnescapeFlagEmoji(t *testing.T) {
	in := "\\U0001F1ED\\U0001F1F0 香港 Hy2 → \\U0001F1EF\\U0001F1F5 日本"
	want := "🇭🇰 香港 Hy2 → 🇯🇵 日本"
	if got := unescapeFlagEmoji(in); got != want {
		t.Fatalf("还原不对：got %q want %q", got, want)
	}
	// 非转义字符串保持不变
	if unescapeFlagEmoji("日本-fanout-23000") != "日本-fanout-23000" {
		t.Fatal("非转义字符不应被改动")
	}
}

// TestThreeMUIBindCleansLegacyInPort 验证绑定时清理历史 IN-PORT 残留、保留其他入站的 IN-NAME、新规则置顶。
func TestThreeMUIBindCleansLegacyInPort(t *testing.T) {
	m := newThreeMMock(t)
	m.listeners[1] = threeMListener{ID: 1, Name: "入口A", Protocol: "vless", Port: "10001", Enabled: true}
	m.listeners[2] = threeMListener{ID: 2, Name: "入口B", Protocol: "vless", Port: "10002", Enabled: true}
	// 历史 IN-PORT 残留 + 其他入站已有的 IN-NAME 绑定 + 用户自建规则
	m.routing.Rules = []string{
		"IN-PORT,10001,fanout-legacy",
		"IN-NAME,入口B,fanout-other",
		"DOMAIN,example.com,DIRECT",
		"MATCH,DIRECT",
	}
	tunnel := &Tunnel{Node: Node{HostName: "jp-home", CountryCode: "JP"}, Port: 23000, Status: "up"}
	if err := m.panel().Bind(listenerTag(1), "jp-home", []*Tunnel{tunnel}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		fmt.Sprintf("IN-NAME,入口A,%s", tunnelTag(tunnel)),
		"IN-NAME,入口B,fanout-other",
		"DOMAIN,example.com,DIRECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(m.routing.Rules, want) {
		t.Fatalf("规则清理/置顶不对：%v", m.routing.Rules)
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

// portFromURL 从 httptest server URL 中提取端口，供探测测试使用。
func portFromURL(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析 URL 失败: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("提取端口失败: %v", err)
	}
	return p
}

// TestListenPortsFromFiles 验证从 /proc/net/tcp 风格内容解析 LISTEN 端口（hex），非 0A 状态跳过。
func TestListenPortsFromFiles(t *testing.T) {
	dir := t.TempDir()
	tcp := filepath.Join(dir, "tcp")
	// 模拟 /proc/net/tcp：表头 + 若干行，只有状态 0A 的本地端口被收集
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	content += "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" // 443 LISTEN
	content += "   1: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n" // 9090 LISTEN
	content += "   2: 00000000:0050 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0\n" // 80 非 LISTEN，跳过
	if err := os.WriteFile(tcp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := listenPortsFromFiles([]string{tcp, filepath.Join(dir, "missing")})
	want := []int{443, 9090}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := listenPortsFromFiles(nil); len(got) != 0 {
		t.Fatalf("空列表应返回空, got %v", got)
	}
}

// TestProbeReachableURL 验证连通性探测：优先 https、2xx/3xx 算可达、4xx/连接失败不算。
func TestProbeReachableURL(t *testing.T) {
	httpsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpsSrv.Close()
	httpsPort := portFromURL(t, httpsSrv.URL)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()
	httpPort := portFromURL(t, httpSrv.URL)

	// 同时含 https 与 http 端口时，应优先返回 https
	if got := probeReachableURL([]int{httpsPort, httpPort}, "wp"); got != fmt.Sprintf("https://127.0.0.1:%d/wp", httpsPort) {
		t.Fatalf("优先 https 失败: got %q", got)
	}
	// 仅 http 端口
	if got := probeReachableURL([]int{httpPort}, "wp"); got != fmt.Sprintf("http://127.0.0.1:%d/wp", httpPort) {
		t.Fatalf("http 失败: got %q", got)
	}
	// https 即使在候选顺序后面也应优先于 http
	if got := probeReachableURL([]int{httpPort, httpsPort}, "wp"); got != fmt.Sprintf("https://127.0.0.1:%d/wp", httpsPort) {
		t.Fatalf("https 应优先即使顺序在后: got %q", got)
	}

	// 3xx 也算可达
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}))
	defer redirSrv.Close()
	redirPort := portFromURL(t, redirSrv.URL)
	if got := probeReachableURL([]int{redirPort}, ""); got != fmt.Sprintf("http://127.0.0.1:%d", redirPort) {
		t.Fatalf("3xx 应算可达: got %q", got)
	}

	// 4xx 不算可达
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer badSrv.Close()
	badPort := portFromURL(t, badSrv.URL)
	if got := probeReachableURL([]int{badPort}, ""); got != "" {
		t.Fatalf("4xx 不应算可达: got %q", got)
	}
	// 无服务端口应返回空
	if got := probeReachableURL([]int{1}, ""); got != "" {
		t.Fatalf("无服务端口应返回空: got %q", got)
	}
}

// TestProbeThreeMUIURLLiveFromConfig 验证 live 探测编排：候选端口组装 + 先 https 后 http 的两轮顺序。
func TestProbeThreeMUIURLLiveFromConfig(t *testing.T) {
	origListen := listenPortsFn
	origHTTP := httpProbeStatus
	defer func() {
		listenPortsFn = origListen
		httpProbeStatus = origHTTP
	}()

	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("server:\n  port: 8080\n  web_path: /wp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 监听端口 [80, 443]，config port 8080 追加 → 候选 [80, 443, 8080]
	listenPortsFn = func() []int { return []int{80, 443} }
	var calls []string
	httpProbeStatus = func(u string, insecure bool) (int, error) {
		calls = append(calls, u)
		if u == "https://127.0.0.1:443/wp" {
			return http.StatusMovedPermanently, nil // 301 应算可达
		}
		return 0, fmt.Errorf("connection refused")
	}

	got := probeThreeMUIURLLiveFromConfig(cfg)
	if got != "https://127.0.0.1:443/wp" {
		t.Fatalf("got %q, want https://127.0.0.1:443/wp; calls=%v", got, calls)
	}
	// 应先测完所有 https 端口再碰 http：80(https) 失败、443(https) 命中即停
	if len(calls) != 2 || calls[0] != "https://127.0.0.1:80/wp" || calls[1] != "https://127.0.0.1:443/wp" {
		t.Fatalf("探测顺序不对，应先 https 全量: %v", calls)
	}
}
