package main

import "sync"

// Panel 定义 fanout 管理 3m-ui Listener、用户和 Mihomo 路由所需的操作。
type Panel interface {
	Kind() string
	Describe() string

	Inbounds(live map[string]bool, tunnels []*Tunnel) ([]Inbound, error)
	InboundDetail(id int, publicHost string, tunnels []*Tunnel) (*InboundDetail, error)
	InboundLinks(ids []int, publicHost string) ([]string, error)
	InboundYAML(ids []int, publicHost string) (string, error)

	Bind(inboundTag string, hostname string, tunnels []*Tunnel) error
	Rebind(oldHost string, target *Tunnel, tunnels []*Tunnel) error
	ResyncOutbound(t *Tunnel, tunnels []*Tunnel) error

	CloneToTunnels(templateID int, hosts []string, tunnels []*Tunnel) ([]int, error)
	DeleteInbounds(ids []int, tunnels []*Tunnel) error
	CreateInbound(spec NewInboundSpec, tunnels []*Tunnel) (*CreatedInbound, error)
	UpdateInbound(id int, patch InboundPatch, tunnels []*Tunnel) error

	AddClient(id int, email string, tunnels []*Tunnel) error
	DeleteClient(id int, email string, tunnels []*Tunnel) error
	ResetClient(id int, email string, tunnels []*Tunnel) error

	OnTunnelsChanged(tunnels []*Tunnel) error
	Close()
}

// InboundPatch 描述对 Listener 的一次局部修改，nil 表示该字段不动。
type InboundPatch struct {
	Port   *int
	Remark *string
	Enable *bool
}

// CreatedInbound 是新建 Listener 后回给界面的摘要。
type CreatedInbound struct {
	ID       int    `json:"id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Remark   string `json:"remark"`
}

var panelState struct {
	mu      sync.Mutex
	current Panel
	workDir string
}

func configurePanel(workDir string) {
	panelState.mu.Lock()
	defer panelState.mu.Unlock()
	panelState.workDir = workDir
	panelState.current = nil
}

// openPanel 缓存唯一的 3m-ui 后端，避免每个请求重复读取配置。
func openPanel() (Panel, error) {
	panelState.mu.Lock()
	defer panelState.mu.Unlock()
	if panelState.current != nil {
		return panelState.current, nil
	}
	p, err := openThreeMUI(panelState.workDir)
	if err != nil {
		return nil, err
	}
	panelState.current = p
	return p, nil
}

func closePanel() {
	panelState.mu.Lock()
	p := panelState.current
	panelState.mu.Unlock()
	if p != nil {
		p.Close()
	}
}
