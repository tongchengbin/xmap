package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Protocol 定义协议类型
type Protocol string

const (
	// TCP 协议
	TCP Protocol = "tcp"
	// UDP 协议
	UDP Protocol = "UDP"
)

// Target 表示扫描目标
type Target struct {
	// IP地址
	IP string
	// 端口
	Port int
	// 协议
	Protocol Protocol
	// 状态检查器，用于跟踪连接状态
	StatusCheck *PortStatusCheck
}

func (t *Target) String() string {
	return fmt.Sprintf("%s:%d", t.IP, t.Port)
}

// NewTarget 创建新的扫描目标
func NewTarget(ip string, port int, protocol Protocol) *Target {
	return &Target{
		IP:          ip,
		Port:        port,
		Protocol:    protocol,
		StatusCheck: &PortStatusCheck{},
	}
}

// ParseTarget 解析目标字符串，格式为 ip:port 或 ip:port/protocol
func ParseTarget(target string, defaultProtocol Protocol) (*Target, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}

	portInt, err := net.LookupPort(string(defaultProtocol), port)
	if err != nil {
		return nil, err
	}

	return NewTarget(host, portInt, defaultProtocol), nil
}

// ScanStatus 扫描结果状态
type ScanStatus int

const (
	StatusUnknown ScanStatus = iota
	StatusMatched
	StatusNoMatch
	StatusError
	StatusClosed
	StatusInvalid    // 无效目标（如连续多次连接失败）
	StatusFirewalled // 可能被防火墙阻止
)

// ScanResult 表示扫描结果
type ScanResult struct {
	// 目标信息
	Target *Target
	// 服务名称
	Service string
	// 附加信息
	Extra map[string]interface{}
	// 主机名
	Hostname    string
	RawResponse []byte
	// 匹配的探针名称
	MatchedProbe string
	// 匹配的正则表达式
	MatchedPattern string
	// 扫描耗时
	Duration float64
	// 错误信息
	Error error
	// 扫描状态
	Status ScanStatus

	startTime time.Time
	endTime   time.Time
}

// NewScanResult 创建新的扫描结果
func NewScanResult(target *Target) *ScanResult {
	return &ScanResult{
		Target:    target,
		startTime: time.Now(),
		Status:    StatusUnknown,
	}
}

// Complete 完成扫描结果
func (r *ScanResult) Complete(err error) {
	r.Error = err
	r.endTime = time.Now()
	r.Duration = r.endTime.Sub(r.startTime).Seconds()

	// 根据错误类型设置状态
	if err != nil {
		if err.Error() == "invalid target" {
			r.Status = StatusInvalid
		} else {
			r.Status = StatusError
		}
	} else if r.Service != "" {
		r.Status = StatusMatched
	} else {
		r.Status = StatusNoMatch
	}
}

// SetMatchResult 设置匹配结果
func (r *ScanResult) SetMatchResult(probeName, service, pattern string, softMatch bool) {
	r.MatchedProbe = probeName
	r.MatchedPattern = pattern
}

// Scanner 定义扫描器接口
type Scanner interface {
	// Scan 扫描单个目标
	Scan(target *Target, options ...ScanOption) (*ScanResult, error)
	// BatchScan 批量扫描多个目标
	BatchScan(targets []*Target, options ...ScanOption) ([]*ScanResult, error)
	// ScanWithContext 带上下文的扫描
	ScanWithContext(ctx context.Context, target *Target, options ...ScanOption) (*ScanResult, error)
	// BatchScanWithContext 带上下文的批量扫描
	BatchScanWithContext(ctx context.Context, targets []*Target, options ...ScanOption) ([]*ScanResult, error)
}
