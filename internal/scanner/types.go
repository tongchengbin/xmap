package scanner

import (
	"context"
	"net"
	"time"
)

// Protocol 定义协议类型
type Protocol string

const (
	// TCP 协议
	TCP Protocol = "TCP"
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
	// 是否使用SSL
	UseSSL bool
}

// NewTarget 创建新的扫描目标
func NewTarget(ip string, port int, protocol Protocol, useSSL bool) *Target {
	return &Target{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		UseSSL:   useSSL,
	}
}

// ParseTarget 解析目标字符串，格式为 ip:port 或 ip:port/protocol
func ParseTarget(target string, defaultProtocol Protocol, useSSL bool) (*Target, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}

	portInt, err := net.LookupPort(string(defaultProtocol), port)
	if err != nil {
		return nil, err
	}

	return NewTarget(host, portInt, defaultProtocol, useSSL), nil
}

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

	startTime time.Time
	endTime   time.Time
}

// NewScanResult 创建新的扫描结果
func NewScanResult(target *Target) *ScanResult {
	return &ScanResult{
		Target:    target,
		startTime: time.Now(),
	}
}

// Complete 完成扫描结果
func (r *ScanResult) Complete(err error) {
	r.Error = err
	r.endTime = time.Now()
	r.Duration = r.endTime.Sub(r.startTime).Seconds()
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
