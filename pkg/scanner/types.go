package scanner

import (
	"context"

	"github.com/tongchengbin/xmap/pkg/types"
)

// Protocol 定义协议类型
type Protocol string

const (
	// TCP 协议
	TCP Protocol = "tcp"
	// UDP 协议
	UDP Protocol = "UDP"
)

// NewTarget 创建新的扫描目标
func NewTarget(ip string, port int, protocol Protocol) *types.ScanTarget {
	return &types.ScanTarget{
		Host:        ip, // 保存原始输入作为 Host
		Port:        port,
		Protocol:    string(protocol),
		StatusCheck: &types.PortStatusCheck{},
	}
}


// Scanner 定义扫描器接口
type Scanner interface {
	// Scan 扫描单个目标
	Scan(target *types.ScanTarget, options ...ScanOption) (*types.ScanResult, error)
	// BatchScan 批量扫描多个目标
	BatchScan(targets []*types.ScanTarget, options ...ScanOption) ([]*types.ScanResult, error)
	// ScanWithContext 带上下文的扫描
	ScanWithContext(ctx context.Context, target *types.ScanTarget, options ...ScanOption) (*types.ScanResult, error)
	// BatchScanWithContext 带上下文的批量扫描
	BatchScanWithContext(ctx context.Context, targets []*types.ScanTarget, options ...ScanOption) ([]*types.ScanResult, error)
}
