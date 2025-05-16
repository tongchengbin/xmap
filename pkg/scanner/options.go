package scanner

import (
	"net/url"
	"time"
)

// ScanOptions 扫描选项
type ScanOptions struct {
	// 单个端口识别最大超时时间
	MaxTimeout time.Duration
	// 超时时间 单个探针
	Timeout time.Duration
	// 重试次数
	Retries int
	// 版本检测强度(0-9)
	VersionIntensity int
	// 是否进行主机发现
	HostDiscovery bool
	// 最大并行扫描数
	MaxParallelism int
	// 指定要使用的探针名称
	ProbeNames []string
	// 指定要使用的端口
	Ports []int
	// 是否使用所有探针
	UseAllProbes bool
	// 是否使用快速模式（只使用常用探针）
	FastMode bool
	// 是否使用服务检测
	ServiceDetection bool
	// 是否使用版本检测
	VersionDetection bool
	// 是否使用操作系统检测
	OSDetection bool
	// 是否使用设备类型检测
	DeviceTypeDetection bool
	// 是否使用主机名检测
	HostnameDetection bool
	// 是否使用产品名称检测
	ProductNameDetection bool
	// 是否使用信息检测
	InfoDetection bool
	// 是否打印请求数据
	DebugRequest bool
	// 是否打印响应数据
	DebugResponse bool
	// 是否打印详细的调试信息
	Verbose bool
	Proxy   *url.URL
}

// DefaultScanOptions 返回默认扫描选项
func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		MaxTimeout:           180 * time.Second,
		Timeout:              6 * time.Second,
		Retries:              2,
		VersionIntensity:     7,
		MaxParallelism:       100,
		UseAllProbes:         false,
		FastMode:             true,
		ServiceDetection:     true,
		VersionDetection:     true,
		OSDetection:          true,
		DeviceTypeDetection:  true,
		HostnameDetection:    true,
		ProductNameDetection: true,
		InfoDetection:        true,
		DebugRequest:         false,
		DebugResponse:        false,
		Verbose:              false,
	}
}
