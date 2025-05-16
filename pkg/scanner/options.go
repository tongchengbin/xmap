package scanner

import (
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
	Proxy   string
}

// DefaultScanOptions 返回默认扫描选项
func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		MaxTimeout:           180 * time.Second,
		Timeout:              6 * time.Second,
		Retries:              2,
		VersionIntensity:     7,
		HostDiscovery:        true,
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

// ScanOption 扫描选项函数类型
type ScanOption func(*ScanOptions)

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		o.Timeout = timeout
	}
}

// WithRetries 设置重试次数
func WithRetries(retries int) ScanOption {
	return func(o *ScanOptions) {
		o.Retries = retries
	}
}

// WithVersionIntensity 设置版本检测强度
func WithVersionIntensity(intensity int) ScanOption {
	return func(o *ScanOptions) {
		if intensity < 0 {
			intensity = 0
		}
		if intensity > 9 {
			intensity = 9
		}
		o.VersionIntensity = intensity
	}
}

// WithHostDiscovery 设置是否进行主机发现
func WithHostDiscovery(hostDiscovery bool) ScanOption {
	return func(o *ScanOptions) {
		o.HostDiscovery = hostDiscovery
	}
}

// WithMaxParallelism 设置最大并行扫描数
func WithMaxParallelism(maxParallelism int) ScanOption {
	return func(o *ScanOptions) {
		if maxParallelism < 1 {
			maxParallelism = 1
		}
		o.MaxParallelism = maxParallelism
	}
}

// WithProbeNames 设置要使用的探针名称
func WithProbeNames(probeNames []string) ScanOption {
	return func(o *ScanOptions) {
		o.ProbeNames = probeNames
	}
}

// WithPorts 设置要扫描的端口
func WithPorts(ports []int) ScanOption {
	return func(o *ScanOptions) {
		o.Ports = ports
	}
}

// WithAllProbes 设置是否使用所有探针
func WithAllProbes(useAllProbes bool) ScanOption {
	return func(o *ScanOptions) {
		o.UseAllProbes = useAllProbes
	}
}

// WithFastMode 设置是否使用快速模式
func WithFastMode(fastMode bool) ScanOption {
	return func(o *ScanOptions) {
		o.FastMode = fastMode
	}
}

// WithServiceDetection 设置是否使用服务检测
func WithServiceDetection(serviceDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.ServiceDetection = serviceDetection
	}
}

// WithVersionDetection 设置是否使用版本检测
func WithVersionDetection(versionDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.VersionDetection = versionDetection
	}
}

// WithOSDetection 设置是否使用操作系统检测
func WithOSDetection(osDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.OSDetection = osDetection
	}
}

// WithDeviceTypeDetection 设置是否使用设备类型检测
func WithDeviceTypeDetection(deviceTypeDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.DeviceTypeDetection = deviceTypeDetection
	}
}

// WithHostnameDetection 设置是否使用主机名检测
func WithHostnameDetection(hostnameDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.HostnameDetection = hostnameDetection
	}
}

// WithProductNameDetection 设置是否使用产品名称检测
func WithProductNameDetection(productNameDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.ProductNameDetection = productNameDetection
	}
}

// WithInfoDetection 设置是否使用信息检测
func WithInfoDetection(infoDetection bool) ScanOption {
	return func(o *ScanOptions) {
		o.InfoDetection = infoDetection
	}
}

// WithDebugRequest 设置是否打印请求数据
func WithDebugRequest(debugRequest bool) ScanOption {
	return func(o *ScanOptions) {
		o.DebugRequest = debugRequest
	}
}

// WithDebugResponse 设置是否打印响应数据
func WithDebugResponse(debugResponse bool) ScanOption {
	return func(o *ScanOptions) {
		o.DebugResponse = debugResponse
	}
}

// WithVerbose 设置是否打印详细的调试信息
func WithVerbose(verbose bool) ScanOption {
	return func(o *ScanOptions) {
		o.Verbose = verbose
	}
}

// WithProxy
func WithProxy(proxy string) ScanOption {
	return func(o *ScanOptions) {
		o.Proxy = proxy
	}
}
