package options

import (
	"fmt"
	"time"
)

// ScanOptions 包含单次扫描的特定配置
type ScanOptions struct {
	// 扫描超时选项
	Timeout          time.Duration // 单个探针超时时间
	MaxTimeout       time.Duration // 单个端口识别最大超时时间
	Retries          int           // 重试次数
	
	// 并发选项
	MaxParallelism   int           // 最大并行扫描数
	
	// 目标选项
	Ports            []int         // 要扫描的端口列表
	
	// 探针选项
	ProbeNames       []string      // 指定要使用的探针名称
	UseAllProbes     bool          // 是否使用所有探针
	FastMode         bool          // 是否使用快速模式（只使用常用探针）
	
	// 检测选项
	HostDiscovery    bool          // 是否进行主机发现
	ServiceDetection bool          // 是否使用服务检测
	VersionDetection bool          // 是否使用版本检测
	VersionIntensity int           // 版本检测强度(0-9)
	OSDetection      bool          // 是否使用操作系统检测
	DeviceTypeDetection bool       // 是否使用设备类型检测
	HostnameDetection bool         // 是否使用主机名检测
	ProductNameDetection bool      // 是否使用产品名称检测
	InfoDetection    bool          // 是否使用信息检测
	
	// 调试选项
	DebugRequest     bool          // 是否打印请求数据
	DebugResponse    bool          // 是否打印响应数据
	VersionTrace     bool          // 是否跟踪版本检测过程
	
	// 网络选项
	UseSSL           bool          // 是否使用SSL
}

// DefaultScanOptions 返回默认扫描选项
func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		Timeout:          6 * time.Second,
		MaxTimeout:       180 * time.Second,
		Retries:          2,
		MaxParallelism:   100,
		
		UseAllProbes:     false,
		FastMode:         true,
		
		HostDiscovery:    true,
		ServiceDetection: true,
		VersionDetection: true,
		VersionIntensity: 7,
		OSDetection:      true,
		DeviceTypeDetection: true,
		HostnameDetection: true,
		ProductNameDetection: true,
		InfoDetection:    true,
		
		DebugRequest:     false,
		DebugResponse:    false,
		VersionTrace:     false,
		
		UseSSL:           false,
	}
}

// Validate 验证扫描选项是否有效
func (o *ScanOptions) Validate() error {
	// 验证超时时间
	if o.Timeout <= 0 {
		return fmt.Errorf("超时时间必须大于0")
	}
	
	// 验证重试次数
	if o.Retries < 0 {
		return fmt.Errorf("重试次数不能为负数")
	}
	
	// 验证并行度
	if o.MaxParallelism <= 0 {
		return fmt.Errorf("最大并行扫描数必须大于0")
	}
	
	// 验证版本检测强度
	if o.VersionIntensity < 0 || o.VersionIntensity > 9 {
		return fmt.Errorf("版本检测强度必须在0-9之间")
	}
	
	return nil
}

// Clone 创建扫描选项的深拷贝
func (o *ScanOptions) Clone() *ScanOptions {
	clone := &ScanOptions{}
	*clone = *o
	
	// 深拷贝切片
	if o.Ports != nil {
		clone.Ports = make([]int, len(o.Ports))
		copy(clone.Ports, o.Ports)
	}
	
	if o.ProbeNames != nil {
		clone.ProbeNames = make([]string, len(o.ProbeNames))
		copy(clone.ProbeNames, o.ProbeNames)
	}
	
	return clone
}

// ScanOption 扫描选项函数类型
type ScanOption func(*ScanOptions)

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		o.Timeout = timeout
	}
}

// WithMaxTimeout 设置最大超时时间
func WithMaxTimeout(maxTimeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		o.MaxTimeout = maxTimeout
	}
}

// WithRetries 设置重试次数
func WithRetries(retries int) ScanOption {
	return func(o *ScanOptions) {
		if retries < 0 {
			retries = 0
		}
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

// WithVersionTrace 设置是否跟踪版本检测过程
func WithVersionTrace(versionTrace bool) ScanOption {
	return func(o *ScanOptions) {
		o.VersionTrace = versionTrace
	}
}

// WithUseSSL 设置是否使用SSL
func WithUseSSL(useSSL bool) ScanOption {
	return func(o *ScanOptions) {
		o.UseSSL = useSSL
	}
}

// Apply 应用选项
func (o *ScanOptions) Apply(options ...ScanOption) {
	for _, option := range options {
		option(o)
	}
}
