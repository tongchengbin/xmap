package types

import (
	"encoding/json"
	"fmt"
	"time"
)

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

// ScanTarget 表示扫描目标
type ScanTarget struct {
	// Web 场景下的协议（http/https），与 Protocol (tcp/udp) 区分
	Scheme string `json:"-"`
	// 原始输入（用户提供的字符串）
	Raw string `json:"raw,omitempty"`
	// 解析后的信息
	Host     string `json:"host,omitempty"`     // 主机名或IP
	IP       string `json:"ip,omitempty"`       // IP地址
	Port     int    `json:"port,omitempty"`     // 端口
	Protocol string `json:"protocol,omitempty"` // 协议 (TCP/UDP)
	Path     string `json:"path,omitempty"`     // URL路径
	// 解析状态，不输出到JSON
	Parsed bool `json:"-"`
	// 状态检查器，用于跟踪连接状态，不输出到JSON
	StatusCheck interface{} `json:"-"`
}

// String 返回目标的字符串表示
func (t *ScanTarget) String() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// ScanResult 表示扫描结果
type ScanResult struct {
	// 目标信息
	Target *ScanTarget `json:"-"`
	// Protocol
	Protocol string `json:"protocol"`
	// 主机名
	Hostname string `json:"hostname"` // 域名或IP
	Port     int    `json:"port"`
	IP       string `json:"ip,omitempty"` // 解析IP，可能为空
	// Web 扫描相关字段
	URL    string                 `json:"url,omitempty"`
	Banner map[string]interface{} `json:"banner,omitempty"`
	// 通用组件信息
	Components []map[string]interface{} `json:"components,omitempty"`
	// 服务名称
	Service string `json:"service"`
	// 是否使用SSL
	SSL bool `json:"ssl"`
	// 附加信息
	Extra       map[string]interface{} `json:"extra,omitempty"`
	RawResponse []byte
	// 匹配的探针名称
	MatchedProbe string `json:"matched_probe"`
	// 匹配的正则表达式
	MatchedPattern string `json:"matched_pattern"`
	// 扫描耗时
	Duration float64 `json:"duration"`
	// 错误信息
	Error error
	// 扫描状态
	Status    ScanStatus `json:"status"`
	startTime time.Time
	endTime   time.Time
}

// NewScanResult 创建新的扫描结果
func NewScanResult(target *ScanTarget) *ScanResult {
	return &ScanResult{
		Target:    target,
		startTime: time.Now(),
		Status:    StatusUnknown,
	}
}

// JSON 返回扫描结果的 JSON 字符串
func (r *ScanResult) JSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(b)
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

// ScanOptions 表示扫描选项
type ScanOptions struct {
	// max timeout
	MaxTimeout int `json:"max_timeout"`
	// 超时时间(秒)
	Timeout int `json:"timeout,omitempty"`
	// 重试次数
	Retries int `json:"retries,omitempty"`
	// 是否使用SSL
	UseSSL bool `json:"use_ssl,omitempty"`
	// 版本检测强度(0-9)
	VersionIntensity int `json:"version_intensity,omitempty"`
	// 是否进行主机发现
	HostDiscovery bool `json:"host_discovery,omitempty"`
	// 最大并行扫描数
	MaxParallelism int `json:"max_parallelism,omitempty"`
	// 指定要使用的探针名称
	ProbeNames []string `json:"probe_names,omitempty"`
	// 指定要使用的端口
	Ports []int `json:"ports,omitempty"`
	// 是否使用所有探针
	UseAllProbes bool `json:"use_all_probes,omitempty"`
	// 是否使用快速模式（只使用常用探针）
	FastMode bool `json:"fast_mode,omitempty"`
	// 是否使用服务检测
	ServiceDetection bool `json:"service_detection,omitempty"`
	// 是否使用版本检测
	VersionDetection bool `json:"version_detection,omitempty"`
	// 是否使用操作系统检测
	OSDetection bool `json:"os_detection,omitempty"`
	// 是否使用设备类型检测
	DeviceTypeDetection bool `json:"device_type_detection,omitempty"`
	// 是否使用主机名检测
	HostnameDetection bool `json:"hostname_detection,omitempty"`
	// 是否使用产品名称检测
	ProductNameDetection bool `json:"product_name_detection,omitempty"`
	// 是否使用信息检测
	InfoDetection bool `json:"info_detection,omitempty"`

	// Web扫描相关选项
	// HTTP代理
	Proxy string `json:"proxy,omitempty"`
	// 是否禁用图标请求匹配
	DisableIcon bool `json:"disable_icon,omitempty"`
	// 是否禁用JavaScript规则匹配
	DisableJS bool `json:"disable_js,omitempty"`
	// 是否调试HTTP响应
	DebugResponse bool `json:"debug_response,omitempty"`
}
