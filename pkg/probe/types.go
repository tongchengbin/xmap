package probe

import (
	"time"

	"github.com/dlclark/regexp2"
)

// 定义协议类型常量
const (
	// TCP 协议
	TCP = "tcp"
	// UDP 协议
	UDP = "udp"
)

// FingerprintOptions 指纹库配置选项
type FingerprintOptions struct {
	// 指纹文件路径（可选，默认使用内置指纹）
	ProbeFilePath string
	// 版本检测强度(0-9)
	VersionIntensity int
}

// VersionInfo 表示版本信息
type VersionInfo struct {
	// 产品名称
	ProductName string
	// 版本号
	Version string
	// 附加信息
	Info string
	// 主机名
	Hostname string
	// 操作系统
	OS string
	// 设备类型
	DeviceType string
	// CPE标识符
	CPE []string
}

// Probe 表示一个服务探针
type Probe struct {
	// 探针名称
	Name string
	// 探针适用的默认端口
	Ports []int
	// 探针适用的SSL端口
	SSLPorts []int
	// 探针总等待时间
	TotalWaitMS time.Duration
	// TCP包装等待时间
	TCPWrappedMS time.Duration
	// 探针稀有度（值越小优先级越高）
	Rarity int
	// 使用字符串表示协议类型
	Protocol string
	// 探针发送数据
	SendData []byte
	// 匹配组
	MatchGroup []*Match
	// 回退探针名称
	Fallback []string
	// 回退探针引用
	FallbackProbes []*Probe
	// 探针的匹配超时时间
	MatchTimeout time.Duration
}

// Match 表示一个匹配规则
type Match struct {
	// 行号
	Line int
	// 是否为软匹配
	Soft bool
	// 服务名称
	Service string
	// 匹配模式
	Pattern string
	// 编译后的正则表达式
	regex *regexp2.Regexp
	// 版本信息
	VersionInfo *VersionInfo
}

type MatchResult struct {
	// 匹配的探针
	Probe *Probe
	// 匹配的规则
	Match *Match
	// 提取的版本信息
	VersionInfo map[string]interface{}
	// 是否通过fallback匹配
	IsFallback bool
	// fallback链路径（如果是通过fallback匹配的）
	FallbackPath []string
	// 原始响应数据
	Response []byte
}
