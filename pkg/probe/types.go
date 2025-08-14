package probe

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
