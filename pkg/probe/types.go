package probe

// Protocol 定义协议类型
type Protocol string

const (
	// TCP 协议
	TCP Protocol = "TCP"
	// UDP 协议
	UDP Protocol = "UDP"
)

// FingerprintOptions 指纹库配置选项
type FingerprintOptions struct {
	// 指纹文件路径（可选，默认使用内置指纹）
	ProbeFilePath string
	// 版本检测强度(0-9)
	VersionIntensity int
}

func (o *FingerprintOptions) Equals(other *FingerprintOptions) bool {
	return o.ProbeFilePath == other.ProbeFilePath && o.VersionIntensity == other.VersionIntensity
}

// ProbeSource 定义探针数据源接口
type ProbeSource interface {
	// Load 加载探针数据
	Load() (string, error)
	// GetVersion 获取探针数据版本
	GetVersion() string
}

// FileProbeSource 从文件加载探针数据
type FileProbeSource struct {
	FilePath string
	Version  string
}

// EmbeddedProbeSource 从嵌入资源加载探针数据
type EmbeddedProbeSource struct {
	Data    string
	Version string
}

// Load 从嵌入资源加载探针数据
func (s *EmbeddedProbeSource) Load() (string, error) {
	return s.Data, nil
}

// GetVersion 获取探针数据版本
func (s *EmbeddedProbeSource) GetVersion() string {
	return s.Version
}
