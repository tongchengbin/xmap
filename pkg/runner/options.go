package runner

import "github.com/projectdiscovery/goflags"

// Options 包含所有命令行选项
type Options struct {
	// 版本和Banner
	Version string
	Banner  string

	// 目标参数
	Target     goflags.StringSlice
	TargetFile string
	Ports      string

	// 扫描选项
	Timeout          int
	Retries          int
	Workers          int
	FastMode         bool
	UseAllProbes     bool
	NmapProneName    goflags.StringSlice
	UseSSL           bool
	VersionIntensity int
	ServiceVersion   bool // 是否探测服务版本
	VersionTrace     bool // 是否跟踪版本

	// Web扫描选项
	AppFingerHome       string
	UpdateAppFingerRule bool
	Proxy               string
	DisableIcon         bool
	DisableJS           bool
	DebugResponse       bool

	// 输出选项
	Output     string
	OutType    string
	Verbose    bool
	Silent     bool
	NoProgress bool

	// 其他选项
	EnablePprof bool
}
