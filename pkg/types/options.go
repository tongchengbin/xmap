package types

import (
	"github.com/projectdiscovery/goflags"
)

// Options 包含XMap全局初始化选项
type Options struct {
	// target
	Target     goflags.StringSlice
	TargetFile string
	Ports      string

	// scan
	// 扫描选项
	Timeout          int
	Retries          int
	Threads          int
	FastMode         bool
	UseAllProbes     bool
	NmapProneName    goflags.StringSlice
	UseSSL           bool
	VersionIntensity int
	ServiceVersion   bool // 是否探测服务版本
	VersionTrace     bool // 是否跟踪版本

	// 基本选项
	Verbose    bool // 是否打印详细的调试信息
	Silent     bool // 是否启用静默模式
	NoProgress bool // 是否不显示进度条

	// 网络选项
	Proxy string // 代理设置

	// 指纹库选项
	AppFingerHome string // 指纹库路径
	UpdateRule    bool   // 是否更新指纹规则

	// Web扫描选项
	DisableIcon bool // 禁用图标请求匹配
	DisableJS   bool // 禁用JavaScript规则匹配

	// 输出选项
	Output     string // 输出文件路径
	OutputType string // 输出格式 (json, csv, console)

	// 其他选项
	EnablePprof bool // 是否启用性能分析

	// 版本信息
	Version             string // 版本信息
	Banner              string // Banner信息
	UpdateAppFingerRule bool   // 是否更新指纹规则
	DebugResponse       bool   // 是否打印响应数据
	OutType             string // 输出格式
}

func DefaultOptions() *Options {
	return &Options{
		Verbose:    false,
		Silent:     false,
		NoProgress: false,
		OutputType: "json",
		Version:    "",
		Banner:     "",
	}
}
