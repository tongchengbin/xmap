package options

import (
	"fmt"
	"time"
)

// Options 包含XMap全局初始化选项
type Options struct {
	// 基本选项
	Verbose          bool          // 是否打印详细的调试信息
	Silent           bool          // 是否启用静默模式
	NoProgress       bool          // 是否不显示进度条
	
	// 网络选项
	Proxy            string        // 代理设置
	
	// 指纹库选项
	AppFingerHome    string        // 指纹库路径
	UpdateRule       bool          // 是否更新指纹规则
	
	// Web扫描选项
	DisableIcon      bool          // 禁用图标请求匹配
	DisableJS        bool          // 禁用JavaScript规则匹配
	
	// 输出选项
	Output           string        // 输出文件路径
	OutputType       string        // 输出格式 (json, csv, console)
	
	// 其他选项
	EnablePprof      bool          // 是否启用性能分析
	
	// 版本信息
	Version          string        // 版本信息
	Banner           string        // Banner信息
}

// DefaultOptions 返回默认全局选项
func DefaultOptions() *Options {
	return &Options{
		Verbose:          false,
		Silent:           false,
		NoProgress:       false,
		OutputType:       "json",
		Version:          "",
		Banner:           "",
	}
}

// Validate 验证全局选项是否有效
func (o *Options) Validate() error {
	// 验证输出格式
	if o.OutputType != "" && o.OutputType != "json" && o.OutputType != "csv" && o.OutputType != "console" {
		return fmt.Errorf("不支持的输出格式: %s", o.OutputType)
	}
	
	return nil
}

// Clone 创建选项的深拷贝
func (o *Options) Clone() *Options {
	clone := &Options{}
	*clone = *o
	return clone
}
