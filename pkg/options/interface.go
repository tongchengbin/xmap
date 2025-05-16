package options

import (
	"strconv"
	"strings"
	"time"
)

// OptionProvider 定义了选项提供者接口
type OptionProvider interface {
	// GetOptions 获取全局初始化选项
	GetOptions() *Options
	
	// GetScanOptions 获取扫描选项
	GetScanOptions() *ScanOptions
}

// FromCLI 从命令行选项创建Options和ScanOptions
func FromCLI(cliOptions map[string]interface{}) (*Options, *ScanOptions, error) {
	// 创建默认选项
	options := DefaultOptions()
	scanOptions := DefaultScanOptions()
	
	// 设置全局选项
	if v, ok := cliOptions["verbose"].(bool); ok {
		options.Verbose = v
	}
	
	if v, ok := cliOptions["silent"].(bool); ok {
		options.Silent = v
	}
	
	if v, ok := cliOptions["no-progress"].(bool); ok {
		options.NoProgress = v
	}
	
	if v, ok := cliOptions["proxy"].(string); ok {
		options.Proxy = v
	}
	
	if v, ok := cliOptions["fingerprint-path"].(string); ok {
		options.AppFingerHome = v
	}
	
	if v, ok := cliOptions["update-rule"].(bool); ok {
		options.UpdateRule = v
	}
	
	if v, ok := cliOptions["disable-icon"].(bool); ok {
		options.DisableIcon = v
	}
	
	if v, ok := cliOptions["disable-js"].(bool); ok {
		options.DisableJS = v
	}
	
	if v, ok := cliOptions["output"].(string); ok {
		options.Output = v
	}
	
	if v, ok := cliOptions["output-type"].(string); ok {
		options.OutputType = v
	}
	
	if v, ok := cliOptions["enable-pprof"].(bool); ok {
		options.EnablePprof = v
	}
	
	if v, ok := cliOptions["version"].(string); ok {
		options.Version = v
	}
	
	if v, ok := cliOptions["banner"].(string); ok {
		options.Banner = v
	}
	
	// 设置扫描选项
	if v, ok := cliOptions["timeout"].(int); ok {
		scanOptions.Timeout = time.Duration(v) * time.Second
	}
	
	if v, ok := cliOptions["retries"].(int); ok {
		scanOptions.Retries = v
	}
	
	if v, ok := cliOptions["workers"].(int); ok {
		scanOptions.MaxParallelism = v
	}
	
	if v, ok := cliOptions["fast"].(bool); ok {
		scanOptions.FastMode = v
	}
	
	if v, ok := cliOptions["all-probes"].(bool); ok {
		scanOptions.UseAllProbes = v
	}
	
	if v, ok := cliOptions["probes"].([]string); ok && len(v) > 0 {
		scanOptions.ProbeNames = v
	}
	
	if v, ok := cliOptions["ssl"].(bool); ok {
		scanOptions.UseSSL = v
	}
	
	if v, ok := cliOptions["version-intensity"].(int); ok {
		scanOptions.VersionIntensity = v
	}
	
	if v, ok := cliOptions["service-version"].(bool); ok {
		scanOptions.VersionDetection = v
	}
	
	if v, ok := cliOptions["version-trace"].(bool); ok {
		scanOptions.VersionTrace = v
	}
	
	if v, ok := cliOptions["debug-resp"].(bool); ok {
		scanOptions.DebugResponse = v
	}
	
	// 处理端口
	if v, ok := cliOptions["ports"].(string); ok {
		ports, err := parsePorts(v)
		if err != nil {
			return nil, nil, err
		}
		scanOptions.Ports = ports
	}
	
	// 验证选项
	if err := options.Validate(); err != nil {
		return nil, nil, err
	}
	
	if err := scanOptions.Validate(); err != nil {
		return nil, nil, err
	}
	
	return options, scanOptions, nil
}

// parsePorts 解析端口字符串
func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	
	// 按逗号分割
	parts := strings.Split(portsStr, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// 检查是否是端口范围
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}
			
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				continue
			}
			
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				continue
			}
			
			// 添加范围内的所有端口
			for port := start; port <= end; port++ {
				if port > 0 && port < 65536 {
					ports = append(ports, port)
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			
			if port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}
	
	return ports, nil
}

// Option 全局选项函数类型
type Option func(*Options)

// WithVerbose 设置是否打印详细的调试信息
func WithVerbose(verbose bool) Option {
	return func(o *Options) {
		o.Verbose = verbose
	}
}

// WithSilent 设置是否启用静默模式
func WithSilent(silent bool) Option {
	return func(o *Options) {
		o.Silent = silent
	}
}

// WithNoProgress 设置是否不显示进度条
func WithNoProgress(noProgress bool) Option {
	return func(o *Options) {
		o.NoProgress = noProgress
	}
}

// WithProxy 设置代理
func WithProxy(proxy string) Option {
	return func(o *Options) {
		o.Proxy = proxy
	}
}

// WithAppFingerHome 设置指纹库路径
func WithAppFingerHome(appFingerHome string) Option {
	return func(o *Options) {
		o.AppFingerHome = appFingerHome
	}
}

// WithUpdateRule 设置是否更新指纹规则
func WithUpdateRule(updateRule bool) Option {
	return func(o *Options) {
		o.UpdateRule = updateRule
	}
}

// WithDisableIcon 设置是否禁用图标请求匹配
func WithDisableIcon(disableIcon bool) Option {
	return func(o *Options) {
		o.DisableIcon = disableIcon
	}
}

// WithDisableJS 设置是否禁用JavaScript规则匹配
func WithDisableJS(disableJS bool) Option {
	return func(o *Options) {
		o.DisableJS = disableJS
	}
}

// WithOutput 设置输出文件路径
func WithOutput(output string) Option {
	return func(o *Options) {
		o.Output = output
	}
}

// WithOutputType 设置输出格式
func WithOutputType(outputType string) Option {
	return func(o *Options) {
		o.OutputType = outputType
	}
}

// WithEnablePprof 设置是否启用性能分析
func WithEnablePprof(enablePprof bool) Option {
	return func(o *Options) {
		o.EnablePprof = enablePprof
	}
}

// WithVersion 设置版本信息
func WithVersion(version string) Option {
	return func(o *Options) {
		o.Version = version
	}
}

// WithBanner 设置Banner信息
func WithBanner(banner string) Option {
	return func(o *Options) {
		o.Banner = banner
	}
}

// Apply 应用选项
func (o *Options) Apply(options ...Option) {
	for _, option := range options {
		option(o)
	}
}
