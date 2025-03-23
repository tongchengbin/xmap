package matcher

import (
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/tongchengbin/xmap/internal/probe"
	"github.com/tongchengbin/xmap/internal/scanner"
)

// MatchEngine 匹配引擎实现
type MatchEngine struct {
	// 是否启用版本检测
	versionDetection bool
	// 是否启用操作系统检测
	osDetection bool
	// 是否启用设备类型检测
	deviceTypeDetection bool
	// 是否启用主机名检测
	hostnameDetection bool
	// 是否启用产品名称检测
	productNameDetection bool
	// 是否启用信息检测
	infoDetection bool
	// 正则表达式缓存
	regexCache map[string]*regexp2.Regexp
}

// NewMatchEngine 创建新的匹配引擎
func NewMatchEngine(options ...MatchOption) *MatchEngine {
	engine := &MatchEngine{
		versionDetection:     true,
		osDetection:          true,
		deviceTypeDetection:  true,
		hostnameDetection:    true,
		productNameDetection: true,
		infoDetection:        true,
		regexCache:           make(map[string]*regexp2.Regexp),
	}

	// 应用选项
	for _, option := range options {
		option(engine)
	}

	return engine
}

// MatchOption 匹配引擎选项函数类型
type MatchOption func(*MatchEngine)

// WithVersionDetection 设置是否启用版本检测
func WithVersionDetection(enable bool) MatchOption {
	return func(e *MatchEngine) {
		e.versionDetection = enable
	}
}

// WithOSDetection 设置是否启用操作系统检测
func WithOSDetection(enable bool) MatchOption {
	return func(e *MatchEngine) {
		e.osDetection = enable
	}
}

// WithDeviceTypeDetection 设置是否启用设备类型检测
func WithDeviceTypeDetection(enable bool) MatchOption {
	return func(e *MatchEngine) {
		e.deviceTypeDetection = enable
	}
}

// WithHostnameDetection 设置是否启用主机名检测
func WithHostnameDetection(enable bool) MatchOption {
	return func(e *MatchEngine) {
		e.hostnameDetection = enable
	}
}

// WithProductNameDetection 设置是否启用产品名称检测
func WithProductNameDetection(enable bool) MatchOption {
	return func(e *MatchEngine) {
		e.productNameDetection = enable
	}
}

// WithInfoDetection 设置是否启用信息检测
func WithInfoDetection(enable bool) MatchOption {
	return func(e *MatchEngine) {
		e.infoDetection = enable
	}
}

// Match 匹配响应数据
func (e *MatchEngine) Match(probe *probe.Probe, response []byte) (*scanner.ScanResult, error) {
	// 创建扫描结果
	result := &scanner.ScanResult{}

	// 遍历匹配组
	for _, match := range probe.MatchGroup {
		// 获取或编译正则表达式
		regex, err := e.getRegex(match.Pattern)
		if err != nil {
			continue
		}

		// 匹配响应
		m, err := regex.FindStringMatch(string(response))
		if err != nil || m == nil {
			continue
		}

		// 匹配成功
		result.Service = match.Service
		result.MatchedService = match.Service
		result.MatchedPattern = match.Pattern
		result.SoftMatch = match.Soft

		// 提取版本信息
		if match.VersionInfo != nil {
			if e.productNameDetection {
				result.ProductName = match.VersionInfo.ProductName
			}
			if e.versionDetection {
				result.Version = match.VersionInfo.Version
			}
			if e.infoDetection {
				result.Info = match.VersionInfo.Info
			}
			if e.hostnameDetection {
				result.Hostname = match.VersionInfo.Hostname
			}
			if e.osDetection {
				result.OS = match.VersionInfo.OS
			}
			if e.deviceTypeDetection {
				result.DeviceType = match.VersionInfo.DeviceType
			}
		}

		// 替换版本信息中的变量
		e.replaceVersionVariables(result, m)

		return result, nil
	}

	// 没有匹配到任何服务
	return nil, nil
}

// getRegex 获取或编译正则表达式
func (e *MatchEngine) getRegex(pattern string) (*regexp2.Regexp, error) {
	// 检查缓存
	if regex, ok := e.regexCache[pattern]; ok {
		return regex, nil
	}

	// 编译正则表达式
	regex, err := regexp2.Compile(pattern, regexp2.IgnoreCase)
	if err != nil {
		return nil, err
	}

	// 缓存正则表达式
	e.regexCache[pattern] = regex

	return regex, nil
}

// replaceVersionVariables 替换版本信息中的变量
func (e *MatchEngine) replaceVersionVariables(result *scanner.ScanResult, match *regexp2.Match) {
	// 获取所有捕获组
	groups := match.Groups()
	if len(groups) <= 1 {
		return
	}

	// 替换版本信息中的变量
	if result.ProductName != "" {
		result.ProductName = e.replaceVariables(result.ProductName, groups)
	}
	if result.Version != "" {
		result.Version = e.replaceVariables(result.Version, groups)
	}
	if result.Info != "" {
		result.Info = e.replaceVariables(result.Info, groups)
	}
	if result.Hostname != "" {
		result.Hostname = e.replaceVariables(result.Hostname, groups)
	}
	if result.OS != "" {
		result.OS = e.replaceVariables(result.OS, groups)
	}
	if result.DeviceType != "" {
		result.DeviceType = e.replaceVariables(result.DeviceType, groups)
	}
}

// replaceVariables 替换字符串中的变量
func (e *MatchEngine) replaceVariables(str string, groups []*regexp2.Group) string {
	result := str

	// 替换 $1, $2, ... 变量
	for i := 1; i < len(groups); i++ {
		if groups[i] != nil && groups[i].Captures != nil && len(groups[i].Captures) > 0 {
			value := groups[i].Captures[0].String()
			result = strings.ReplaceAll(result, "$"+string(i+'0'), value)
		}
	}

	return result
}
