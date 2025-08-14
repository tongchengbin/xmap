package probe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/projectdiscovery/gologger"
)

var DefaultRegexpTimeout = 3 * time.Second

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

// Match 表示匹配规则
type Match struct {
	// 是否为软匹配
	Soft bool
	// 服务名称
	Service string
	// 匹配模式
	Pattern []byte
	// 编译好的正则表达式
	regex *regexp2.Regexp
	// 版本信息
	VersionInfo *VersionInfo
	// 行号
	Line int
}

// HasPort 检查探针是否适用于指定端口
func (p *Probe) HasPort(port int) bool {
	for _, p := range p.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// HasSSLPort 检查探针是否适用于指定SSL端口
func (p *Probe) HasSSLPort(port int) bool {
	for _, p := range p.SSLPorts {
		if p == port {
			return true
		}
	}
	return false
}

// matchWithTimeout 在指定超时时间内执行正则表达式匹配
func matchWithTimeout(regex *regexp2.Regexp, input string) (*regexp2.Match, error) {
	type matchResult struct {
		match *regexp2.Match
		err   error
	}
	resultCh := make(chan matchResult, 1)
	// 在goroutine中执行匹配操作
	go func() {
		match, err := regex.FindStringMatch(input)
		resultCh <- matchResult{match: match, err: err}
	}()

	// 等待匹配结果或超时
	select {
	case result := <-resultCh:
		return result.match, result.err
	case <-time.After(DefaultRegexpTimeout):
		return nil, fmt.Errorf("正则表达式匹配超时 (超过 %v)", DefaultRegexpTimeout)
	}
}

// extractMatchGroups 从匹配结果中提取所有组
func extractMatchGroups(matcher *regexp2.Match) map[string]string {
	groups := make(map[string]string)
	if len(matcher.Groups()) > 1 {
		for index, group := range matcher.Groups() {
			groups[fmt.Sprintf("$%d", index)] = group.String()
		}
	}
	return groups
}

// extractVersionInfo 从匹配结果中提取版本信息
func extractVersionInfo(m *Match, groups map[string]string) map[string]interface{} {
	extra := map[string]interface{}{}

	// 提取基本版本信息
	if m.VersionInfo.Version != "" {
		extra["version"] = groups[m.VersionInfo.Version]
	}
	if m.VersionInfo.ProductName != "" {
		extra["product"] = m.VersionInfo.ProductName
	}
	if m.VersionInfo.OS != "" {
		extra["os"] = m.VersionInfo.OS
	}
	if m.VersionInfo.Info != "" {
		extra["info"] = m.VersionInfo.Info
	}
	if m.VersionInfo.Hostname != "" {
		extra["hostname"] = m.VersionInfo.Hostname
	}
	if m.VersionInfo.DeviceType != "" {
		extra["device_type"] = m.VersionInfo.DeviceType
	}

	// 处理变量替换
	for k, v := range extra {
		vStr, ok := v.(string)
		if !ok {
			continue
		}

		if strings.Contains(vStr, "$") {
			// 提取所有的$N引用
			varPattern := regexp.MustCompile(`\$(\d+|[a-zA-Z][a-zA-Z0-9_]*)`)
			// 替换所有的$N引用为相应的组值
			replacedValue := varPattern.ReplaceAllStringFunc(vStr, func(match string) string {
				groupKey := match[1:] // 去掉$前缀
				// 如果是数字，直接从groups中获取
				if _, err := strconv.Atoi(groupKey); err == nil {
					if groupValue, ok := groups["$"+groupKey]; ok {
						return groupValue
					}
					return ""
				}
				// 否则使用命名组
				if groupValue, ok := groups[groupKey]; ok {
					return groupValue
				}
				return "" // 如果没有找到对应的组，返回空字符串
			})
			extra[k] = replacedValue
		}
	}

	return extra
}

// Match 匹配响应数据，返回匹配结果
func (p *Probe) Match(response []byte) (*MatchResult, error) {
	visited := make(map[string]bool)
	return p.matchInternal(response, visited, true)
}

// matchInternal 内部递归函数，实现循环检测和回退匹配
func (p *Probe) matchInternal(response []byte, visited map[string]bool, matchFall bool) (*MatchResult, error) {
	/*
		visited: 用于检测循环引用
		matchFall: 是否进行备用匹配
	*/
	if visited[p.Name] {
		return nil, fmt.Errorf("检测到循环引用: %s", p.Name)
	}
	visited[p.Name] = true
	for _, m := range p.MatchGroup {
		matcher, err := matchWithTimeout(m.regex, string(response))
		if err != nil {
			gologger.Debug().Msgf("匹配探针 %s 时出错: %v", p.Name, err)
			continue
		}
		if matcher != nil {
			groups := extractMatchGroups(matcher)
			versionInfo := extractVersionInfo(m, groups)
			return &MatchResult{
				Probe:       p,
				Match:       m,
				VersionInfo: versionInfo,
				Response:    response,
			}, nil
		}
	}
	if matchFall {
		for _, fallbackProbe := range p.FallbackProbes {
			// 使用相同的visited映射进行递归调用，确保循环检测有效
			result, err := fallbackProbe.matchInternal(response, visited, false)
			if err != nil {
				return nil, err
			}
			if result != nil {
				// 回退路径已在matchInternal中正确设置
				return result, nil
			}
		}
	}
	return nil, nil
}
