package probe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/projectdiscovery/gologger"
)

// DefaultRegexpTimeout 默认正则表达式匹配超时时间，防止灾难性回溯
const DefaultRegexpTimeout = 500 * time.Millisecond

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

// HasExactPort 检查探针是否精确匹配指定端口（单独列出而非端口范围）
func (p *Probe) HasExactPort(port int) bool {
	// 如果探针没有指定端口，则认为不是精确匹配
	if len(p.Ports) == 0 {
		return false
	}

	// 检查是否精确匹配端口
	for _, p := range p.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// HasExactSSLPort 检查探针是否精确匹配SSL端口（单独列出而非端口范围）
func (p *Probe) HasExactSSLPort(port int) bool {
	// 如果探针没有指定SSL端口，则认为不是精确匹配
	if len(p.SSLPorts) == 0 {
		return false
	}

	// 检查是否精确匹配SSL端口
	for _, sslPort := range p.SSLPorts {
		if sslPort == port {
			return true
		}
	}
	return false
}

// matchWithTimeout 在指定超时时间内执行正则表达式匹配
// 结合正则表达式内置超时和goroutine超时双重保护
func matchWithTimeout(regex *regexp2.Regexp, input string) (*regexp2.Match, error) {
	type matchResult struct {
		match *regexp2.Match
		err   error
	}

	// 创建可取消的上下文
	ctx, cancel := context.WithTimeout(context.Background(), DefaultRegexpTimeout)
	defer cancel()

	resultCh := make(chan matchResult, 1)

	// 在goroutine中执行匹配操作
	go func() {
		// 尝试匹配，正则表达式库内部会处理其MatchTimeout超时
		match, err := regex.FindStringMatch(input)

		// 检查上下文是否已取消或超时
		select {
		case <-ctx.Done():
			// 上下文已取消，不发送结果
			return
		default:
			// 上下文未取消，发送结果
			resultCh <- matchResult{match: match, err: err}
		}
	}()

	// 等待匹配结果或超时
	select {
	case result := <-resultCh:
		return result.match, result.err
	case <-ctx.Done():
		// 外部超时或取消
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
			if groups[k] != "" {
				extra[k] = groups[k]
				continue
			}
			replacedValue := strings.ReplaceAll(vStr, "$", "")
			replacedValue = strings.ReplaceAll(replacedValue, "{", "")
			replacedValue = strings.ReplaceAll(replacedValue, "}", "")
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
