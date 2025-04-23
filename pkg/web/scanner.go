package web

import (
	"context"
	"fmt"
	"time"

	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"github.com/tongchengbin/xmap/pkg/types"
)

// Scanner Web应用指纹扫描器
type Scanner struct {
	options *crawl.Options
}

// NewScanner 创建新的Web扫描器
func NewScanner() (*Scanner, error) {
	// 获取规则管理器实例
	ruleManager := rule.GetRuleManager()
	if !ruleManager.IsLoaded() {
		return nil, fmt.Errorf("规则库未加载")
	}
	// 创建默认选项
	options := &crawl.Options{
		Timeout:   10 * time.Second,
		DebugResp: false,
	}

	return &Scanner{
		options: options,
	}, nil
}

// ReloadRules 重新加载指纹库规则
func ReloadRules() error {
	return rule.GetRuleManager().ReloadRules()
}

// SetTimeout 设置超时时间
func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.options.Timeout = timeout
}

// SetDebugResponse 设置是否调试响应
func (s *Scanner) SetDebugResponse(debug bool) {
	s.options.DebugResp = debug
}

// SetProxy 设置代理
func (s *Scanner) SetProxy(proxy string) {
	s.options.Proxy = proxy
}


// ShouldScan 判断是否应该进行Web扫描
func ShouldScan(service string) bool {
	return service == "http" || service == "https" ||
		service == "http-alt" || service == "https-alt" ||
		service == "http-proxy" || service == "ssl/http"
}

// ScanWithContext 带上下文的Web扫描
func (s *Scanner) ScanWithContext(ctx context.Context, target *types.ScanTarget) (*types.ScanResult, error) {
	// 获取指纹库
	finger := rule.GetRuleManager().GetFinger()
	if finger == nil {
		return nil, fmt.Errorf("指纹库未加载")
	}

	// 组装 URL，优先用 Scheme 字段
	scheme := target.Scheme
	if scheme == "" {
		// 自动推断
		if target.Port == 443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	url := fmt.Sprintf("%s://%s", scheme, target.Host)
	if target.Port != 80 && target.Port != 443 && target.Port != 0 {
		url += fmt.Sprintf(":%d", target.Port)
	}
	if target.Path != "" {
		url += target.Path
	}

	// 创建爬虫
	crawler := crawl.NewCrawl(s.options, finger)

	// 执行匹配
	banner, components, err := crawler.Match(url)
	if err != nil {
		// 转换 components 为 []map[string]interface{}
		var componentsSlice []map[string]interface{}
		for k, v := range components {
			entry := map[string]interface{}{"name": k, "info": v}
			componentsSlice = append(componentsSlice, entry)
		}
		return &types.ScanResult{
			Target:     target,
			URL:        url,
			Error:      err,
			Components: componentsSlice,
		}, err
	}
	// 转换 components 为 []map[string]interface{}
	var componentsSlice []map[string]interface{}
	for k, v := range components {
		entry := map[string]interface{}{"name": k, "info": v}
		componentsSlice = append(componentsSlice, entry)
	}
	// 返回结果
	return &types.ScanResult{
		Target:     target,
		URL:        url,
		Components: componentsSlice,
		Banner:     banner,
	}, nil
}
