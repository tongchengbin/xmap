package web

import (
	"context"
	"fmt"
	"github.com/tongchengbin/appfinger/pkg/runner"
	"time"

	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/rule"
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
	options := crawl.DefaultOption()

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

// ScanResult Web扫描结果
type ScanResult struct {
	URL        string
	Components map[string]map[string]string
	Error      error
	Banner     *crawl.Banner
}

// ShouldScan 判断是否应该进行Web扫描
func ShouldScan(service string) bool {
	return service == "http" || service == "https" ||
		service == "http-alt" || service == "https-alt" ||
		service == "http-proxy" || service == "ssl/http"
}

// ScanWithContext 带上下文的Web扫描
func (s *Scanner) ScanWithContext(ctx context.Context, url string) (*ScanResult, error) {
	// 获取指纹库
	finger := rule.GetRuleManager().GetFinger()
	if finger == nil {
		return nil, fmt.Errorf("指纹库未加载")
	}
	// 创建爬虫
	crawler := crawl.NewCrawler(s.options)
	sdk, err := runner.NewRunner(crawler, rule.GetRuleManager(), nil)
	if err != nil {
		return nil, fmt.Errorf("create Runner Error~")
	}
	// 执行匹配
	result, err := sdk.ScanWithContext(ctx, url)
	if err != nil {
		return &ScanResult{
			URL:   url,
			Error: err,
		}, err
	}
	// 返回结果
	return &ScanResult{
		URL:        url,
		Components: result.Fingerprint,
		Banner:     result.Banner,
	}, nil
}
