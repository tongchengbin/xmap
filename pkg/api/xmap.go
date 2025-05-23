package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"strconv"
	"strings"
	"sync"

	"github.com/remeh/sizedwaitgroup"
	"github.com/tongchengbin/xmap/pkg/input"
	"github.com/tongchengbin/xmap/pkg/scanner"

	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/xmap/pkg/probe"
	"github.com/tongchengbin/xmap/pkg/types"
	"github.com/tongchengbin/xmap/pkg/web"
)

// ScannerConfig 扫描器配置接口
type ScannerConfig interface {
	GetOptions() *types.Options
}

// XMap 是核心扫描引擎，负责协调各种扫描器
type XMap struct {
	// 服务扫描器 - 负责基础网络服务探测
	serviceScanner *scanner.ServiceScanner
	// Web扫描器 - 负责Web应用指纹识别
	webScanner *web.Scanner
	// 指纹管理器
	probeManager *probe.Manager
	// 配置选项
	options *types.Options
	// 初始化锁
	initOnce sync.Once
}

// New 创建新的XMap实例
func New(options *types.Options) (*XMap, error) {
	// 创建XMap实例
	x := &XMap{
		options: options,
	}
	// 初始化扫描引擎
	err := x.init()
	return x, err
}

// init 初始化XMap扫描引擎
func (x *XMap) init() error {
	// 使用sync.Once确保只初始化一次
	var initErr error
	// 创建服务扫描器
	x.serviceScanner, initErr = scanner.NewServiceScanner(x.options)
	if initErr != nil {
		return initErr
	}
	// 初始化Web规则库
	initErr = InitWebRuleManager(customrules.GetDefaultDirectory())
	if initErr != nil {
		return initErr
	}
	// 创建Web扫描器
	x.webScanner, initErr = web.NewScanner(x.options)

	return initErr
}

// Scan 扫描单个目标
func (x *XMap) Scan(ctx context.Context, target *types.ScanTarget) (*types.ScanResult, error) {
	// 1. 执行服务扫描
	if web.ShouldScan(target.Scheme) {
		// 构建URL
		result := types.NewScanResult(target)
		url := x.buildTargetURL(target, target.Scheme)
		// 执行Web扫描
		webResult, err := x.webScanner.ScanWithContext(ctx, url)
		result.Service = target.Scheme
		x.enrichResultWithWebData(result, webResult)
		return result, err
	}
	result, err := x.serviceScanner.ScanWithContext(ctx, target)
	if err != nil {
		return nil, err
	}
	// 2. 标准化结果格式
	x.normalizeResult(result)
	// 3. 如果是Web服务，执行Web扫描
	if web.ShouldScan(result.Service) && x.webScanner != nil {
		// 构建URL
		url := x.buildTargetURL(target, result.Service)
		// 执行Web扫描
		webResult, err := x.webScanner.ScanWithContext(ctx, url)
		if err != nil {
			gologger.Debug().Msgf("Web扫描失败: %v", err)
		} else {
			// 合并Web扫描结果
			x.enrichResultWithWebData(result, webResult)
		}
	}

	return result, nil
}

// buildTargetURL 构建目标URL
func (x *XMap) buildTargetURL(target *types.ScanTarget, service string) string {
	if target.Host == "" {
		return fmt.Sprintf("%s://%s:%d", service, target.IP, target.Port)
	} else {
		return fmt.Sprintf("%s://%s:%d", service, target.Host, target.Port)
	}
}

// enrichResultWithWebData 使用Web扫描数据丰富扫描结果
func (x *XMap) enrichResultWithWebData(result *types.ScanResult, webResult *web.ScanResult) {
	if result == nil || webResult == nil {
		return
	}
	// 确保Metadata已初始化
	if result.Banner == nil {
		result.Banner = make(map[string]interface{})
	}
	result.URL = webResult.URL
	// 添加Banner信息到Metadata
	if webResult.Banner != nil {
		// 添加标题
		if webResult.Banner.Title != "" {
			result.Banner["title"] = webResult.Banner.Title
		}
		// 添加状态码
		if webResult.Banner.StatusCode > 0 {
			result.Banner["status_code"] = webResult.Banner.StatusCode
		}
		// 如果有HTTP响应体，添加到Metadata
		if webResult.Banner.Body != "" {
			result.Banner["body"] = webResult.Banner.Body
		}
		if webResult.Banner.IconBytes != nil {
			result.Banner["icon"] = base64.StdEncoding.EncodeToString(webResult.Banner.IconBytes)
		}
		if webResult.Banner.Certificate != "" {
			result.Banner["certificate"] = webResult.Banner.Certificate
		}
		if webResult.Banner.Charset != "" {
			result.Banner["charset"] = webResult.Banner.Charset
		}
		if webResult.Banner.Header != "" {
			result.Banner["header"] = webResult.Banner.Header
		}
		if webResult.Banner.IconType != "" {
			result.Banner["icon_type"] = webResult.Banner.IconType
		}
		if webResult.Banner.IconHash > 0 {
			result.Banner["icon_hash"] = webResult.Banner.IconHash
		}
		if webResult.Banner.BodyHash > 0 {
			result.Banner["body_hash"] = webResult.Banner.BodyHash
		}
	}
	// 添加指纹信息
	if len(webResult.Components) > 0 {
		for name, ext := range webResult.Components {
			// 创建新的map[string]interface{}
			componentInfo := make(map[string]interface{})
			componentInfo["name"] = name
			// 复制其他属性
			for k, v := range ext {
				componentInfo[k] = v
			}
			result.Components = append(result.Components, componentInfo)
		}
	}
}

// normalizeResult 标准化扫描结果
func (x *XMap) normalizeResult(result *types.ScanResult) {
	result.Protocol = result.Target.Protocol
	result.Hostname = result.Target.Host
	// 设置端口
	result.Port = result.Target.Port
	if result.IP == "" && result.Target.IP != "" {
		result.IP = result.Target.IP
	}
	if result.Extra != nil && len(result.Extra) > 0 {
		// fix product to name
		if name, ok := result.Extra["product"]; ok {
			result.Extra["name"] = name
			delete(result.Extra, "product")
			result.Components = append(result.Components, result.Extra)
		}
	}
	if result.Service == "http" && result.SSL {
		result.Service = "https"
	}
	// 设置原始响应数据
	if result.RawResponse != nil && len(result.RawResponse) > 0 {
		result.Banner["tcp_banner"] = base64.StdEncoding.EncodeToString(result.RawResponse)
	}
}

// ParseTargetsString 将目标字符串解析为ScanTarget切片
func (x *XMap) ParseTargetsString(targetsStr string) ([]*types.ScanTarget, error) {
	lines := strings.Split(targetsStr, "\n")
	targets := make([]*types.ScanTarget, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析目标格式: IP:Port/Protocol
		parts := strings.Split(line, ":")
		if len(parts) < 1 {
			continue
		}

		host := parts[0]
		port := 0
		protocol := "tcp"

		if len(parts) > 1 {
			portProto := strings.Split(parts[1], "/")
			if len(portProto) > 0 {
				portStr := portProto[0]
				portInt, err := strconv.Atoi(portStr)
				if err == nil {
					port = portInt
				}
			}

			if len(portProto) > 1 {
				protocol = strings.ToLower(portProto[1])
			}
		}

		target := &types.ScanTarget{
			Host:     host,
			Port:     port,
			Protocol: protocol,
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// ScanWithCallback 使用回调函数扫描多个目标
// 每完成一个目标的扫描就调用回调函数，适用于需要实时处理结果的场景
func (x *XMap) ScanWithCallback(ctx context.Context, targets input.Provider, callback func(*types.ScanResult)) error {
	// 设置默认并行数
	if x.options.Threads <= 0 {
		x.options.Threads = 10
	}
	// 创建上下文，支持取消
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// 启动扫描协程池
	wg := sizedwaitgroup.New(x.options.Threads)
	// 处理每个目标
	targets.Scan(func(target *types.ScanTarget) bool {
		// 添加到等待组
		wg.Add()
		// 为每个目标启动一个goroutine
		go func(target *types.ScanTarget) {
			defer wg.Done()
			// 检查上下文是否已取消
			if scanCtx.Err() != nil {
				x.handleScanError(callback, target, scanCtx.Err())
				return
			}
			// 执行扫描
			result, err := x.Scan(scanCtx, target)
			if err != nil {
				x.handleScanError(callback, target, err)
				return
			}
			// 调用回调函数
			if callback != nil {
				callback(result)
			}
		}(target)

		return true // 继续处理下一个目标
	})

	// 等待所有扫描完成
	wg.Wait()
	return nil
}

// handleScanError 处理扫描错误
func (x *XMap) handleScanError(callback func(*types.ScanResult), target *types.ScanTarget, err error) {
	if callback != nil {
		callback(&types.ScanResult{
			Target: target,
			Error:  err,
		})
	}
}

// GetOptions 获取选项
func (x *XMap) GetOptions() *types.Options {
	return x.options
}
