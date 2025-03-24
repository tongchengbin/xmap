package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/xmap/pkg/scanner"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/xmap/pkg/model"
	"github.com/tongchengbin/xmap/pkg/probe"
	"github.com/tongchengbin/xmap/pkg/web"
)

// XMap 是公共API接口，用于与外部系统集成
type XMap struct {
	// 扫描器
	scanner *scanner.ServiceScanner
	// Web扫描器
	webScanner *web.Scanner
	// 指纹管理器
	probeManager *probe.Manager
	// 默认选项
	defaultOptions *scanner.ScanOptions
	// 初始化锁
	initOnce sync.Once
}

// NewXMap 创建新的XMap实例
func NewXMap(options ...Option) *XMap {
	// 创建XMap实例
	x := &XMap{
		defaultOptions: scanner.DefaultScanOptions(),
	}
	// 应用选项
	for _, option := range options {
		option(x)
	}

	// 延迟初始化
	x.init()

	return x
}

// init 初始化XMap
func (x *XMap) init() {
	x.initOnce.Do(func() {
		// 初始化默认管理器（如果尚未初始化）
		err := probe.InitDefaultManager()
		if err != nil {
			gologger.Error().Msgf("初始化默认管理器失败: %v", err)
			return
		}

		// 获取指纹管理器
		x.probeManager, err = probe.GetManager(&probe.FingerprintOptions{
			VersionIntensity: x.defaultOptions.VersionIntensity,
		})
		if err != nil {
			gologger.Error().Msgf("获取指纹管理器失败: %v", err)
			return
		}
		// 创建服务扫描器
		x.scanner, err = scanner.NewServiceScanner(
			scanner.WithVersionIntensity(x.defaultOptions.VersionIntensity),
			scanner.WithTimeout(x.defaultOptions.Timeout),
			scanner.WithRetries(x.defaultOptions.Retries),
			scanner.WithMaxParallelism(x.defaultOptions.MaxParallelism),
			scanner.WithFastMode(x.defaultOptions.FastMode),
			scanner.WithDebugRequest(x.defaultOptions.DebugRequest),
			scanner.WithDebugResponse(x.defaultOptions.DebugResponse),
		)
		if err != nil {
			gologger.Error().Msgf("创建服务扫描器失败: %v", err)
			return
		}
		// 初始化规则库
		err = InitRuleManager(customrules.GetDefaultDirectory())
		if err != nil {
			gologger.Warning().Msgf("初始化规则库失败: %v", err)
			// 即使规则库初始化失败，也不影响基本功能
		}

		// 创建Web扫描器
		x.webScanner, err = web.NewScanner()
		if err != nil {
			gologger.Warning().Msgf("创建Web扫描器失败: %v", err)
			// 即使Web扫描器创建失败，也不影响基本功能
		} else {
			// 设置Web扫描器选项
			x.webScanner.SetTimeout(time.Duration(x.defaultOptions.Timeout) * time.Second)
			x.webScanner.SetDebugResponse(x.defaultOptions.DebugResponse)
		}
	})
}

// Option 选项函数类型
type Option func(*XMap)

// WithTimeout 设置默认超时时间
func WithTimeout(timeout time.Duration) Option {
	return func(x *XMap) {
		x.defaultOptions.Timeout = timeout
	}
}

// WithRetries 设置默认重试次数
func WithRetries(retries int) Option {
	return func(x *XMap) {
		x.defaultOptions.Retries = retries
	}
}

// WithVersionIntensity 设置默认版本检测强度
func WithVersionIntensity(intensity int) Option {
	return func(x *XMap) {
		x.defaultOptions.VersionIntensity = intensity
	}
}

// WithMaxParallelism 设置默认最大并行扫描数
func WithMaxParallelism(maxParallelism int) Option {
	return func(x *XMap) {
		x.defaultOptions.MaxParallelism = maxParallelism
	}
}

// WithFastMode 设置默认是否使用快速模式
func WithFastMode(fastMode bool) Option {
	return func(x *XMap) {
		x.defaultOptions.FastMode = fastMode
	}
}

// WithDebugRequest 设置是否打印请求数据
func WithDebugRequest(debugRequest bool) Option {
	return func(x *XMap) {
		x.defaultOptions.DebugRequest = debugRequest
	}
}

// WithDebugResponse 设置是否打印响应数据
func WithDebugResponse(debugResponse bool) Option {
	return func(x *XMap) {
		x.defaultOptions.DebugResponse = debugResponse
	}
}

// WithVerbose 设置是否打印详细的调试信息
func WithVerbose(verbose bool) Option {
	return func(x *XMap) {
		x.defaultOptions.Verbose = verbose
	}
}

// Scan 扫描单个目标
func (x *XMap) Scan(ctx context.Context, target *model.ScanTarget, options ...*model.ScanOptions) (*model.ScanResult, error) {
	// 使用默认选项
	opts := &model.ScanOptions{
		Timeout:          int(x.defaultOptions.Timeout.Seconds()),
		Retries:          x.defaultOptions.Retries,
		VersionIntensity: x.defaultOptions.VersionIntensity,
		MaxParallelism:   x.defaultOptions.MaxParallelism,
		FastMode:         x.defaultOptions.FastMode,
		ServiceDetection: true,
		VersionDetection: true,
	}

	// 应用用户选项
	if len(options) > 0 && options[0] != nil {
		opts = options[0]
	}

	// 转换目标
	scannerTarget := scanner.NewTarget(target.IP, target.Port, scanner.Protocol(target.Protocol))

	// 创建扫描选项
	scanOptions := x.createScanOptions(opts)

	// 执行扫描
	result, err := x.scanner.ScanWithContext(ctx, scannerTarget, scanOptions...)
	if err != nil {
		return nil, err
	}

	// 转换结果
	modelResult := x.convertResult(result, target)

	// 如果是Web服务，执行Web扫描
	if web.ShouldScan(result.Service) && x.webScanner != nil {
		// 设置Web扫描器选项
		x.webScanner.SetTimeout(time.Duration(opts.Timeout) * time.Second)
		x.webScanner.SetDebugResponse(opts.DebugResponse)

		// 设置代理
		if opts.Proxy != "" {
			x.webScanner.SetProxy(opts.Proxy)
		}

		// 执行Web扫描
		webResult, err := x.webScanner.ScanWithContext(ctx, scannerTarget)
		if err != nil {
			gologger.Debug().Msgf("Web扫描失败: %v", err)
		} else {
			// 使用Web扫描结果丰富结果
			x.enrichResultWithWebData(modelResult, webResult)
		}
	}

	return modelResult, nil
}

// BatchScan 批量扫描多个目标
func (x *XMap) BatchScan(ctx context.Context, targets []*model.ScanTarget, options *model.ScanOptions) ([]*model.ScanResult, error) {
	// 转换目标
	scanTargets := make([]*scanner.Target, len(targets))
	for i, target := range targets {
		scanTargets[i] = scanner.NewTarget(target.IP, target.Port, scanner.Protocol(target.Protocol))
	}

	// 创建扫描选项
	scanOptions := x.createScanOptions(options)

	// 执行扫描
	results, err := x.scanner.BatchScanWithContext(ctx, scanTargets, scanOptions...)
	if err != nil {
		return nil, err
	}

	// 转换结果
	modelResults := make([]*model.ScanResult, len(results))
	for i, result := range results {
		modelResults[i] = x.convertResult(result, targets[i])

		// 检查是否需要进行Web扫描
		if web.ShouldScan(result.Service) {
			gologger.Debug().Msgf("检测到HTTP服务，执行Web扫描: %s:%d", targets[i].IP, targets[i].Port)

			// 执行Web扫描
			webResult, webErr := x.webScanner.ScanWithContext(ctx, scanTargets[i])
			if webErr != nil {
				gologger.Warning().Msgf("Web扫描失败: %v", webErr)
			} else if webResult != nil {
				// 将Web扫描结果添加到模型结果中
				x.enrichResultWithWebData(modelResults[i], webResult)
				gologger.Debug().Msgf("Web扫描成功，发现 %d 个指纹", len(webResult.Components))
			}
		}
	}

	return modelResults, nil
}

// ExecuteTask 执行扫描任务
func (x *XMap) ExecuteTask(ctx context.Context, task *model.ScanTask) (*model.ScanTask, []*model.ScanResult, error) {
	// 更新任务状态
	task.Status = model.TaskStatusRunning
	task.StartedAt = time.Now()

	// 执行批量扫描
	results, err := x.BatchScan(ctx, task.Targets, task.Options)

	// 更新任务状态
	task.CompletedAt = time.Now()
	if err != nil {
		task.Status = model.TaskStatusFailed
		return task, results, err
	}

	task.Status = model.TaskStatusCompleted
	return task, results, nil
}

// ExecuteTaskWithProgress 执行扫描任务并报告进度
func (x *XMap) ExecuteTaskWithProgress(ctx context.Context, task *model.ScanTask, progressCallback func(*model.ScanProgress)) (*model.ScanTask, []*model.ScanResult, error) {
	// 更新任务状态
	task.Status = model.TaskStatusRunning
	task.StartedAt = time.Now()

	// 创建进度跟踪器
	progress := &model.ScanProgress{
		TaskID:           task.ID,
		TotalTargets:     len(task.Targets),
		CompletedTargets: 0,
		SuccessTargets:   0,
		FailedTargets:    0,
		Percentage:       0,
		Status:           model.TaskStatusRunning,
		StartTime:        task.StartedAt,
		CurrentTime:      time.Now(),
	}

	// 创建结果通道
	resultChan := make(chan *model.ScanResult, len(task.Targets))

	// 创建等待组
	var wg sync.WaitGroup

	// 创建上下文
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 设置最大并行数
	maxParallelism := 10
	if task.Options != nil && task.Options.MaxParallelism > 0 {
		maxParallelism = task.Options.MaxParallelism
	}

	// 创建信号量通道
	sem := make(chan struct{}, maxParallelism)

	// 启动扫描协程
	for i, target := range task.Targets {
		wg.Add(1)
		go func(idx int, t *model.ScanTarget) {
			defer wg.Done()

			// 获取信号量
			sem <- struct{}{}
			defer func() { <-sem }()

			// 执行扫描
			result, err := x.Scan(scanCtx, t, task.Options)
			if err != nil {
				gologger.Debug().Msgf("Failed to scan target %s:%d: %v", t.IP, t.Port, err)
			}
			if result == nil {
				result = &model.ScanResult{
					Target: t,
					Error:  fmt.Sprintf("Failed to scan target %s:%d", t.IP, t.Port),
				}
			}
			resultChan <- result

		}(i, target)
	}

	// 启动结果收集协程
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果并更新进度
	results := make([]*model.ScanResult, 0, len(task.Targets))
	lastProgressUpdate := time.Now()
	progressUpdateInterval := 500 * time.Millisecond

	for result := range resultChan {
		results = append(results, result)

		// 更新进度
		progress.CompletedTargets++
		if result.Error == "" {
			progress.SuccessTargets++
		} else {
			progress.FailedTargets++
		}
		progress.Percentage = float64(progress.CompletedTargets) / float64(progress.TotalTargets) * 100
		progress.CurrentTime = time.Now()

		// 计算预计剩余时间
		if progress.CompletedTargets > 0 {
			elapsedSeconds := int(progress.CurrentTime.Sub(progress.StartTime).Seconds())
			if elapsedSeconds > 0 {
				targetsPerSecond := float64(progress.CompletedTargets) / float64(elapsedSeconds)
				if targetsPerSecond > 0 {
					remainingTargets := progress.TotalTargets - progress.CompletedTargets
					progress.EstimatedTimeRemaining = int(float64(remainingTargets) / targetsPerSecond)
				}
			}
		}

		// 调用进度回调
		if progressCallback != nil && time.Since(lastProgressUpdate) >= progressUpdateInterval {
			progressCallback(progress)
			lastProgressUpdate = time.Now()
		}
	}

	// 最后一次进度更新
	if progressCallback != nil {
		progress.Status = model.TaskStatusCompleted
		progress.CurrentTime = time.Now()
		progress.Percentage = 100
		progress.EstimatedTimeRemaining = 0
		progressCallback(progress)
	}

	// 更新任务状态
	task.CompletedAt = time.Now()
	task.Status = model.TaskStatusCompleted

	return task, results, nil
}

// ExecuteWithFile 从文件执行扫描任务
func (x *XMap) ExecuteWithFile(ctx context.Context, targetsFile string, options *model.ScanOptions) ([]*model.ScanResult, error) {
	// TODO: 实现从文件加载目标并执行扫描
	return nil, fmt.Errorf("not implemented")
}

// createScanOptions 创建扫描选项
func (x *XMap) createScanOptions(options *model.ScanOptions) []scanner.ScanOption {
	var scanOptions []scanner.ScanOption

	if options == nil {
		return scanOptions
	}

	// 设置超时
	if options.Timeout > 0 {
		scanOptions = append(scanOptions, scanner.WithTimeout(time.Duration(options.Timeout)*time.Second))
	}

	// 设置重试次数
	if options.Retries > 0 {
		scanOptions = append(scanOptions, scanner.WithRetries(options.Retries))
	}

	// 设置SSL
	scanOptions = append(scanOptions, scanner.WithSSL(options.UseSSL))

	// 设置版本检测强度
	if options.VersionIntensity >= 0 && options.VersionIntensity <= 9 {
		scanOptions = append(scanOptions, scanner.WithVersionIntensity(options.VersionIntensity))
	}

	// 设置主机发现
	scanOptions = append(scanOptions, scanner.WithHostDiscovery(options.HostDiscovery))

	// 设置最大并行数
	if options.MaxParallelism > 0 {
		scanOptions = append(scanOptions, scanner.WithMaxParallelism(options.MaxParallelism))
	}

	// 设置探针名称
	if len(options.ProbeNames) > 0 {
		scanOptions = append(scanOptions, scanner.WithProbeNames(options.ProbeNames))
	}

	// 设置端口
	if len(options.Ports) > 0 {
		scanOptions = append(scanOptions, scanner.WithPorts(options.Ports))
	}

	// 设置是否使用所有探针
	scanOptions = append(scanOptions, scanner.WithAllProbes(options.UseAllProbes))

	// 设置是否使用快速模式
	scanOptions = append(scanOptions, scanner.WithFastMode(options.FastMode))

	// 设置是否使用服务检测
	scanOptions = append(scanOptions, scanner.WithServiceDetection(options.ServiceDetection))

	// 设置是否使用版本检测
	scanOptions = append(scanOptions, scanner.WithVersionDetection(options.VersionDetection))

	// 设置是否使用操作系统检测
	scanOptions = append(scanOptions, scanner.WithOSDetection(options.OSDetection))

	// 设置是否使用设备类型检测
	scanOptions = append(scanOptions, scanner.WithDeviceTypeDetection(options.DeviceTypeDetection))

	// 设置是否使用主机名检测
	scanOptions = append(scanOptions, scanner.WithHostnameDetection(options.HostnameDetection))

	// 设置是否使用产品名称检测
	scanOptions = append(scanOptions, scanner.WithProductNameDetection(options.ProductNameDetection))

	// 设置是否使用信息检测
	scanOptions = append(scanOptions, scanner.WithInfoDetection(options.InfoDetection))

	return scanOptions
}

// enrichResultWithWebData 使用Web扫描数据丰富扫描结果
func (x *XMap) enrichResultWithWebData(result *model.ScanResult, webResult *web.ScanResult) {
	if result == nil || webResult == nil {
		return
	}
	// 确保Metadata已初始化
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	// 添加Banner信息到Metadata
	if webResult.Banner != nil {
		// 添加标题
		if webResult.Banner.Title != "" {
			result.Metadata["title"] = webResult.Banner.Title
		}
		// 添加状态码
		if webResult.Banner.StatusCode > 0 {
			result.Metadata["status_code"] = webResult.Banner.StatusCode
		}
		// 如果有HTTP响应体，添加到Metadata
		if webResult.Banner.Body != "" {
			result.Metadata["body"] = webResult.Banner.Body
		}
		if webResult.Banner.IconBytes != nil {
			result.Metadata["icon"] = base64.StdEncoding.EncodeToString(webResult.Banner.IconBytes)
		}
		if webResult.Banner.Certificate != "" {
			result.Metadata["certificate"] = webResult.Banner.Certificate
		}
		if webResult.Banner.Charset != "" {
			result.Metadata["charset"] = webResult.Banner.Charset
		}
		if webResult.Banner.Header != "" {
			result.Metadata["header"] = webResult.Banner.Header
		}
		if webResult.Banner.IconType != "" {
			result.Metadata["icon_type"] = webResult.Banner.IconType
		}
		if webResult.Banner.IconHash > 0 {
			result.Metadata["icon_hash"] = webResult.Banner.IconHash
		}
		if webResult.Banner.BodyHash > 0 {

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

// convertResult 转换扫描结果
func (x *XMap) convertResult(result *scanner.ScanResult, target *model.ScanTarget) *model.ScanResult {
	if result == nil {
		return nil
	}

	// 创建模型结果
	modelResult := &model.ScanResult{
		Target: &model.ScanTarget{
			IP:       target.IP,
			Port:     target.Port,
			Protocol: target.Protocol,
		},
		Service:      result.Service,
		MatchedProbe: result.MatchedProbe,
		Components:   []map[string]interface{}{},
		Duration:     result.Duration,
		Metadata:     make(map[string]interface{}),
	}

	if result.Extra != nil && len(result.Extra) > 0 {
		modelResult.Components = append(modelResult.Components, result.Extra)
	}

	// 设置错误信息
	if result.Error != nil {
		modelResult.Error = result.Error.Error()
	}

	// 设置原始响应数据
	if result.RawResponse != nil && len(result.RawResponse) > 0 {
		modelResult.Metadata["tcp_banner"] = base64.StdEncoding.EncodeToString(result.RawResponse)
	}

	return modelResult
}
