package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/model"
)

func main() {
	// 设置日志级别
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	// 创建XMap实例
	xmap := api.NewXMap(
		api.WithTimeout(5*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(9), // 使用最高版本检测强度
		api.WithMaxParallelism(100),
	)

	// 创建示例目标
	targets := []*model.ScanTarget{
		// HTTP服务
		{
			IP:       "example.com",
			Port:     80,
			Protocol: "TCP",
			ID:       "http-target",
		},
		// HTTPS服务
		{
			IP:       "example.com",
			Port:     443,
			Protocol: "TCP",
			ID:       "https-target",
		},
		// SSH服务
		{
			IP:       "example.com",
			Port:     22,
			Protocol: "TCP",
			ID:       "ssh-target",
		},
	}

	// 创建上下文（支持取消）
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理中断信号
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		fmt.Println("\n接收到中断信号，正在停止扫描...")
		cancel()
	}()

	// 示例1：使用不同的扫描选项
	fmt.Println("=== 示例1：使用不同的扫描选项 ===")
	demonstrateScanOptions(ctx, xmap, targets[0])

	// 示例2：自定义探针选择
	fmt.Println("\n=== 示例2：自定义探针选择 ===")
	demonstrateCustomProbes(ctx, xmap, targets)

	// 示例3：并发扫描与进度跟踪
	fmt.Println("\n=== 示例3：并发扫描与进度跟踪 ===")
	demonstrateConcurrentScanning(ctx, xmap)

	// 示例4：错误处理与重试
	fmt.Println("\n=== 示例4：错误处理与重试 ===")
	demonstrateErrorHandling(ctx, xmap)
}

// 示例1：展示不同的扫描选项
func demonstrateScanOptions(ctx context.Context, xmap *api.XMap, target *model.ScanTarget) {
	fmt.Println("1.1 使用快速模式（只使用常用探针）")
	fastOptions := &model.ScanOptions{
		Timeout:          3,
		Retries:          1,
		VersionIntensity: 5,
		FastMode:         true,
	}
	result, err := xmap.Scan(ctx, target, fastOptions)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
	} else {
		fmt.Printf("快速模式扫描完成，耗时: %s，服务: %s\n", result.Duration, result.Service)
	}

	fmt.Println("\n1.2 使用全面模式（使用所有探针）")
	thoroughOptions := &model.ScanOptions{
		Timeout:          10,
		Retries:          2,
		VersionIntensity: 9,
		UseAllProbes:     true,
		FastMode:         false,
	}
	result, err = xmap.Scan(ctx, target, thoroughOptions)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
	} else {
		fmt.Printf("全面模式扫描完成，耗时: %s，服务: %s\n", result.Duration, result.Service)
	}

	fmt.Println("\n1.3 使用自定义超时和重试")
	customOptions := &model.ScanOptions{
		Timeout:          1, // 非常短的超时
		Retries:          5, // 多次重试
		VersionIntensity: 7,
		FastMode:         true,
	}
	result, err = xmap.Scan(ctx, target, customOptions)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
	} else {
		fmt.Printf("自定义超时重试扫描完成，耗时: %s，服务: %s\n", result.Duration, result.Service)
	}
}

// 示例2：展示自定义探针选择
func demonstrateCustomProbes(ctx context.Context, xmap *api.XMap, targets []*model.ScanTarget) {
	// 2.1 只使用HTTP探针
	fmt.Println("2.1 只使用HTTP探针")
	httpOptions := &model.ScanOptions{
		Timeout:          5,
		Retries:          2,
		VersionIntensity: 7,
		ProbeNames:       []string{"GetRequest", "HTTPOptions", "RTSPRequest"},
	}

	for _, target := range targets {
		result, err := xmap.Scan(ctx, target, httpOptions)
		if err != nil {
			fmt.Printf("目标 %s:%d 扫描失败: %v\n", target.IP, target.Port, err)
		} else {
			fmt.Printf("目标 %s:%d 使用HTTP探针扫描完成，服务: %s\n",
				target.IP, target.Port, result.Service)
		}
	}

	// 2.2 只使用SSL探针
	fmt.Println("\n2.2 只使用SSL探针")
	sslOptions := &model.ScanOptions{
		Timeout:          5,
		Retries:          2,
		VersionIntensity: 7,
		ProbeNames:       []string{"SSLSessionReq", "TLSSessionReq"},
		UseSSL:           true,
	}

	for _, target := range targets {
		if target.Port == 443 {
			result, err := xmap.Scan(ctx, target, sslOptions)
			if err != nil {
				fmt.Printf("目标 %s:%d 扫描失败: %v\n", target.IP, target.Port, err)
			} else {
				fmt.Printf("目标 %s:%d 使用SSL探针扫描完成，服务: %s\n",
					target.IP, target.Port, result.Service)
			}
		}
	}

	// 2.3 使用端口特定探针
	fmt.Println("\n2.3 使用端口特定探针")
	for _, target := range targets {
		var probeNames []string

		// 根据端口选择探针
		switch target.Port {
		case 22:
			probeNames = []string{"SSHv2", "SSHv1"}
		case 80:
			probeNames = []string{"GetRequest", "HTTPOptions"}
		case 443:
			probeNames = []string{"SSLSessionReq", "TLSSessionReq"}
		default:
			probeNames = []string{"NULL"}
		}

		portOptions := &model.ScanOptions{
			Timeout:          5,
			Retries:          2,
			VersionIntensity: 7,
			ProbeNames:       probeNames,
			UseSSL:           target.Port == 443,
		}

		result, err := xmap.Scan(ctx, target, portOptions)
		if err != nil {
			fmt.Printf("目标 %s:%d 扫描失败: %v\n", target.IP, target.Port, err)
		} else {
			fmt.Printf("目标 %s:%d 使用端口特定探针扫描完成，服务: %s\n",
				target.IP, target.Port, result.Service)
		}
	}
}

// 示例3：展示并发扫描与进度跟踪
func demonstrateConcurrentScanning(ctx context.Context, xmap *api.XMap) {
	// 创建大量目标
	targets := make([]*model.ScanTarget, 0, 100)
	for i := 0; i < 100; i++ {
		targets = append(targets, &model.ScanTarget{
			IP:       "example.com",
			Port:     80 + i%10, // 使用不同端口
			Protocol: "TCP",
			ID:       fmt.Sprintf("target-%03d", i+1),
		})
	}

	// 创建扫描选项
	options := &model.ScanOptions{
		Timeout:          3,
		Retries:          1,
		VersionIntensity: 5,
		FastMode:         true,
		MaxParallelism:   20, // 设置并发数
	}

	// 创建任务
	task := &model.ScanTask{
		ID:        "concurrent-task",
		Targets:   targets,
		Options:   options,
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	// 进度回调函数
	var lastUpdateTime time.Time
	progressCallback := func(progress *model.ScanProgress) {
		// 限制更新频率
		if time.Since(lastUpdateTime) < 200*time.Millisecond {
			return
		}
		lastUpdateTime = time.Now()

		fmt.Printf("\r进度: %.2f%% (%d/%d) - 成功: %d, 失败: %d, 预计剩余时间: %ds",
			progress.Percentage,
			progress.CompletedTargets,
			progress.TotalTargets,
			progress.SuccessTargets,
			progress.FailedTargets,
			progress.EstimatedTimeRemaining,
		)
	}

	// 执行任务
	fmt.Printf("开始并发扫描 %d 个目标...\n", len(targets))
	startTime := time.Now()

	_, results, err := xmap.ExecuteTaskWithProgress(ctx, task, progressCallback)
	if err != nil {
		fmt.Printf("\n任务执行失败: %v\n", err)
		return
	}

	// 输出结果统计
	fmt.Printf("\n\n并发扫描完成，总耗时: %s\n", time.Since(startTime))

	// 统计服务类型
	serviceStats := make(map[string]int)
	for _, result := range results {
		if result.Service != "" {
			serviceStats[result.Service]++
		}
	}

	fmt.Println("服务统计:")
	for service, count := range serviceStats {
		fmt.Printf("- %s: %d\n", service, count)
	}
}

// 示例4：展示错误处理与重试
func demonstrateErrorHandling(ctx context.Context, xmap *api.XMap) {
	// 创建一个无效目标
	invalidTarget := &model.ScanTarget{
		IP:       "invalid-host-that-does-not-exist.example",
		Port:     80,
		Protocol: "TCP",
		ID:       "invalid-target",
	}

	// 创建一个超时非常短的选项
	shortTimeoutOptions := &model.ScanOptions{
		Timeout:          1, // 1秒超时
		Retries:          0, // 不重试
		VersionIntensity: 5,
		FastMode:         true,
	}

	// 4.1 处理无效目标
	fmt.Println("4.1 处理无效目标")
	result, err := xmap.Scan(ctx, invalidTarget, nil)
	if err != nil {
		fmt.Printf("扫描失败（预期行为）: %v\n", err)
	} else {
		fmt.Printf("扫描完成，但可能有错误: %s\n", result.Error)
	}

	// 4.2 处理超时
	fmt.Println("\n4.2 处理超时")
	timeoutTarget := &model.ScanTarget{
		IP:       "example.com",
		Port:     80,
		Protocol: "TCP",
		ID:       "timeout-target",
	}

	result, err = xmap.Scan(ctx, timeoutTarget)
	if err != nil {
		fmt.Printf("扫描超时（预期行为）: %v\n", err)
	} else if result.Error != "" {
		fmt.Printf("扫描完成，但有错误: %s\n", result.Error)
	} else {
		fmt.Printf("扫描成功（意外）: %s\n", result.Service)
	}

	// 4.3 使用重试机制
	fmt.Println("\n4.3 使用重试机制")
	retryOptions := &model.ScanOptions{
		Timeout:          1, // 1秒超时
		Retries:          5, // 5次重试
		VersionIntensity: 5,
		FastMode:         true,
	}

	result, err = xmap.Scan(ctx, timeoutTarget, retryOptions)
	if err != nil {
		fmt.Printf("尽管重试，扫描仍然失败: %v\n", err)
	} else if result.Error != "" {
		fmt.Printf("扫描完成，但有错误: %s\n", result.Error)
	} else {
		fmt.Printf("重试后扫描成功: %s\n", result.Service)
	}

	// 4.4 使用上下文取消
	fmt.Println("\n4.4 使用上下文取消")
	cancelCtx, cancelFunc := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		longTimeoutOptions := &model.ScanOptions{
			Timeout:          30,   // 30秒超时
			Retries:          3,    // 3次重试
			VersionIntensity: 9,    // 高强度版本检测
			UseAllProbes:     true, // 使用所有探针
		}

		fmt.Println("开始长时间扫描...")
		result, err := xmap.Scan(cancelCtx, timeoutTarget, longTimeoutOptions)
		if err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				fmt.Println("扫描被取消（预期行为）")
			} else {
				fmt.Printf("扫描失败: %v\n", err)
			}
		} else {
			fmt.Printf("扫描完成: %s\n", result.Service)
		}
	}()

	// 等待1秒后取消
	time.Sleep(1 * time.Second)
	fmt.Println("取消扫描...")
	cancelFunc()

	// 等待扫描结束
	wg.Wait()
}
