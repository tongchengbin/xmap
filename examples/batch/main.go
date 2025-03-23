package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/model"
)

func main() {
	// 设置日志级别
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	// 检查命令行参数
	if len(os.Args) < 2 {
		fmt.Println("使用方法: batch <targets_file>")
		fmt.Println("目标文件格式: 每行一个目标，格式为 ip:port 或 ip（默认使用80端口）")
		fmt.Println("示例: batch targets.txt")
		os.Exit(1)
	}

	// 读取目标文件
	targetsFile := os.Args[1]
	targets, err := readTargetsFile(targetsFile)
	if err != nil {
		fmt.Printf("读取目标文件失败: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 {
		fmt.Println("未找到有效目标")
		os.Exit(1)
	}

	fmt.Printf("已加载 %d 个目标\n", len(targets))

	// 创建XMap实例
	xmap := api.NewXMap(
		api.WithTimeout(5*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(7),
		api.WithMaxParallelism(50),
	)

	// 创建扫描选项
	options := &model.ScanOptions{
		Timeout:          5,
		Retries:          2,
		VersionIntensity: 7,
		FastMode:         true,
		MaxParallelism:   50,
	}

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 创建任务
	task := &model.ScanTask{
		ID:        "batch-task",
		Targets:   targets,
		Options:   options,
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	// 进度回调函数
	progressCallback := func(progress *model.ScanProgress) {
		fmt.Printf("\r进度: %.2f%% (%d/%d) - 成功: %d, 失败: %d, 预计剩余时间: %ds",
			progress.Percentage,
			progress.CompletedTargets,
			progress.TotalTargets,
			progress.SuccessTargets,
			progress.FailedTargets,
			progress.EstimatedTimeRemaining,
		)
	}

	// 执行扫描
	fmt.Printf("开始扫描 %d 个目标...\n", len(targets))
	startTime := time.Now()

	_, results, err := xmap.ExecuteTaskWithProgress(ctx, task, progressCallback)
	if err != nil {
		fmt.Printf("\n扫描失败: %v\n", err)
		os.Exit(1)
	}

	// 输出结果
	fmt.Println("\n\n扫描完成，耗时:", time.Since(startTime))
	fmt.Printf("总计 %d 个目标，发现 %d 个服务\n\n", len(targets), countServices(results))

	// 打印服务统计
	printServiceStats(results)

	// 保存结果到文件
	saveResultsToFile(results, "scan_results.csv")
}

// 读取目标文件
func readTargetsFile(filename string) ([]*model.ScanTarget, error) {
	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// 解析目标
	lines := strings.Split(string(data), "\n")
	targets := make([]*model.ScanTarget, 0, len(lines))

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析IP和端口
		ip, port := parseTarget(line)
		if ip == "" {
			continue
		}

		// 判断是否使用SSL
		useSSL := port == 443 || port == 8443

		// 创建目标
		target := &model.ScanTarget{
			IP:       ip,
			Port:     port,
			Protocol: "TCP",
			ID:       fmt.Sprintf("target-%d", i+1),
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// 解析目标
func parseTarget(target string) (string, int) {
	// 检查是否包含端口
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) != 2 {
			return "", 0
		}

		ip := parts[0]
		var port int
		_, err := fmt.Sscanf(parts[1], "%d", &port)
		if err != nil || port <= 0 || port >= 65536 {
			return ip, 80 // 默认端口
		}

		return ip, port
	}

	// 没有端口，使用默认端口
	return target, 80
}

// 统计服务数量
func countServices(results []*model.ScanResult) int {
	count := 0
	for _, result := range results {
		if result.Service != "" {
			count++
		}
	}
	return count
}

// 打印服务统计
func printServiceStats(results []*model.ScanResult) {
	// 统计服务类型
	serviceStats := make(map[string]int)
	for _, result := range results {
		if result.Service != "" {
			serviceStats[result.Service]++
		}
	}

	// 打印统计结果
	fmt.Println("服务统计:")
	fmt.Println("----------------------------------------")
	for service, count := range serviceStats {
		fmt.Printf("%-20s: %d\n", service, count)
	}
	fmt.Println("----------------------------------------")
}

// 保存结果到文件
func saveResultsToFile(results []*model.ScanResult, filename string) {
	// 创建文件
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("创建文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 写入CSV头
	file.WriteString("IP,端口,协议,服务,产品,版本,操作系统,设备类型,信息,匹配探针,耗时\n")

	// 写入结果
	for _, result := range results {
		line := fmt.Sprintf("%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			result.Target.IP,
			result.Target.Port,
			result.Target.Protocol,
			result.Service,
			result.ProductName,
			result.Version,
			result.OS,
			result.DeviceType,
			strings.ReplaceAll(result.Info, ",", " "), // 避免CSV格式问题
			result.MatchedProbe,
			result.Duration,
		)
		file.WriteString(line)
	}

	fmt.Printf("结果已保存到文件: %s\n", filename)
}
