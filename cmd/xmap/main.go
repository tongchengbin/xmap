package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/model"
)

var (
	// 目标参数
	targetFlag     = flag.String("target", "", "扫描目标，格式: ip:port 或 ip (使用默认端口)")
	targetFileFlag = flag.String("target-file", "", "包含扫描目标的文件，每行一个目标")
	portsFlag      = flag.String("ports", "80,443,8080", "要扫描的端口，逗号分隔")

	// 扫描选项
	timeoutFlag     = flag.Int("timeout", 5, "扫描超时时间(秒)")
	retriesFlag     = flag.Int("retries", 2, "扫描重试次数")
	parallelismFlag = flag.Int("parallelism", 100, "最大并行扫描数")
	fastModeFlag    = flag.Bool("fast", false, "使用快速模式")
	allProbesFlag   = flag.Bool("all-probes", false, "使用所有探针")
	probeNamesFlag  = flag.String("probes", "", "要使用的探针名称，逗号分隔")
	sslFlag         = flag.Bool("ssl", false, "使用SSL")
	versionFlag     = flag.Int("version-intensity", 7, "版本检测强度(0-9)")

	// 输出选项
	outputFlag     = flag.String("output", "", "输出结果到文件")
	jsonFlag       = flag.Bool("json", false, "以JSON格式输出")
	csvFlag        = flag.Bool("csv", false, "以CSV格式输出")
	verboseFlag    = flag.Bool("verbose", false, "显示详细信息")
	silentFlag     = flag.Bool("silent", false, "静默模式")
	noProgressFlag = flag.Bool("no-progress", false, "不显示进度条")

	// 其他选项
	helpFlag        = flag.Bool("help", false, "显示帮助信息")
	versionInfoFlag = flag.Bool("version", false, "显示版本信息")
	examplesFlag    = flag.Bool("examples", false, "显示使用示例")
)

const (
	version = "1.0.0"
	banner  = `
 __   __  __    __   _______  _______  
|  |_|  ||  |  |  | |   _   ||       | 
|       ||  |__|  | |  |_|  ||    _  | 
|       ||       | |       ||   |_| | 
|_     _||_     _| |       ||    ___| 
  |   |    |   |   |   _   ||   |     
  |___|    |___|   |__| |__||___|     v%s
                                      
高性能分布式网络服务指纹识别框架
`
)

func showHelp() {
	fmt.Printf(banner, version)
	fmt.Println("\n使用方法:")
	fmt.Println("  xmap [选项] -target <目标> 或 -target-file <目标文件>")
	fmt.Println("\n示例:")
	fmt.Println("  xmap -target 192.168.1.1")
	fmt.Println("  xmap -target-file targets.txt -ports 80,443,8080-8090")
	fmt.Println("  xmap -target 192.168.1.1 -fast -output results.json -json")
	fmt.Println("\n选项:")
	flag.PrintDefaults()
}

func showExamples() {
	fmt.Printf(banner, version)
	fmt.Println("\n使用示例:")
	fmt.Println("1. 扫描单个目标:")
	fmt.Println("   xmap -target 192.168.1.1")
	fmt.Println("\n2. 扫描多个端口:")
	fmt.Println("   xmap -target 192.168.1.1 -ports 80,443,8080-8090")
	fmt.Println("\n3. 从文件读取目标:")
	fmt.Println("   xmap -target-file targets.txt")
	fmt.Println("\n4. 使用快速模式:")
	fmt.Println("   xmap -target 192.168.1.1 -fast")
	fmt.Println("\n5. 输出JSON格式结果:")
	fmt.Println("   xmap -target 192.168.1.1 -output results.json -json")
	fmt.Println("\n6. 使用特定探针:")
	fmt.Println("   xmap -target 192.168.1.1 -probes http,https,ssh")
	fmt.Println("\n7. 高并发扫描:")
	fmt.Println("   xmap -target-file large-targets.txt -parallelism 500")
}

func main() {
	// 解析命令行参数
	flag.Parse()

	// 显示版本信息
	if *versionInfoFlag {
		fmt.Printf("XMap 版本: %s\n", version)
		return
	}

	// 显示帮助信息
	if *helpFlag {
		showHelp()
		return
	}

	// 显示使用示例
	if *examplesFlag {
		showExamples()
		return
	}

	// 显示banner
	if !*silentFlag {
		fmt.Printf(banner, version)
	}

	// 设置日志级别
	if *silentFlag {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if *verboseFlag {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	// 解析端口
	ports := parsePorts(*portsFlag)

	// 解析目标
	targets, err := parseTargets(*targetFlag, *targetFileFlag, ports)
	if err != nil {
		gologger.Fatal().Msgf("解析目标失败: %v", err)
	}

	if len(targets) == 0 {
		gologger.Fatal().Msg("未指定扫描目标，使用 -target 或 -target-file 参数")
		showHelp()
		return
	}

	// 解析探针名称
	var probeNames []string
	if *probeNamesFlag != "" {
		probeNames = strings.Split(*probeNamesFlag, ",")
	}

	// 创建扫描选项
	options := &model.ScanOptions{
		Timeout:          *timeoutFlag,
		Retries:          *retriesFlag,
		UseSSL:           *sslFlag,
		VersionIntensity: *versionFlag,
		MaxParallelism:   *parallelismFlag,
		FastMode:         *fastModeFlag,
		UseAllProbes:     *allProbesFlag,
		ProbeNames:       probeNames,
		ServiceDetection: true,
		VersionDetection: true,
	}

	// 创建XMap实例
	xmapInstance := api.NewXMap(
		api.WithTimeout(time.Duration(*timeoutFlag)*time.Second),
		api.WithRetries(*retriesFlag),
		api.WithVersionIntensity(*versionFlag),
		api.WithMaxParallelism(*parallelismFlag),
		api.WithFastMode(*fastModeFlag),
	)

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理中断信号
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		gologger.Info().Msg("接收到中断信号，正在停止扫描...")
		cancel()
	}()

	// 创建任务
	task := &model.ScanTask{
		ID:        "cmd-task",
		Targets:   targets,
		Options:   options,
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	// 进度回调函数
	progressCallback := func(progress *model.ScanProgress) {
		if !*silentFlag && !*noProgressFlag {
			fmt.Printf("\r进度: %.2f%% (%d/%d) - 成功: %d, 失败: %d, 预计剩余时间: %ds",
				progress.Percentage,
				progress.CompletedTargets,
				progress.TotalTargets,
				progress.SuccessTargets,
				progress.FailedTargets,
				progress.EstimatedTimeRemaining,
			)
		}
	}

	// 执行扫描
	gologger.Info().Msgf("开始扫描 %d 个目标...", len(targets))
	startTime := time.Now()

	_, results, err := xmapInstance.ExecuteTaskWithProgress(ctx, task, progressCallback)
	if err != nil {
		gologger.Fatal().Msgf("扫描失败: %v", err)
	}

	// 输出结果
	if !*silentFlag && !*noProgressFlag {
		fmt.Println() // 换行
	}
	gologger.Info().Msgf("扫描完成，耗时: %s", time.Since(startTime))
	gologger.Info().Msgf("扫描结果: 总计 %d 个目标，发现 %d 个服务", len(targets), countServices(results))

	// 输出详细结果
	if !*silentFlag {
		if *jsonFlag {
			printResultsJSON(results)
		} else if *csvFlag {
			printResultsCSV(results)
		} else {
			printResults(results)
		}
	}

	// 保存结果到文件
	if *outputFlag != "" {
		var format string
		if *jsonFlag {
			format = "json"
		} else if *csvFlag {
			format = "csv"
		} else {
			format = "txt"
		}

		err := saveResults(results, *outputFlag, format)
		if err != nil {
			gologger.Error().Msgf("保存结果失败: %v", err)
		} else {
			gologger.Info().Msgf("结果已保存到文件: %s", *outputFlag)
		}
	}
}

// 解析端口
func parsePorts(portsStr string) []int {
	if portsStr == "" {
		return []int{80} // 默认端口
	}

	portStrs := strings.Split(portsStr, ",")
	ports := make([]int, 0, len(portStrs))

	for _, portStr := range portStrs {
		// 处理端口范围 (例如 8080-8090)
		if strings.Contains(portStr, "-") {
			rangeParts := strings.Split(portStr, "-")
			if len(rangeParts) != 2 {
				continue
			}

			var startPort, endPort int
			_, err1 := fmt.Sscanf(rangeParts[0], "%d", &startPort)
			_, err2 := fmt.Sscanf(rangeParts[1], "%d", &endPort)

			if err1 != nil || err2 != nil || startPort > endPort {
				continue
			}

			for port := startPort; port <= endPort; port++ {
				if port > 0 && port < 65536 {
					ports = append(ports, port)
				}
			}
			continue
		}

		// 处理单个端口
		var port int
		_, err := fmt.Sscanf(portStr, "%d", &port)
		if err != nil {
			continue
		}
		if port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}

	if len(ports) == 0 {
		return []int{80} // 默认端口
	}

	return ports
}

// 解析目标
func parseTargets(targetStr, targetFile string, ports []int) ([]*model.ScanTarget, error) {
	targets := make([]*model.ScanTarget, 0)

	// 从命令行参数解析目标
	if targetStr != "" {
		parsedTargets := parseTargetString(targetStr, ports)
		targets = append(targets, parsedTargets...)
	}

	// 从文件解析目标
	if targetFile != "" {
		fileTargets, err := parseTargetFile(targetFile, ports)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	return targets, nil
}

// 解析目标字符串
func parseTargetString(targetStr string, ports []int) []*model.ScanTarget {
	targets := make([]*model.ScanTarget, 0)

	// 处理多个目标，以逗号分隔
	targetStrs := strings.Split(targetStr, ",")
	for _, target := range targetStrs {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// 解析IP和端口
		ip, port, err := parseIPPort(target)
		if err != nil {
			gologger.Warning().Msgf("解析目标失败: %v", err)
			continue
		}

		// 如果指定了端口，只使用该端口
		if port > 0 {
			targets = append(targets, &model.ScanTarget{
				IP:       ip,
				Port:     port,
				Protocol: "tcp",
			})
		} else {
			// 否则使用所有指定的端口
			for _, p := range ports {
				targets = append(targets, &model.ScanTarget{
					IP:       ip,
					Port:     p,
					Protocol: "tcp",
				})
			}
		}
	}

	return targets
}

// 从文件解析目标
func parseTargetFile(filename string, ports []int) ([]*model.ScanTarget, error) {
	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取目标文件失败: %v", err)
	}

	// 解析每一行
	lines := strings.Split(string(data), "\n")
	targets := make([]*model.ScanTarget, 0, len(lines)*len(ports))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 将每一行作为目标字符串解析
		lineTargets := parseTargetString(line, ports)
		targets = append(targets, lineTargets...)
	}

	return targets, nil
}

// 解析IP和端口
func parseIPPort(target string) (string, int, error) {
	// 检查是否包含端口
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) != 2 {
			return "", 0, fmt.Errorf("无效的目标格式: %s", target)
		}

		ip := parts[0]
		var port int
		_, err := fmt.Sscanf(parts[1], "%d", &port)
		if err != nil || port <= 0 || port >= 65536 {
			return "", 0, fmt.Errorf("无效的端口: %s", parts[1])
		}

		return ip, port, nil
	}

	// 没有端口，只返回IP
	return target, 0, nil
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

// 打印结果
func printResults(results []*model.ScanResult) {
	if len(results) == 0 {
		fmt.Println("未发现任何服务")
		return
	}

	// 表格形式打印
	fmt.Println("-------------------------------------------------------------------------------------------------------------------")
	fmt.Printf("%-20s %-10s %-15s %-15s %-15s %-20s\n", "目标", "端口", "服务", "产品", "版本", "信息")
	fmt.Println("-------------------------------------------------------------------------------------------------------------------")

	for _, result := range results {
		fmt.Printf("%-20s %-10d %-15s %-15s %-15s %-20s\n",
			result.Target.IP,
			result.Target.Port,
			truncateString(result.Service, 15),
			truncateString(result.ProductName, 15),
			truncateString(result.Version, 15),
			truncateString(result.Info, 20),
		)
	}
	fmt.Println("-------------------------------------------------------------------------------------------------------------------")
}

// 打印JSON格式结果
func printResultsJSON(results []*model.ScanResult) {
	fmt.Println("[")
	for i, result := range results {
		jsonResult := fmt.Sprintf(`  {
    "target": "%s:%d",
    "protocol": "%s",
    "service": "%s",
    "product": "%s",
    "version": "%s",
    "os": "%s",
    "info": "%s",
    "matched_probe": "%s",
    "duration": "%s"
  }`,
			result.Target.IP,
			result.Target.Port,
			result.Target.Protocol,
			result.Service,
			result.ProductName,
			result.Version,
			result.OS,
			result.Info,
			result.MatchedProbe,
			result.Duration,
		)
		fmt.Print(jsonResult)
		if i < len(results)-1 {
			fmt.Println(",")
		} else {
			fmt.Println("")
		}
	}
	fmt.Println("]")
}

// 打印CSV格式结果
func printResultsCSV(results []*model.ScanResult) {
	// 打印CSV头
	fmt.Println("IP,Port,Protocol,Service,Version,Banner")

	for _, result := range results {
		ip := result.Target.IP
		port := result.Target.Port
		protocol := result.Target.Protocol
		service := result.Service
		version := result.Version
		info := strings.ReplaceAll(truncateString(result.Info, 50), "\n", " ")

		fmt.Printf("%s,%d,%s,%s,%s,%s\n",
			ip, port, protocol, service, version, info)
	}
}

// 保存结果到文件
func saveResults(results []*model.ScanResult, filename string, format string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 重定向标准输出到文件
	oldStdout := os.Stdout
	os.Stdout = file

	switch format {
	case "json":
		printResultsJSON(results)
	case "csv":
		printResultsCSV(results)
	default:
		printResults(results)
	}

	// 恢复标准输出
	os.Stdout = oldStdout

	return nil
}

// 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
