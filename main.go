package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/output"
	"github.com/tongchengbin/xmap/pkg/types"
)

var (
	// 目标参数
	targetFlag     string
	targetFileFlag string
	portsFlag      string

	// 扫描选项
	timeoutFlag     int
	retriesFlag     int
	parallelismFlag int
	fastModeFlag    bool
	allProbesFlag   bool
	probeNamesFlag  string
	sslFlag         bool
	versionFlag     int

	// Web扫描选项
	fingerprintPathFlag string
	updateRuleFlag      bool
	proxyFlag           string
	disableIconFlag     bool
	disableJsFlag       bool
	debugRespFlag       bool

	// 输出选项
	outputFlag     string
	jsonFlag       bool
	csvFlag        bool
	verboseFlag    bool
	silentFlag     bool
	noProgressFlag bool

	// 其他选项
	helpFlag        bool
	versionInfoFlag bool
	examplesFlag    bool
)

// 版本信息
const version = "v0.1.0"

// banner
var banner = fmt.Sprintf(`
__  ____  ___           
\ \/ /  \/  / __ _ _ __  
 \  /| |\/| |/ _' | '_ \ 
 /  \| |  | | (_| | |_) |
/_/\_\_|  |_|\__,_| .__/ 
                  |_|    %s
`, version)

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("XMap 是一个网络扫描和指纹识别工具")

	// 创建目标参数组
	flagSet.CreateGroup("目标", "目标设置",
		flagSet.StringVarP(&targetFlag, "target", "t", "", "扫描目标，格式: ip:port 或 ip (使用默认端口)"),
		flagSet.StringVarP(&targetFileFlag, "target-file", "l", "", "包含扫描目标的文件，每行一个目标"),
		flagSet.StringVarP(&portsFlag, "ports", "p", "80,443,8080", "要扫描的端口，逗号分隔"),
	)

	// 创建扫描选项组
	flagSet.CreateGroup("扫描", "扫描选项",
		flagSet.IntVar(&timeoutFlag, "timeout", 5, "扫描超时时间(秒)"),
		flagSet.IntVarP(&retriesFlag, "retries", "r", 2, "扫描重试次数"),
		flagSet.IntVarP(&parallelismFlag, "parallelism", "c", 100, "最大并行扫描数"),
		flagSet.BoolVarP(&fastModeFlag, "fast", "f", false, "使用快速模式"),
		flagSet.BoolVar(&allProbesFlag, "all-probes", false, "使用所有探针"),
		flagSet.StringVar(&probeNamesFlag, "probes", "", "要使用的探针名称，逗号分隔"),
		flagSet.BoolVar(&sslFlag, "ssl", false, "使用SSL"),
		flagSet.IntVar(&versionFlag, "version-intensity", 7, "版本检测强度(0-9)"),
	)

	// 创建Web扫描选项组
	flagSet.CreateGroup("Web扫描", "Web扫描选项",
		flagSet.StringVarP(&fingerprintPathFlag, "fingerprint-path", "d", "", "指纹库路径，默认使用内置路径"),
		flagSet.BoolVarP(&updateRuleFlag, "update-rule", "ur", false, "更新指纹规则库"),
		flagSet.StringVarP(&proxyFlag, "proxy", "x", "", "HTTP代理，格式: http://host:port"),
		flagSet.BoolVarP(&disableIconFlag, "disable-icon", "di", false, "禁用图标请求匹配"),
		flagSet.BoolVarP(&disableJsFlag, "disable-js", "dj", false, "禁用JavaScript规则匹配"),
		flagSet.BoolVar(&debugRespFlag, "debug-resp", false, "调试HTTP响应"),
	)

	// 创建输出选项组
	flagSet.CreateGroup("输出", "输出选项",
		flagSet.StringVarP(&outputFlag, "output", "o", "", "输出结果到文件"),
		flagSet.BoolVarP(&jsonFlag, "json", "j", false, "以JSON格式输出"),
		flagSet.BoolVar(&csvFlag, "csv", false, "以CSV格式输出"),
		flagSet.BoolVarP(&verboseFlag, "verbose", "v", false, "显示详细信息"),
		flagSet.BoolVarP(&silentFlag, "silent", "s", false, "静默模式"),
		flagSet.BoolVar(&noProgressFlag, "no-progress", false, "不显示进度条"),
	)

	// 创建其他选项组
	flagSet.CreateGroup("其他", "其他选项",
		flagSet.BoolVarP(&helpFlag, "help", "h", false, "显示帮助信息"),
		flagSet.BoolVar(&versionInfoFlag, "version", false, "显示版本信息"),
		flagSet.BoolVarP(&examplesFlag, "examples", "e", false, "显示使用示例"),
	)

	// 解析命令行参数
	if err := flagSet.Parse(); err != nil {
		fmt.Println("解析命令行参数失败:", err.Error())
		os.Exit(1)
	}
}

func main() {
	// 显示版本信息
	if versionInfoFlag {
		fmt.Printf("XMap 版本: %s\n", version)
		return
	}

	// 显示banner
	if !silentFlag {
		fmt.Printf(banner)
	}

	// 设置日志级别
	if silentFlag {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if verboseFlag {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	// 更新指纹规则库
	if updateRuleFlag {
		gologger.Info().Msg("正在更新指纹规则库...")
		err := api.UpdateRules()
		if err != nil {
			gologger.Fatal().Msgf("更新指纹规则库失败: %v", err)
		}
		gologger.Info().Msg("指纹规则库更新成功")
		return
	}

	// 初始化规则库
	if fingerprintPathFlag != "" {
		gologger.Info().Msgf("使用指定的指纹库路径: %s", fingerprintPathFlag)
		err := api.InitRuleManager(fingerprintPathFlag)
		if err != nil {
			gologger.Warning().Msgf("初始化指纹库失败: %v", err)
		}
	}

	// 解析端口
	ports := parsePorts(portsFlag)

	// 解析目标
	targets, err := parseTargets(targetFlag, targetFileFlag, ports)
	if err != nil {
		gologger.Fatal().Msgf("解析目标失败: %v", err)
	}

	if len(targets) == 0 {
		gologger.Fatal().Msg("未指定扫描目标，使用 -target 或 -target-file 参数")
		return
	}

	// 解析探针名称
	var probeNames []string
	if probeNamesFlag != "" {
		probeNames = strings.Split(probeNamesFlag, ",")
	}

	// 创建扫描选项
	scanOptions := &types.ScanOptions{
		Timeout:          timeoutFlag,
		Retries:          retriesFlag,
		UseSSL:           sslFlag,
		VersionIntensity: versionFlag,
		MaxParallelism:   parallelismFlag,
		FastMode:         fastModeFlag,
		UseAllProbes:     allProbesFlag,
		ProbeNames:       probeNames,
		ServiceDetection: true,
		VersionDetection: true,
		// Web扫描选项
		Proxy:         proxyFlag,
		DisableIcon:   disableIconFlag,
		DisableJS:     disableJsFlag,
		DebugResponse: debugRespFlag,
	}

	// 创建XMap实例
	xmapInstance := api.NewXMap(
		api.WithTimeout(time.Duration(timeoutFlag)*time.Second),
		api.WithRetries(retriesFlag),
		api.WithVersionIntensity(versionFlag),
		api.WithMaxParallelism(parallelismFlag),
		api.WithFastMode(fastModeFlag),
		api.WithVerbose(verboseFlag),
		api.WithDebugResponse(debugRespFlag),
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

	// 创建结果输出器
	var outer output.Outer
	if jsonFlag {
		outer = output.NewJSONOuter(outputFlag)
	} else if csvFlag {
		outer = output.NewCSVOuter(outputFlag)
	} else {
		outer = output.NewConsoleOuter(outputFlag, silentFlag)
	}

	// 执行扫描
	err = xmapInstance.ExecuteWithResultCallback(ctx, targets, scanOptions,
		// 进度回调
		func(completed, total int, percentage float64, status string) {
			if silentFlag || noProgressFlag {
				return
			}

			// 计算成功和失败数量（简化实现）
			success := completed
			failed := 0

			fmt.Printf("\r进度: %.2f%% (%d/%d) - 成功: %d, 失败: %d, 状态: %s",
				percentage,
				completed,
				total,
				success,
				failed,
				status,
			)
		},
		// 结果回调 - 每当有一个结果就立即输出
		func(result *types.ScanResult) {
			// 使用输出器输出结果
			err := outer.Output(result)
			if err != nil {
				gologger.Error().Msgf("输出结果失败: %v", err)
			}
		},
	)
	if err != nil {
		gologger.Fatal().Msgf("扫描失败: %v", err)
		return
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
func parseTargets(targetStr, targetFile string, ports []int) ([]*types.ScanTarget, error) {
	targets := make([]*types.ScanTarget, 0)

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
func parseTargetString(targetStr string, ports []int) []*types.ScanTarget {
	targets := make([]*types.ScanTarget, 0)

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
			targets = append(targets, &types.ScanTarget{
				IP:       ip,
				Port:     port,
				Protocol: "tcp",
			})
		} else {
			// 否则使用所有指定的端口
			for _, p := range ports {
				targets = append(targets, &types.ScanTarget{
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
func parseTargetFile(filename string, ports []int) ([]*types.ScanTarget, error) {
	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取目标文件失败: %v", err)
	}

	// 解析每一行
	lines := strings.Split(string(data), "\n")
	targets := make([]*types.ScanTarget, 0, len(lines)*len(ports))

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
