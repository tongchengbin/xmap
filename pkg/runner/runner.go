package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/output"
	"github.com/tongchengbin/xmap/pkg/types"
	"github.com/tongchengbin/xmap/pkg/utils"
)

// Runner 结构体包含扫描运行时所需的所有内容
type Runner struct {
	options *Options
	xmap    *api.XMap
}

// New 创建一个新的Runner实例
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	// 设置日志级别
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	// 创建XMap实例
	xmapInstance := api.NewXMap(
		api.WithTimeout(time.Duration(options.Timeout)*time.Second),
		api.WithRetries(options.Retries),
		api.WithVersionIntensity(options.VersionIntensity),
		api.WithMaxParallelism(options.Workers),
		api.WithFastMode(options.FastMode),
		api.WithVerbose(options.Verbose),
		api.WithDebugResponse(options.DebugResponse),
	)

	runner.xmap = xmapInstance
	return runner, nil
}

// ShowBanner 显示程序的banner
func (r *Runner) ShowBanner() {
	if !r.options.Silent {
		fmt.Print(r.options.Banner)
	}
}

// UpdateRules 更新指纹规则库
func (r *Runner) UpdateRules() error {
	gologger.Info().Msg("正在更新指纹规则库...")
	err := api.UpdateRules()
	if err != nil {
		return err
	}
	gologger.Info().Msg("指纹规则库更新成功")
	return nil
}

// InitRuleManager 初始化规则管理器
func (r *Runner) InitRuleManager() error {
	if r.options.AppFingerHome != "" {
		gologger.Info().Msgf("使用指定的指纹库路径: %s", r.options.AppFingerHome)
		err := api.InitRuleManager(r.options.AppFingerHome)
		if err != nil {
			return err
		}
	}
	return nil
}

// Run 执行扫描
func (r *Runner) Run() error {
	// 初始化规则管理器
	if err := r.InitRuleManager(); err != nil {
		gologger.Warning().Msgf("初始化指纹库失败: %v", err)
	}

	// 解析端口
	ports := utils.ParsePorts(r.options.Ports)

	// 创建未解析的目标列表
	var unparsedTargets []*types.ScanTarget

	// 从命令行参数创建未解析的目标
	if len(r.options.Target) > 0 {
		unparsedTargets = append(unparsedTargets, utils.CreateUnparsedTargets(r.options.Target)...)
	}

	// 从文件创建未解析的目标
	if r.options.TargetFile != "" {
		fileTargets, err := utils.CreateUnparsedTargetsFromFile(r.options.TargetFile)
		if err != nil {
			return fmt.Errorf("从文件加载目标失败: %v", err)
		}
		unparsedTargets = append(unparsedTargets, fileTargets...)
	}

	if len(unparsedTargets) == 0 {
		return fmt.Errorf("未指定扫描目标，使用 -target 或 -target-file 参数")
	}

	// 延迟解析目标
	targets := make([]*types.ScanTarget, 0, len(unparsedTargets))
	for _, target := range unparsedTargets {
		parsedTargets := utils.ParseTarget(target, ports)
		if len(parsedTargets) > 0 {
			targets = append(targets, parsedTargets...)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("所有目标解析失败，请检查目标格式")
	}
	gologger.Info().Msgf("共解析到 %d 个有效目标", len(targets))
	// 解析探针名称
	var probeNames []string
	if len(r.options.NmapProneName) > 0 {
		probeNames = r.options.NmapProneName
	}
	// 创建扫描选项
	scanOptions := &types.ScanOptions{
		Timeout:          r.options.Timeout,
		Retries:          r.options.Retries,
		UseSSL:           r.options.UseSSL,
		VersionIntensity: r.options.VersionIntensity,
		MaxParallelism:   r.options.Workers,
		FastMode:         r.options.FastMode,
		UseAllProbes:     r.options.UseAllProbes,
		ProbeNames:       probeNames,
		ServiceDetection: true,
		VersionDetection: r.options.ServiceVersion,
		// Web扫描选项
		Proxy:         r.options.Proxy,
		DisableIcon:   r.options.DisableIcon,
		DisableJS:     r.options.DisableJS,
		DebugResponse: r.options.DebugResponse,
	}

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
	// 始终创建控制台输出器，确保控制台实时显示结果
	consoleOuter := output.NewConsoleOuter("", r.options.Silent)

	// 创建文件输出器（如果需要）
	var fileOuter output.Outer
	if r.options.Output != "" {
		switch r.options.OutType {
		case "json":
			fileOuter = output.NewJSONOuter(r.options.Output)
		case "csv":
			fileOuter = output.NewCSVOuter(r.options.Output)
		default:
			fileOuter = output.NewConsoleOuter(r.options.Output, false) // 文件输出不需要静默模式
		}
	}

	// 创建进度跟踪器
	var progressTracker *utils.Progress
	if !r.options.Silent && !r.options.NoProgress {
		progressTracker = utils.NewProgress("扫描进度", len(targets))
		go progressTracker.Start()
	}

	// 执行扫描
	err := r.xmap.ExecuteWithResultCallback(ctx, targets, scanOptions,
		// 结果回调 - 每当有一个结果就立即输出
		func(result *types.ScanResult) {
			// 更新进度
			if progressTracker != nil {
				progressTracker.Increment()
			}

			// 始终在控制台显示结果
			err := consoleOuter.Output(result)
			if err != nil {
				gologger.Error().Msgf("控制台输出失败: %v", err)
			}

			// 如果指定了文件输出，也输出到文件
			if fileOuter != nil {
				err := fileOuter.Output(result)
				if err != nil {
					gologger.Error().Msgf("文件输出失败: %v", err)
				}
			}
		},
	)
	if err != nil {
		return fmt.Errorf("扫描失败: %v", err)
	}
	return nil
}
