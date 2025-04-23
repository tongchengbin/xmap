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

	// 解析目标
	targets, err := utils.ParseTargets(r.options.Target, r.options.TargetFile, ports)
	if err != nil {
		return fmt.Errorf("解析目标失败: %v", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("未指定扫描目标，使用 -target 或 -target-file 参数")
	}

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
	var outer output.Outer
	switch r.options.OutType {
	case "json":
		outer = output.NewJSONOuter(r.options.Output)
	case "csv":
		outer = output.NewCSVOuter(r.options.Output)
	default:
		outer = output.NewConsoleOuter(r.options.Output, r.options.Silent)
	}

	// 创建进度跟踪器
	var progressTracker *utils.Progress
	if !r.options.Silent && !r.options.NoProgress {
		progressTracker = utils.NewProgress("扫描进度", len(targets))
		go progressTracker.Start()
	}

	// 执行扫描
	err = r.xmap.ExecuteWithResultCallback(ctx, targets, scanOptions,
		// 结果回调 - 每当有一个结果就立即输出
		func(result *types.ScanResult) {
			// 更新进度
			if progressTracker != nil {
				progressTracker.Increment()
			}

			// 使用输出器输出结果
			err := outer.Output(result)
			if err != nil {
				gologger.Error().Msgf("输出结果失败: %v", err)
			}
		},
	)
	if err != nil {
		return fmt.Errorf("扫描失败: %v", err)
	}

	return nil
}
