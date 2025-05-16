package runner

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/input"
	"github.com/tongchengbin/xmap/pkg/output"
	"github.com/tongchengbin/xmap/pkg/types"
	"github.com/tongchengbin/xmap/pkg/utils"
	"os"
	"os/signal"
)

// Runner 结构体包含扫描运行时所需的所有内容
type Runner struct {
	// 全局选项
	options *types.Options
	// XMap API 实例
	xmap *api.XMap
	// 输入提供者
	inputProvider input.Provider
}

// New 创建一个新的Runner实例
func New(options *types.Options) (*Runner, error) {
	// 初始化日志
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	// 直接使用全局选项创建 XMap 实例
	xmapInstance, err := api.New(options)
	if err != nil {
		return nil, err
	}
	// 创建并返回 Runner 实例
	return &Runner{
		options: options,
		xmap:    xmapInstance,
	}, nil
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
	err := r.xmap.UpdateRules()
	if err != nil {
		return err
	}
	gologger.Info().Msg("指纹规则库更新成功")
	return nil
}

// InitRuleManager 初始化规则管理器
func (r *Runner) InitRuleManager() error {
	// 规则管理器已在 XMap 初始化时自动初始化
	return nil
}

// RunEnumeration 执行扫描
func (r *Runner) RunEnumeration() error {
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
		switch r.options.OutputType {
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
		//go progressTracker.Start()
	}
	// 创建输入提供者
	inputProvider, err := input.CreateProviderFromOptions(r.options)
	if err != nil {
		return fmt.Errorf("create input provider failed: %v", err)
	}
	// 执行扫描

	scanErr := r.xmap.ScanWithCallback(ctx, inputProvider,
		// 结果回调 - 每当有一个结果就立即输出
		func(result *types.ScanResult) {
			// 更新进度
			if progressTracker != nil {
				progressTracker.Increment()
			}

			// 始终在控制台显示结果
			outputErr := consoleOuter.Output(result)
			if outputErr != nil {
				gologger.Error().Msgf("控制台输出失败: %v", outputErr)
			}

			// 如果指定了文件输出，也输出到文件
			if fileOuter != nil {
				fileErr := fileOuter.Output(result)
				if fileErr != nil {
					gologger.Error().Msgf("文件输出失败: %v", fileErr)
				}
			}
		},
	)
	if scanErr != nil {
		return fmt.Errorf("扫描失败: %v", scanErr)
	}
	return nil
}
