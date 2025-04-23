package runner

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/goflags"
)

// Version 版本信息
const Version = "v0.1.0"

// Banner 程序的banner
var Banner = fmt.Sprintf(`
__  ____  ___           
\ \/ /  \/  / __ _ _ __  
 \  /| |\/| |/ _' | '_ \ 
 /  \| |  | | (_| | |_) |
/_/\_\_|  |_|\__,_| .__/ 
                  |_|    %s
`, Version)

// ParseOptions 解析命令行选项
func ParseOptions() (*Options, error) {
	options := &Options{}

	// 设置版本和banner
	options.Version = Version
	options.Banner = Banner

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("XMap - 一个快速可靠的网络扫描和指纹识别工具")

	// 创建目标参数组
	flagSet.CreateGroup("目标", "目标设置",
		flagSet.StringSliceVarP(&options.Target, "target", "t", goflags.StringSlice{}, "扫描目标，格式: ip:port 或 ip (使用默认端口)", goflags.Options{}),
		flagSet.StringVarP(&options.TargetFile, "target-file", "l", "", "包含扫描目标的文件，每行一个目标"),
		flagSet.StringVarP(&options.Ports, "ports", "p", "80,443,8080", "要扫描的端口，逗号分隔"),
	)

	// 创建扫描选项组
	flagSet.CreateGroup("扫描", "扫描选项",
		flagSet.IntVar(&options.Timeout, "timeout", 5, "扫描超时时间(秒)"),
		flagSet.IntVarP(&options.Retries, "retries", "r", 2, "扫描重试次数"),
		flagSet.IntVarP(&options.Workers, "workers", "c", 100, "最大并行扫描数"),
		flagSet.BoolVarP(&options.FastMode, "fast", "f", false, "使用快速模式"),
		flagSet.BoolVar(&options.UseAllProbes, "all-probes", false, "使用所有探针"),
		flagSet.StringSliceVarP(&options.NmapProneName, "probes", "np", goflags.StringSlice{}, "要使用的探针名称，逗号分隔", goflags.Options{}),
		flagSet.BoolVar(&options.UseSSL, "ssl", false, "使用SSL"),
		flagSet.IntVar(&options.VersionIntensity, "version-intensity", 7, "版本检测强度(0-9)"),
		flagSet.BoolVarP(&options.ServiceVersion, "service-version", "sv", true, "显示服务版本"),
		flagSet.BoolVar(&options.VersionTrace, "version-trace", false, "跟踪版本检测过程"),
	)

	// 创建Web扫描选项组
	flagSet.CreateGroup("Web扫描", "Web扫描选项",
		flagSet.StringVarP(&options.AppFingerHome, "fingerprint-path", "d", "", "指纹库路径，默认使用内置路径"),
		flagSet.BoolVarP(&options.UpdateAppFingerRule, "update-rule", "ur", false, "更新指纹规则库"),
		flagSet.StringVarP(&options.Proxy, "proxy", "x", "", "HTTP代理，格式: http://host:port"),
		flagSet.BoolVarP(&options.DisableIcon, "disable-icon", "di", false, "禁用图标请求匹配"),
		flagSet.BoolVarP(&options.DisableJS, "disable-js", "dj", false, "禁用JavaScript规则匹配"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "调试HTTP响应"),
	)

	// 创建输出选项组
	flagSet.CreateGroup("输出", "输出选项",
		flagSet.StringVarP(&options.Output, "output", "o", "", "输出结果到文件"),
		flagSet.StringVarP(&options.OutType, "output-type", "ot", "json", "输出格式 (json, csv, console)"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "显示详细信息"),
		flagSet.BoolVarP(&options.Silent, "silent", "s", false, "静默模式"),
		flagSet.BoolVar(&options.NoProgress, "no-progress", false, "不显示进度条"),
	)

	// 创建其他选项组
	var helpFlag, versionFlag, examplesFlag bool
	flagSet.CreateGroup("其他", "其他选项",
		flagSet.BoolVarP(&helpFlag, "help", "h", false, "显示帮助信息"),
		flagSet.BoolVar(&versionFlag, "version", false, "显示版本信息"),
		flagSet.BoolVarP(&examplesFlag, "examples", "e", false, "显示使用示例"),
		flagSet.BoolVar(&options.EnablePprof, "enable-pprof", false, "启用性能分析"),
	)

	// 解析命令行参数
	if err := flagSet.Parse(); err != nil {
		return nil, fmt.Errorf("解析命令行参数失败: %v", err)
	}

	// 显示版本信息
	if versionFlag {
		fmt.Printf("XMap 版本: %s\n", Version)
		os.Exit(0)
	}

	// 显示帮助信息
	if helpFlag {
		fmt.Println("XMap - 一个快速可靠的网络扫描和指纹识别工具")
		fmt.Println()
		fmt.Println("使用方法: xmap [options]")
		fmt.Println()
		fmt.Println("常用选项:")
		fmt.Println("  -t, --target         扫描目标，格式: ip:port 或 ip")
		fmt.Println("  -l, --target-file    包含扫描目标的文件，每行一个目标")
		fmt.Println("  -p, --ports          要扫描的端口，逗号分隔")
		fmt.Println("  -o, --output         输出结果到文件")
		fmt.Println("  -v, --verbose        显示详细信息")
		fmt.Println("  -s, --silent         静默模式")
		fmt.Println("  -h, --help           显示帮助信息")
		fmt.Println("  -e, --examples       显示使用示例")
		fmt.Println("      --version        显示版本信息")
		fmt.Println()
		fmt.Println("更多选项请参考文档或使用 --examples 查看使用示例")
		os.Exit(0)
	}

	// 显示使用示例
	if examplesFlag {
		printExamples()
		os.Exit(0)
	}

	return options, nil
}

// 打印使用示例
func printExamples() {
	examples := `
使用示例:
  # 扫描单个目标
  xmap -t 192.168.1.1

  # 扫描多个目标
  xmap -t 192.168.1.1,192.168.1.2

  # 从文件加载目标
  xmap -l targets.txt

  # 指定端口
  xmap -t 192.168.1.1 -p 80,443,8080-8090

  # 输出到文件
  xmap -t 192.168.1.1 -o results.json

  # 使用CSV格式输出
  xmap -t 192.168.1.1 -o results.csv -ot csv

  # 更新指纹规则库
  xmap --update-rule

  # 使用自定义指纹库路径
  xmap -t 192.168.1.1 -d /path/to/fingerprints

  # 使用代理
  xmap -t 192.168.1.1 -x http://127.0.0.1:8080
`
	fmt.Println(examples)
}
