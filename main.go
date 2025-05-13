package main

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/xmap/pkg/runner"
)

func main() {
	// 解析命令行选项
	options, err := runner.ParseOptions()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 显示banner
	if !options.Silent {
		fmt.Print(options.Banner)
	}

	// 更新指纹规则库
	if options.UpdateAppFingerRule {
		run, err := runner.New(options)
		if err != nil {
			gologger.Fatal().Msgf("创建runner失败: %v", err)
		}

		err = run.UpdateRules()
		if err != nil {
			gologger.Fatal().Msgf("更新指纹规则库失败: %v", err)
		}
		return
	}

	// 创建runner
	run, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("创建runner失败: %v", err)
	}

	// 执行扫描
	err = run.Run()
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}
}
