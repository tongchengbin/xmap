package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
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
		fmt.Println("使用方法: simple <target> [port]")
		fmt.Println("示例: simple example.com 80")
		os.Exit(1)
	}

	// 解析目标和端口
	target := os.Args[1]
	port := 80 // 默认端口

	if len(os.Args) > 2 {
		p, err := strconv.Atoi(os.Args[2])
		if err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	// 判断是否使用SSL
	useSSL := port == 443 || port == 8443

	// 创建XMap实例
	xmap := api.NewXMap(
		api.WithTimeout(5*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(7),
	)

	// 创建扫描目标
	scanTarget := &model.ScanTarget{
		IP:       target,
		Port:     port,
		Protocol: "TCP",
		ID:       fmt.Sprintf("%s:%d", target, port),
	}

	// 创建扫描选项
	options := &model.ScanOptions{
		Timeout:          5,
		Retries:          2,
		UseSSL:           useSSL,
		VersionIntensity: 7,
		FastMode:         true,
	}

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 执行扫描
	fmt.Printf("正在扫描 %s:%d...\n", target, port)
	startTime := time.Now()

	result, err := xmap.Scan(ctx, scanTarget, options)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		os.Exit(1)
	}

	// 输出结果
	fmt.Printf("扫描完成，耗时: %s\n\n", time.Since(startTime))
	printResult(result)
}

// 打印扫描结果
func printResult(result *model.ScanResult) {
	fmt.Println("扫描结果:")
	fmt.Println("----------------------------------------")
	fmt.Printf("目标:     %s:%d\n", result.Target.IP, result.Target.Port)
	fmt.Printf("协议:     %s\n", result.Target.Protocol)
	fmt.Println("----------------------------------------")

	if result.Error != "" {
		fmt.Printf("错误:     %s\n", result.Error)
		return
	}

	if result.Service != "" {
		fmt.Printf("服务:     %s\n", result.Service)
	}

	if result.ProductName != "" {
		fmt.Printf("产品:     %s\n", result.ProductName)
	}

	if result.Version != "" {
		fmt.Printf("版本:     %s\n", result.Version)
	}

	if result.OS != "" {
		fmt.Printf("操作系统: %s\n", result.OS)
	}

	if result.DeviceType != "" {
		fmt.Printf("设备类型: %s\n", result.DeviceType)
	}

	if result.Hostname != "" {
		fmt.Printf("主机名:   %s\n", result.Hostname)
	}

	if result.Info != "" {
		fmt.Printf("信息:     %s\n", result.Info)
	}

	if result.MatchedProbe != "" {
		fmt.Printf("匹配探针: %s\n", result.MatchedProbe)
	}

	if result.MatchedService != "" {
		fmt.Printf("匹配服务: %s\n", result.MatchedService)
	}

	fmt.Printf("扫描耗时: %s\n", result.Duration)
	fmt.Println("----------------------------------------")
}
