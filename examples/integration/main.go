package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/types"
)

func main() {
	// 设置日志级别
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	// 创建XMap实例（全局单例，指纹库只加载一次）
	xmapInstance := api.NewXMap(
		api.WithTimeout(5*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(7),
		api.WithMaxParallelism(100),
	)

	// 示例1: 单个目标扫描
	fmt.Println("=== 示例1: 单个目标扫描 ===")
	singleScanExample(xmapInstance)

	// 示例2: 批量扫描
	fmt.Println("\n=== 示例2: 批量扫描 ===")
	batchScanExample(xmapInstance)

	// 示例3: 任务执行与进度报告
	fmt.Println("\n=== 示例3: 任务执行与进度报告 ===")
	taskWithProgressExample(xmapInstance)

	// 示例4: 集成到risk-schedule
	fmt.Println("\n=== 示例4: 集成到risk-schedule ===")
	riskScheduleIntegrationExample(xmapInstance)
}

// 单个目标扫描示例
func singleScanExample(xmapInstance *api.XMap) {
	// 创建目标
	target := &types.ScanTarget{
		IP:       "192.168.1.1",
		Port:     80,
		Protocol: "tcp",
	}

	// 执行扫描
	fmt.Println("开始单个目标扫描...")
	result, err := xmapInstance.Scan(context.Background(), target)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		return
	}

	// 输出结果
	printResult(result)
}

// 批量扫描示例
func batchScanExample(xmapInstance *api.XMap) {
	// 创建扫描目标
	targets := []*types.ScanTarget{
		{
			IP:       "example.com",
			Port:     80,
			Protocol: "tcp",
		},
		{
			IP:       "example.org",
			Port:     443,
			Protocol: "tcp",
		},
	}

	// 执行批量扫描
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := xmapInstance.BatchScan(ctx, targets, nil)
	if err != nil {
		fmt.Printf("批量扫描失败: %v\n", err)
		return
	}

	// 输出结果
	for i, result := range results {
		fmt.Printf("目标 %d 结果:\n", i+1)
		printResult(result)
		fmt.Println()
	}
}

// 任务执行与进度报告示例
func taskWithProgressExample(xmapInstance *api.XMap) {
	// 创建扫描任务
	task := &types.ScanTask{
		ID: "task-001",
		Targets: []*types.ScanTarget{
			{
				IP:       "example.com",
				Port:     80,
				Protocol: "tcp",
			},
			{
				IP:       "example.org",
				Port:     443,
				Protocol: "tcp",
			},
			{
				IP:       "example.net",
				Port:     8080,
				Protocol: "tcp",
			},
		},
		Options: &types.ScanOptions{
			Timeout:          5,
			Retries:          2,
			VersionIntensity: 7,
			FastMode:         true,
			MaxParallelism:   10,
		},
		Status:    types.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	// 进度回调函数
	progressCallback := func(progress *types.ScanProgress) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	updatedTask, results, err := xmapInstance.ExecuteTaskWithProgress(ctx, task, progressCallback)
	if err != nil {
		fmt.Printf("\n任务执行失败: %v\n", err)
		return
	}

	// 输出任务信息
	fmt.Printf("\n\n任务完成: %s\n", updatedTask.Status)
	fmt.Printf("开始时间: %s\n", updatedTask.StartedAt.Format(time.RFC3339))
	fmt.Printf("完成时间: %s\n", updatedTask.CompletedAt.Format(time.RFC3339))
	fmt.Printf("总耗时: %s\n", updatedTask.CompletedAt.Sub(updatedTask.StartedAt))
	fmt.Printf("结果数量: %d\n", len(results))
}

// risk-schedule集成示例
func riskScheduleIntegrationExample(xmapInstance *api.XMap) {
	// 这个示例展示如何将XMap集成到risk-schedule中
	// 在实际应用中，这部分代码会在risk-schedule项目中实现

	// 1. 创建XMap执行器
	executor := NewXMapExecutor(xmapInstance)

	// 2. 从risk-schedule接收任务
	task := createMockScanTask()

	// 3. 执行任务
	fmt.Println("开始执行risk-schedule任务...")
	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		fmt.Printf("任务执行失败: %v\n", err)
		return
	}

	// 4. 处理结果
	fmt.Printf("任务执行成功，扫描了 %d 个目标，发现 %d 个服务\n",
		result.TotalTargets, result.IdentifiedServices)

	// 5. 将结果保存到文件
	saveResultToFile(result, "scan_result.json")
}

// XMapExecutor 是risk-schedule中的XMap执行器
type XMapExecutor struct {
	xmap *api.XMap
}

// NewXMapExecutor 创建新的XMap执行器
func NewXMapExecutor(xmap *api.XMap) *XMapExecutor {
	return &XMapExecutor{
		xmap: xmap,
	}
}

// RiskScheduleScanTask 是risk-schedule中的扫描任务
type RiskScheduleScanTask struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Targets     []string           `json:"targets"`
	Options     *types.ScanOptions `json:"options"`
	CreatedAt   time.Time          `json:"created_at"`
}

// RiskScheduleScanResult 是risk-schedule中的扫描结果
type RiskScheduleScanResult struct {
	TaskID             string              `json:"task_id"`
	Status             string              `json:"status"`
	TotalTargets       int                 `json:"total_targets"`
	ScannedTargets     int                 `json:"scanned_targets"`
	IdentifiedServices int                 `json:"identified_services"`
	StartTime          time.Time           `json:"start_time"`
	EndTime            time.Time           `json:"end_time"`
	Duration           time.Duration       `json:"duration"`
	Results            []*types.ScanResult `json:"results"`
}

// Execute 执行risk-schedule扫描任务
func (e *XMapExecutor) Execute(ctx context.Context, task *RiskScheduleScanTask) (*RiskScheduleScanResult, error) {
	// 1. 将risk-schedule任务转换为XMap任务
	targets := make([]*types.ScanTarget, 0, len(task.Targets))
	for i, targetStr := range task.Targets {
		// 这里简化了目标解析逻辑，实际应用中需要更复杂的解析
		target := &types.ScanTarget{
			IP:       targetStr,
			Port:     80, // 默认端口
			Protocol: "tcp",
		}
		targets = append(targets, target)
	}

	xmapTask := &types.ScanTask{
		Targets:   targets,
		Options:   task.Options,
		Status:    types.TaskStatusPending,
		CreatedAt: task.CreatedAt,
		Metadata: map[string]interface{}{
			"name":        task.Name,
			"description": task.Description,
		},
	}

	// 2. 执行XMap任务
	_, results, err := e.xmap.ExecuteTask(ctx, xmapTask)
	if err != nil {
		return nil, err
	}

	// 3. 统计服务识别结果
	identifiedServices := 0
	for _, result := range results {
		if result.Service != "" {
			identifiedServices++
		}
	}

	// 4. 创建risk-schedule结果
	scanResult := &RiskScheduleScanResult{
		TaskID:             task.ID,
		Status:             "completed",
		TotalTargets:       len(task.Targets),
		ScannedTargets:     len(results),
		IdentifiedServices: identifiedServices,
		StartTime:          xmapTask.StartedAt,
		EndTime:            xmapTask.CompletedAt,
		Duration:           xmapTask.CompletedAt.Sub(xmapTask.StartedAt),
		Results:            results,
	}

	return scanResult, nil
}

// createMockScanTask 创建模拟的risk-schedule扫描任务
func createMockScanTask() *RiskScheduleScanTask {
	return &RiskScheduleScanTask{
		ID:          "risk-task-001",
		Name:        "示例扫描任务",
		Description: "这是一个示例扫描任务，用于展示XMap与risk-schedule的集成",
		Targets:     []string{"example.com", "example.org", "example.net"},
		Options: &types.ScanOptions{
			Timeout:          5,
			Retries:          2,
			VersionIntensity: 7,
			FastMode:         true,
			MaxParallelism:   10,
		},
		CreatedAt: time.Now(),
	}
}

// printResult 打印扫描结果
func printResult(result *types.ScanResult) {
	fmt.Printf("目标: %s:%d\n", result.Target.IP, result.Target.Port)
	fmt.Printf("服务: %s\n", result.Service)

	fmt.Printf("扫描耗时: %s\n", result.Duration)
	if result.Error != "" {
		fmt.Printf("错误: %s\n", result.Error)
	}
}

// saveResultToFile 将结果保存到文件
func saveResultToFile(result *RiskScheduleScanResult, filename string) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("序列化结果失败: %v\n", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("保存结果到文件失败: %v\n", err)
		return
	}

	fmt.Printf("结果已保存到文件: %s\n", filename)
}
