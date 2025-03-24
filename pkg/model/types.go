package model

import (
	"encoding/json"
	"time"
)

// ScanTarget 表示扫描目标
type ScanTarget struct {
	// 目标ID
	ID string `json:"id,omitempty"`
	// IP地址
	IP string `json:"ip"`
	// 端口
	Port int `json:"port"`
	// 协议 (TCP/UDP)
	Protocol string `json:"protocol"`
	// 自定义元数据
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ScanResult 表示扫描结果
type ScanResult struct {
	// 目标信息
	Target *ScanTarget `json:"target"`
	// 服务名称
	Service string `json:"service,omitempty"`
	// 附加信息
	Components []map[string]interface{} `json:"components,omitempty"`
	// 主机名
	Hostname string `json:"hostname,omitempty"`
	// 匹配的探针名称
	MatchedProbe string `json:"matched_probe,omitempty"`
	// 匹配的服务名称
	MatchedService string `json:"matched_service,omitempty"`
	// 匹配的正则表达式
	MatchedPattern string `json:"matched_pattern,omitempty"`
	// 扫描耗时
	Duration float64 `json:"duration"`
	// 错误信息
	Error string `json:"error,omitempty"`
	// 自定义元数据，http banner,tcp banner
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (r *ScanResult) JSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ScanTask 表示扫描任务
type ScanTask struct {
	// 任务ID
	ID string `json:"id"`
	// 扫描目标列表
	Targets []*ScanTarget `json:"targets"`
	// 扫描选项
	Options *ScanOptions `json:"options,omitempty"`
	// 任务状态
	Status string `json:"status"`
	// 创建时间
	CreatedAt time.Time `json:"created_at"`
	// 开始时间
	StartedAt time.Time `json:"started_at,omitempty"`
	// 完成时间
	CompletedAt time.Time `json:"completed_at,omitempty"`
	// 自定义元数据
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ScanOptions 表示扫描选项
type ScanOptions struct {
	// 超时时间(秒)
	Timeout int `json:"timeout,omitempty"`
	// 重试次数
	Retries int `json:"retries,omitempty"`
	// 是否使用SSL
	UseSSL bool `json:"use_ssl,omitempty"`
	// 版本检测强度(0-9)
	VersionIntensity int `json:"version_intensity,omitempty"`
	// 是否进行主机发现
	HostDiscovery bool `json:"host_discovery,omitempty"`
	// 最大并行扫描数
	MaxParallelism int `json:"max_parallelism,omitempty"`
	// 指定要使用的探针名称
	ProbeNames []string `json:"probe_names,omitempty"`
	// 指定要使用的端口
	Ports []int `json:"ports,omitempty"`
	// 是否使用所有探针
	UseAllProbes bool `json:"use_all_probes,omitempty"`
	// 是否使用快速模式（只使用常用探针）
	FastMode bool `json:"fast_mode,omitempty"`
	// 是否使用服务检测
	ServiceDetection bool `json:"service_detection,omitempty"`
	// 是否使用版本检测
	VersionDetection bool `json:"version_detection,omitempty"`
	// 是否使用操作系统检测
	OSDetection bool `json:"os_detection,omitempty"`
	// 是否使用设备类型检测
	DeviceTypeDetection bool `json:"device_type_detection,omitempty"`
	// 是否使用主机名检测
	HostnameDetection bool `json:"hostname_detection,omitempty"`
	// 是否使用产品名称检测
	ProductNameDetection bool `json:"product_name_detection,omitempty"`
	// 是否使用信息检测
	InfoDetection bool `json:"info_detection,omitempty"`
}

// TaskStatus 表示任务状态
const (
	// TaskStatusPending 表示任务等待中
	TaskStatusPending = "pending"
	// TaskStatusRunning 表示任务运行中
	TaskStatusRunning = "running"
	// TaskStatusCompleted 表示任务已完成
	TaskStatusCompleted = "completed"
	// TaskStatusFailed 表示任务失败
	TaskStatusFailed = "failed"
	// TaskStatusCanceled 表示任务已取消
	TaskStatusCanceled = "canceled"
)

// ScanProgress 表示扫描进度
type ScanProgress struct {
	// 任务ID
	TaskID string `json:"task_id"`
	// 总目标数
	TotalTargets int `json:"total_targets"`
	// 已完成目标数
	CompletedTargets int `json:"completed_targets"`
	// 成功目标数
	SuccessTargets int `json:"success_targets"`
	// 失败目标数
	FailedTargets int `json:"failed_targets"`
	// 进度百分比
	Percentage float64 `json:"percentage"`
	// 当前状态
	Status string `json:"status"`
	// 开始时间
	StartTime time.Time `json:"start_time,omitempty"`
	// 当前时间
	CurrentTime time.Time `json:"current_time"`
	// 预计剩余时间(秒)
	EstimatedTimeRemaining int `json:"estimated_time_remaining,omitempty"`
}
