# XMap: 高性能分布式网络服务指纹识别框架

XMap 是一个基于 Go 语言的高性能分布式网络服务指纹识别框架，它在 gonmap 的基础上进行了架构优化和功能扩展，专注于提供更高效、可扩展的网络服务识别能力。XMap 特别适合在大规模分布式环境中使用，支持多任务共享指纹库同时使用独立扫描参数的场景。

## 🌟 主要特性

- **高性能扫描引擎**：基于 gonmap 优化的 TCP/UDP 服务探测和识别
- **共享指纹库**：多任务共享指纹加载，减少内存占用和初始化时间
- **独立扫描参数**：每个扫描任务可使用自定义的扫描参数
- **分布式架构**：支持水平扩展的工作节点
- **灵活的插件系统**：支持自定义探测和匹配逻辑
- **完善的上下文控制**：支持超时和取消机制
- **丰富的输出格式**：支持 JSON、CSV 等多种输出格式
- **实时监控**：提供扫描进度和资源使用情况的实时监控

## 🚀 核心设计

### 1. 架构概览

XMap 采用模块化设计，主要包含以下核心组件：

```
┌─────────────────────────────────────────────────────────────┐
│                      XMap Framework                          │
├─────────────┬─────────────┬───────────────┬─────────────────┤
│             │             │               │                 │
│  Fingerprint│   Scanner   │    Matcher    │     Worker      │
│   Manager   │   Engine    │     Engine    │      Pool       │
│             │             │               │                 │
├─────────────┼─────────────┼───────────────┼─────────────────┤
│             │             │               │                 │
│  Probe      │  Protocol   │   Result      │     Plugin      │
│  Repository │  Handlers   │   Processors  │     System      │
│             │             │               │                 │
└─────────────┴─────────────┴───────────────┴─────────────────┘
```

### 2. 指纹管理设计

#### 2.1 指纹管理器 (FingerprintManager)

指纹管理器是 XMap 的核心组件，负责指纹的加载、缓存和分发：

```go
// FingerprintManager 负责管理指纹库
type FingerprintManager struct {
    // 指纹库存储
    probeStore *ProbeStore
    // 加载锁，确保并发安全
    loadMutex sync.RWMutex
    // 配置选项
    options *FingerprintOptions
    // 指纹库状态
    status FingerprintStatus
}

// FingerprintOptions 指纹库配置选项
type FingerprintOptions struct {
    // 指纹文件路径
    ProbeFilePath string
    // 指纹版本
    Version string
    // 是否启用缓存
    EnableCache bool
    // 缓存过期时间
    CacheTTL time.Duration
    // 自动重载间隔
    ReloadInterval time.Duration
}

// ProbeStore 存储和管理探针数据
type ProbeStore struct {
    // 按名称索引的探针映射
    probesByName map[string]*Probe
    // TCP探针列表
    tcpProbes []*Probe
    // UDP探针列表
    udpProbes []*Probe
    // 创建时间
    createdAt time.Time
    // 最后访问时间
    lastAccessedAt time.Time
}
```

#### 2.2 单例模式实现

为确保多任务共享指纹库，XMap 使用单例模式实现 FingerprintManager：

```go
var (
    fingerprintManagerInstance *FingerprintManager
    fingerprintManagerOnce     sync.Once
    fingerprintManagerMutex    sync.RWMutex
)

// GetFingerprintManager 获取指纹管理器单例
func GetFingerprintManager(options *FingerprintOptions) *FingerprintManager {
    fingerprintManagerOnce.Do(func() {
        fingerprintManagerInstance = newFingerprintManager(options)
    })
    
    // 如果配置有变更，更新配置但不重新加载指纹
    if options != nil && !reflect.DeepEqual(fingerprintManagerInstance.options, options) {
        fingerprintManagerMutex.Lock()
        fingerprintManagerInstance.updateOptions(options)
        fingerprintManagerMutex.Unlock()
    }
    
    return fingerprintManagerInstance
}
```

### 3. 扫描引擎设计

#### 3.1 扫描器接口

```go
// Scanner 定义扫描器接口
type Scanner interface {
    // Scan 执行单个目标扫描
    Scan(ctx context.Context, target string, opts ...ScanOption) (*Result, error)
    
    // BatchScan 执行批量目标扫描
    BatchScan(ctx context.Context, targets []string, opts ...ScanOption) ([]*Result, error)
    
    // Match 仅执行匹配操作
    Match(protocol Protocol, data []byte, opts ...MatchOption) (*MatchResult, error)
}
```

#### 3.2 扫描选项设计

使用函数选项模式实现灵活的参数配置：

```go
// ScanOptions 定义扫描选项
type ScanOptions struct {
    // 连接超时时间
    Timeout time.Duration
    
    // 扫描总超时时间
    ScanTimeout time.Duration
    
    // 代理设置
    Proxy string
    
    // 版本检测强度(0-9)
    VersionIntensity int
    
    // 是否启用TLS
    EnableTLS bool
    
    // 调试选项
    Debug bool
    
    // 并发数
    Concurrency int
    
    // 重试次数
    Retries int
    
    // 重试间隔
    RetryInterval time.Duration
}

// ScanOption 定义扫描选项设置函数
type ScanOption func(*ScanOptions)

// WithTimeout 设置连接超时
func WithTimeout(timeout time.Duration) ScanOption {
    return func(o *ScanOptions) {
        o.Timeout = timeout
    }
}

// WithScanTimeout 设置扫描总超时
func WithScanTimeout(timeout time.Duration) ScanOption {
    return func(o *ScanOptions) {
        o.ScanTimeout = timeout
    }
}

// 其他选项设置函数...
```

#### 3.3 扫描器实现

```go
// XMapScanner 实现Scanner接口
type XMapScanner struct {
    // 指纹管理器
    fingerprintManager *FingerprintManager
    
    // 默认选项
    defaultOptions *ScanOptions
    
    // 工作池
    workerPool *WorkerPool
}

// NewScanner 创建新的扫描器
func NewScanner(opts ...ScanOption) *XMapScanner {
    options := &ScanOptions{
        Timeout:          5 * time.Second,
        ScanTimeout:      30 * time.Second,
        VersionIntensity: 7,
        Concurrency:      10,
        Retries:          2,
        RetryInterval:    1 * time.Second,
    }
    
    for _, opt := range opts {
        opt(options)
    }
    
    // 获取共享的指纹管理器
    fpManager := GetFingerprintManager(&FingerprintOptions{
        ProbeFilePath: "nmap-service-probes",
        EnableCache:   true,
    })
    
    return &XMapScanner{
        fingerprintManager: fpManager,
        defaultOptions:     options,
        workerPool:         NewWorkerPool(options.Concurrency),
    }
}

// Scan 实现Scanner.Scan方法
func (s *XMapScanner) Scan(ctx context.Context, target string, opts ...ScanOption) (*Result, error) {
    // 合并默认选项和自定义选项
    scanOptions := *s.defaultOptions
    for _, opt := range opts {
        opt(&scanOptions)
    }
    
    // 解析目标
    ip, port, err := ParseTarget(target)
    if err != nil {
        return nil, err
    }
    
    // 创建扫描任务
    task := &ScanTask{
        Target:  target,
        IP:      ip,
        Port:    port,
        Options: &scanOptions,
    }
    
    // 执行扫描
    return s.executeTask(ctx, task)
}

// BatchScan 实现Scanner.BatchScan方法
func (s *XMapScanner) BatchScan(ctx context.Context, targets []string, opts ...ScanOption) ([]*Result, error) {
    // 实现批量扫描逻辑
    // ...
}
```

### 4. 工作池设计

为支持高效的并发扫描，XMap 实现了工作池：

```go
// WorkerPool 管理扫描工作线程
type WorkerPool struct {
    // 工作线程数量
    size int
    
    // 任务队列
    taskQueue chan *ScanTask
    
    // 结果队列
    resultQueue chan *Result
    
    // 工作线程组
    workers []*Worker
    
    // 控制信号
    quit chan struct{}
    
    // 等待组
    wg sync.WaitGroup
}

// Worker 表示工作线程
type Worker struct {
    // 工作线程ID
    id int
    
    // 任务队列
    taskQueue chan *ScanTask
    
    // 结果队列
    resultQueue chan *Result
    
    // 指纹管理器
    fingerprintManager *FingerprintManager
    
    // 退出信号
    quit chan struct{}
}
```

### 5. 插件系统设计

XMap 提供插件系统支持自定义扫描和匹配逻辑：

```go
// Plugin 定义插件接口
type Plugin interface {
    // Name 返回插件名称
    Name() string
    
    // Version 返回插件版本
    Version() string
    
    // Init 初始化插件
    Init(ctx context.Context) error
    
    // Execute 执行插件逻辑
    Execute(ctx context.Context, input interface{}) (interface{}, error)
    
    // Cleanup 清理资源
    Cleanup() error
}

// PluginManager 管理插件
type PluginManager struct {
    // 已注册的插件
    plugins map[string]Plugin
    
    // 插件加载路径
    pluginPaths []string
}
```

## 📋 项目结构

```
xmap/
├── cmd/                      # 命令行工具
│   └── xmap/                 # 主程序
│       └── main.go           # 入口点
├── internal/                 # 内部包
│   ├── fingerprint/          # 指纹管理
│   │   ├── manager.go        # 指纹管理器
│   │   ├── probe.go          # 探针定义
│   │   └── store.go          # 指纹存储
│   ├── scanner/              # 扫描引擎
│   │   ├── scanner.go        # 扫描器实现
│   │   ├── options.go        # 扫描选项
│   │   └── result.go         # 结果定义
│   ├── matcher/              # 匹配引擎
│   │   ├── matcher.go        # 匹配器实现
│   │   └── pattern.go        # 匹配模式
│   ├── worker/               # 工作池
│   │   ├── pool.go           # 工作池实现
│   │   └── worker.go         # 工作线程
│   ├── plugin/               # 插件系统
│   │   ├── manager.go        # 插件管理器
│   │   └── interface.go      # 插件接口
│   └── protocol/             # 协议处理
│       ├── tcp.go            # TCP协议
│       └── udp.go            # UDP协议
├── pkg/                      # 公共包
│   ├── model/                # 数据模型
│   │   ├── result.go         # 结果模型
│   │   └── task.go           # 任务模型
│   ├── utils/                # 工具函数
│   │   ├── net.go            # 网络工具
│   │   └── sync.go           # 同步工具
│   └── config/               # 配置管理
│       └── config.go         # 配置定义
├── plugins/                  # 插件目录
│   ├── http/                 # HTTP插件
│   └── ssl/                  # SSL插件
├── data/                     # 数据目录
│   └── nmap-service-probes   # 服务探针数据
├── go.mod                    # Go模块定义
└── README.md                 # 项目文档
```

## 🔧 使用示例

### 基本使用

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/tongchengbin/xmap/pkg/model"
    "github.com/tongchengbin/xmap/internal/scanner"
)

func main() {
    // 创建扫描器
    xmapScanner := scanner.NewScanner(
        scanner.WithTimeout(5 * time.Second),
        scanner.WithVersionIntensity(7),
    )
    
    // 执行扫描
    ctx := context.Background()
    result, err := xmapScanner.Scan(ctx, "example.com:80")
    if err != nil {
        panic(err)
    }
    
    // 输出结果
    fmt.Printf("Service: %s\n", result.Service)
    fmt.Printf("Product: %s\n", result.Product)
    fmt.Printf("Version: %s\n", result.Version)
}
```

### 批量扫描示例

```go
func batchScanExample() {
    // 创建扫描器
    xmapScanner := scanner.NewScanner(
        scanner.WithTimeout(5 * time.Second),
        scanner.WithConcurrency(20),
    )
    
    // 定义目标
    targets := []string{
        "example.com:80",
        "example.com:443",
        "example.com:22",
    }
    
    // 执行批量扫描
    ctx := context.Background()
    results, err := xmapScanner.BatchScan(ctx, targets)
    if err != nil {
        panic(err)
    }
    
    // 处理结果
    for _, result := range results {
        fmt.Printf("%s: %s %s %s\n", 
            result.Target, 
            result.Service, 
            result.Product, 
            result.Version)
    }
}
```

### 自定义扫描参数示例

```go
func customScanExample() {
    // 创建基础扫描器
    baseScanner := scanner.NewScanner(
        scanner.WithVersionIntensity(5),
        scanner.WithTimeout(3 * time.Second),
    )
    
    // 第一个任务使用默认参数
    result1, _ := baseScanner.Scan(context.Background(), "example.com:80")
    
    // 第二个任务使用自定义参数
    result2, _ := baseScanner.Scan(
        context.Background(), 
        "example.com:443",
        scanner.WithTimeout(10 * time.Second),
        scanner.WithVersionIntensity(9),
        scanner.WithRetries(3),
    )
    
    // 两个任务使用相同的指纹库，但扫描参数不同
    fmt.Println("Task 1 result:", result1.Service)
    fmt.Println("Task 2 result:", result2.Service)
}
```

## ⚙️ 配置选项

XMap 提供了丰富的配置选项，可以通过命令行参数、配置文件或代码设置：

### 扫描选项

- **Timeout**: 连接超时时间
- **ScanTimeout**: 扫描总超时时间
- **VersionIntensity**: 版本检测强度(0-9)
- **Concurrency**: 并发扫描数量
- **Retries**: 重试次数
- **RetryInterval**: 重试间隔
- **Proxy**: 代理设置
- **EnableTLS**: 是否启用TLS

### 指纹选项

- **ProbeFilePath**: 指纹文件路径
- **EnableCache**: 是否启用缓存
- **CacheTTL**: 缓存过期时间
- **ReloadInterval**: 自动重载间隔

## 🔄 与 gonmap 的区别

XMap 在 gonmap 的基础上进行了以下关键改进：

1. **指纹管理优化**：
   - 实现单例模式的指纹管理器，多任务共享指纹库
   - 支持指纹缓存和自动重载机制

2. **架构优化**：
   - 模块化设计，解耦扫描和匹配逻辑
   - 统一的扫描接口，简化调用方式

3. **功能增强**：
   - 工作池实现，支持高效并发扫描
   - 插件系统，支持自定义扫描和匹配逻辑
   - 更完善的上下文控制和错误处理

4. **性能优化**：
   - 减少重复指纹加载，降低内存占用
   - 优化匹配算法，提高识别速度
   - 支持扫描任务的优先级调度

## 📄 许可证

本项目基于MIT许可证开源。详情请参阅[LICENSE](LICENSE)文件。

## 🤝 贡献

欢迎贡献！请提交Issue或Pull Request。

## 📞 联系方式

如有任何问题或需要支持，请联系[tongchengbin](https://github.com/tongchengbin)。

---

祝您扫描愉快! 🎉
