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
- **Web指纹识别**：集成appfinger实现高效的Web应用指纹识别

## 🚀 快速开始

### 安装

#### 使用 go install 安装

```bash
# 直接安装最新版本
go install github.com/tongchengbin/xmap@latest
```

#### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/tongchengbin/xmap.git
cd xmap

# 安装依赖
go mod download

# 编译
go build -o xmap main.go

# 运行
./xmap -h
```

#### 使用Docker

```bash
# 构建Docker镜像
docker build -t xmap .

# 运行
docker run --rm xmap -h
```

### 基本用法

```bash
# 扫描单个目标
xmap -target 192.168.1.1

# 扫描多个端口
xmap -target 192.168.1.1 -ports 80,443,8080-8090

# 从文件读取目标
xmap -target-file targets.txt

# 使用快速模式
xmap -target 192.168.1.1 -fast

# 输出JSON格式结果
xmap -target 192.168.1.1 -output results.json -json
```

### 编程接口示例

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/tongchengbin/xmap/pkg/api"
    "github.com/tongchengbin/xmap/pkg/model"
)

func main() {
    // 创建XMap实例
    xmap := api.NewXMap(
        api.WithTimeout(5*time.Second),
        api.WithRetries(2),
        api.WithVersionIntensity(7),
    )
    
    // 创建扫描目标
    target := &model.ScanTarget{
        IP:       "192.168.1.1",
        Port:     80,
        Protocol: "tcp",
    }
    
    // 执行扫描
    ctx := context.Background()
    result, err := xmap.Scan(ctx, target)
    if err != nil {
        fmt.Printf("扫描失败: %v\n", err)
        return
    }
    
    // 处理结果
    fmt.Printf("IP: %s, 端口: %d, 服务: %s, 版本: %s\n",
        result.IP, result.Port, result.Service, result.Version)
}
```

## 🏗️ 架构设计

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

### 指纹管理设计

XMap 使用单例模式实现 FingerprintManager，确保多任务共享指纹库：

```go
// 获取指纹管理器单例
func GetFingerprintManager(options *FingerprintOptions) *FingerprintManager {
    // 单例实现确保指纹库只加载一次
    // ...
    return fingerprintManagerInstance
}
```

### 扫描引擎设计

XMap 提供统一的扫描接口，支持单个和批量目标扫描：

```go
// Scanner 定义扫描器接口
type Scanner interface {
    // 执行单个目标扫描
    Scan(ctx context.Context, target string, opts ...ScanOption) (*Result, error)
    
    // 执行批量目标扫描
    BatchScan(ctx context.Context, targets []string, opts ...ScanOption) ([]*Result, error)
}
```

### 工作池设计

为支持高效的并发扫描，XMap 实现了工作池机制，可根据需要动态调整并发度。

## 📋 项目结构

```
xmap/
├── pkg/                      # 公共包
│   ├── api/                  # API接口
│   ├── model/                # 数据模型
│   ├── probe/                # 探针定义
│   ├── scanner/              # 扫描引擎
│   └── web/                  # Web扫描
├── examples/                 # 使用示例
│   ├── batch/                # 批量扫描示例
│   └── simple/               # 简单扫描示例
├── test/                     # 测试代码
├── main.go                   # 主程序入口
├── go.mod                    # Go模块定义
└── README.md                 # 项目文档
```

## ⚙️ 配置选项

XMap 提供了丰富的配置选项，可以通过命令行参数或编程接口设置：

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

5. **Web扫描增强**：
   - 集成appfinger，提供高效的Web应用指纹识别
   - 共享指纹库设计，减少内存占用

## 📚 文档

详细文档请参阅 [Wiki](https://github.com/tongchengbin/xmap/wiki)

## 🤝 贡献指南

我们欢迎并感谢任何形式的贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何参与项目开发。

## 📄 许可证

XMap 使用 [MIT 许可证](LICENSE)。

## 🙏 致谢

XMap 基于以下开源项目和资源：

- [rule](https://github.com/tongchengbin/finger-rules) - 提供服务指纹识别规则
- [appfinger](https://github.com/tongchengbin/appfinger) - 提供Web应用指纹识别能力
- [goflags](https://github.com/projectdiscovery/goflags) - 提供命令行参数解析
- [gologger](https://github.com/projectdiscovery/gologger) - 提供日志记录功能
