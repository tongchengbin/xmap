package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/xmap/pkg/probe"
)

// ServiceScanner 默认扫描器实现
type ServiceScanner struct {
	// 默认选项
	defaultOptions *ScanOptions
	// 版本强度
	probeManager *probe.Manager
}

// NewServiceScanner 创建新的扫描器
func NewServiceScanner(options ...ScanOption) (*ServiceScanner, error) {
	// 创建默认选项
	defaultOptions := DefaultScanOptions()

	// 应用选项
	for _, option := range options {
		option(defaultOptions)
	}

	probeManager, err := probe.GetManager(&probe.FingerprintOptions{
		VersionIntensity: defaultOptions.VersionIntensity,
	})
	if err != nil {
		gologger.Error().Msgf("获取指纹管理器失败: %v", err)
		return nil, err
	}
	// 创建扫描器
	scanner := &ServiceScanner{
		defaultOptions: defaultOptions,
		probeManager:   probeManager,
	}

	return scanner, nil
}

// Scan 扫描单个目标
func (s *ServiceScanner) Scan(target *Target, options ...ScanOption) (*ScanResult, error) {
	return s.ScanWithContext(context.Background(), target, options...)
}

// BatchScan 批量扫描多个目标
func (s *ServiceScanner) BatchScan(targets []*Target, options ...ScanOption) ([]*ScanResult, error) {
	return s.BatchScanWithContext(context.Background(), targets, options...)
}

// ScanWithContext 带上下文的扫描
func (s *ServiceScanner) ScanWithContext(ctx context.Context, target *Target, options ...ScanOption) (*ScanResult, error) {
	// 创建扫描选项
	scanOptions := s.createScanOptions(options)
	// 创建扫描结果
	result := NewScanResult(target)
	// 选择适用的探针
	var probes []*probe.Probe
	if target.Protocol == TCP {
		probes = s.probeManager.GetTCPProbes()
	} else {
		probes = s.probeManager.GetUDPProbes()
	}
	// sort probes by rarity
	if len(probes) == 0 {
		err := errors.New("no suitable probes found for target")
		result.Complete(err)
		return result, err
	}
	// 对探针进行排序，优先使用适合当前端口的探针
	probes = sortProbes(probes, target.Port, false)
	// 执行扫描
	err := s.executeProbes(ctx, target, probes, result, scanOptions)
	result.Complete(err)
	return result, err
}

// BatchScanWithContext 带上下文的批量扫描
func (s *ServiceScanner) BatchScanWithContext(ctx context.Context, targets []*Target, options ...ScanOption) ([]*ScanResult, error) {
	// 创建扫描选项
	scanOptions := s.createScanOptions(options)

	// 创建结果切片
	results := make([]*ScanResult, len(targets))

	// 创建工作池
	workerCount := scanOptions.MaxParallelism
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	// 创建任务通道
	tasks := make(chan int, len(targets))

	// 创建等待组
	var wg sync.WaitGroup
	wg.Add(workerCount)

	// 启动工作协程
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for taskIndex := range tasks {
				target := targets[taskIndex]
				result, _ := s.ScanWithContext(ctx, target, options...)
				results[taskIndex] = result

				// 检查上下文是否已取消
				select {
				case <-ctx.Done():
					return
				default:
					// 继续处理
				}
			}
		}()
	}

	// 分发任务
	for i := range targets {
		tasks <- i
	}
	close(tasks)

	// 等待所有工作完成
	wg.Wait()

	return results, nil
}

// createScanOptions 创建扫描选项
func (s *ServiceScanner) createScanOptions(options []ScanOption) *ScanOptions {
	// 复制默认选项
	scanOptions := &ScanOptions{}
	*scanOptions = *s.defaultOptions

	// 应用选项
	for _, option := range options {
		option(scanOptions)
	}

	return scanOptions
}

// executeProbes 执行探针扫描
func (s *ServiceScanner) executeProbes(ctx context.Context, target *Target, probes []*probe.Probe, result *ScanResult, options *ScanOptions) error {
	// 对每个探针执行扫描
	for _, pb := range probes {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 继续处理
		}

		// 检查目标是否已被判定为无效
		if target.StatusCheck.IsClose() {
			gologger.Warning().Msgf("目标 %s:%d 已被判定为无效，终止后续探针扫描", target.IP, target.Port)
			return target.StatusCheck.GetReason()
		}
		// 检查目标是否可能被防火墙阻止
		if target.StatusCheck.IsLikelyFirewalled() {
			return target.StatusCheck.GetReason()
		}
		// 执行探针
		response, err := s.executeProbe(ctx, target, pb, options)
		if err != nil {
			// 使用 HandleError 方法统一处理错误
			shouldTerminate, _ := target.StatusCheck.HandleError(err, target)
			if shouldTerminate {
				return target.StatusCheck.GetReason()
			}
			// 继续尝试下一个探针
			continue
		}
		if s.defaultOptions.DebugResponse {
			gologger.Print().Msgf("Read (%d bytes) for probe %s on %s:%d:\n%s", len(response), pb.Name, target.IP, target.Port, formatProbeData(response))
		}
		// 匹配响应
		matchService, extra := pb.Match(response)
		// 如果匹配成功
		if matchService != nil {
			gologger.Debug().Msgf("Matched probe %s on %s://%s:%d line on:%d", pb.Name, matchService.Service, target.IP, target.Port, matchService.Line)
			result.Extra = extra
			result.Service = matchService.Service
			return nil
		}
	}
	// 如果没有匹配到任何服务
	return ErrNotMatched
}

// executeProbe 执行单个探针
func (s *ServiceScanner) executeProbe(ctx context.Context, target *Target, probe *probe.Probe, options *ScanOptions) ([]byte, error) {
	// 创建连接超时上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	if options.DebugRequest {
		gologger.Debug().Msgf("Sending probe %s to %s:%d", probe.Name, target.IP, target.Port)
	}

	// 创建连接
	conn, err := s.createConnection(timeoutCtx, target, options.Timeout)
	if err != nil {
		// 使用 HandleError 方法统一处理错误
		shouldTerminate, wrappedErr := target.StatusCheck.HandleError(err, target)
		if shouldTerminate {
			return nil, wrappedErr
		}
		return nil, wrappedErr
	}
	defer conn.Close()

	// 连接成功，更新状态检查器
	target.StatusCheck.SetOpen()

	// 设置读写超时
	_ = conn.SetDeadline(time.Now().Add(options.Timeout))
	// 发送探针数据
	_, err = conn.Write(probe.SendData)
	if err != nil {
		gologger.Debug().Msgf("发送探针数据到 %s:%d 失败: %v", target.IP, target.Port, err)
		// 使用 HandleError 方法统一处理错误
		shouldTerminate, wrappedErr := target.StatusCheck.HandleError(err, target)
		if shouldTerminate {
			return nil, wrappedErr
		}
		return nil, wrappedErr
	}

	// 读取响应
	response, err := s.readResponse(conn, options)
	if len(response) > 0 {
		target.StatusCheck.SetReadOK()
	}
	if err != nil {
		// 使用 HandleError 方法统一处理错误
		shouldTerminate, wrappedErr := target.StatusCheck.HandleError(err, target)
		if shouldTerminate {
			return response, wrappedErr
		}
		return response, wrappedErr
	}
	return response, nil
}

// createConnection 创建网络连接
func (s *ServiceScanner) createConnection(ctx context.Context, target *Target, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	if target.Protocol == TCP {
		return dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target.IP, target.Port))
	} else if target.Protocol == UDP {
		return dialer.DialContext(ctx, "udp", fmt.Sprintf("%s:%d", target.IP, target.Port))
	} else {
		return nil, fmt.Errorf("unsupported protocol: %s", target.Protocol)
	}
}

// readResponse 从连接中读取响应数据
func (s *ServiceScanner) readResponse(conn net.Conn, options *ScanOptions) ([]byte, error) {
	var responseData []byte
	buffer := make([]byte, 1024)

	// 设置最大读取时间
	maxReadTime := time.Now().Add(options.Timeout)
	for {
		// 检查是否超过最大读取时间
		if time.Now().After(maxReadTime) {
			// 如果已经读取到了一些数据，则返回这些数据
			if len(responseData) > 0 {
				return responseData, nil
			}
			// 否则返回超时错误
			return responseData, fmt.Errorf("max read timeout")
		}

		// 设置单次读取超时
		remainingTime := maxReadTime.Sub(time.Now())
		if remainingTime <= 0 {
			remainingTime = 100 * time.Millisecond // 最小超时时间
		}
		_ = conn.SetReadDeadline(time.Now().Add(remainingTime))

		// 读取数据
		n, err := conn.Read(buffer)
		// 如果读取到数据，追加到响应中
		if n > 0 {
			responseData = append(responseData, buffer[:n]...)
			// 如果缓冲区未满，可能表示数据已经读取完毕
			if n < len(buffer) {
				break
			}

			// 如果响应数据已经足够大，停止读取
			if len(responseData) >= 4096 {
				break
			}
		}

		// 处理错误
		if err != nil {
			err = ErrReadTimeout
		}
	}
	return responseData, nil
}

// formatProbeData 格式化探针数据以便于日志输出
func formatProbeData(data []byte) string {
	if len(data) == 0 {
		return "NULL"
	}

	var result strings.Builder
	result.WriteString("b'")

	for _, b := range data {
		if b >= 32 && b <= 126 { // 可打印 ASCII 字符
			if b == '\\' || b == '\'' { // 转义反斜杠和单引号
				result.WriteByte('\\')
			}
			result.WriteByte(b)
		} else {
			// 特殊字符使用 \x 格式
			switch b {
			case '\n':
				result.WriteString("\\n")
			case '\r':
				result.WriteString("\\r")
			case '\t':
				result.WriteString("\\t")
			default:
				result.WriteString(fmt.Sprintf("\\x%02x", b))
			}
		}
	}

	result.WriteString("'")
	return result.String()
}
