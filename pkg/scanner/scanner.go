package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	gologger.Debug().Msgf("scanning %s with config: %v", target.String(), scanOptions)
	if scanOptions.MaxTimeout > 0 {
		// ctx 包裹
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanOptions.MaxTimeout)
		defer cancel()
	}
	// 对探针进行排序，优先使用适合当前端口的探针
	probes = sortProbes(probes, target.Port, false)
	// 执行扫描
	err := s.executeProbes(ctx, target, probes, false, result, scanOptions)
	if result.Service == "ssl" {
		probes = sortProbes(probes, target.Port, true)
		err = s.executeProbes(ctx, target, probes, true, result, scanOptions)
	}
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
func (s *ServiceScanner) executeProbes(ctx context.Context, target *Target, probes []*probe.Probe, useSSl bool, result *ScanResult, options *ScanOptions) error {
	// 对每个探针执行扫描
	for _, pb := range probes {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 继续处理
		}
		// 执行探针
		response, errType := s.executeProbe(ctx, target, pb, useSSl, options)
		if s.defaultOptions.DebugResponse && len(response) > 0 {
			gologger.Print().Msgf("Read (%d bytes) for probe %s on %s:%d:\n%s", len(response), pb.Name, target.IP, target.Port, formatProbeData(response))
		}
		if len(response) > 0 {
			// 匹配响应
			target.StatusCheck.SetOpen()
			matchService, extra := pb.Match(response)
			// 如果匹配成功
			if matchService != nil {
				if useSSl {
					gologger.Debug().Msgf("Matched probe %s on (ssl)%s://%s:%d line on:%d", pb.Name, matchService.Service, target.IP, target.Port, matchService.Line)
				} else {
					gologger.Debug().Msgf("Matched probe %s on %s://%s:%d line on:%d", pb.Name, matchService.Service, target.IP, target.Port, matchService.Line)
				}
				result.Extra = extra
				result.Service = matchService.Service
				result.SSL = useSSl
				return nil
			}
		}
		shouldTerminate := target.StatusCheck.HandleError(errType, target)
		if shouldTerminate {
			return target.StatusCheck.GetReason()
		}
	}
	// 如果没有匹配到任何服务
	return ErrNotMatched
}

func replaceProbeRaw(raw []byte, target *Target) []byte {
	return bytes.Replace(raw, []byte("{Host}"), []byte(fmt.Sprintf("%s:%d", target.IP, target.Port)), 1)
}

// executeProbe 执行单个探针
func (s *ServiceScanner) executeProbe(ctx context.Context, target *Target, probe *probe.Probe, UseSSl bool, options *ScanOptions) ([]byte, ErrorType) {
	// 创建连接超时上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	if options.DebugRequest {
		gologger.Debug().Msgf("Sending probe %s to %s", probe.Name, target.String())
	}
	// 创建连接
	conn, err := s.createConnection(timeoutCtx, string(target.Protocol), fmt.Sprintf("%s:%d", target.IP, target.Port), UseSSl, options.Timeout)
	if err != nil {
		gologger.Debug().Msgf("Connect from [%s:%d] (timeout: 5000ms) %s", target.IP, target.Port, err)
		return nil, ParseNetworkError(err)
	}
	defer conn.Close()
	// 设置读写超时
	_ = conn.SetDeadline(time.Now().Add(options.Timeout))
	// 发送探针数据
	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw)
	if UseSSl {
		gologger.Debug().Msgf("Sendto request for %d bytes to [ssl://%s:%d]", len(raw), target.IP, target.Port)
	} else {
		gologger.Debug().Msgf("Sendto request for %d bytes to [%s:%d]", len(raw), target.IP, target.Port)
	}

	if err != nil {
		gologger.Debug().Msgf("WRITE Faild for [%s:%d]", target.IP, target.Port)
		// 使用 HandleError 方法统一处理错误
		return nil, ParseNetworkError(err)
	}
	// 读取响应
	response, err := s.readResponse(conn, options)
	if len(response) > 0 {
		return response, ErrNil
	}
	if err != nil {
		gologger.Debug().Msgf("READ Err for  [%s:%d]", target.IP, target.Port)
		// 使用 HandleError 方法统一处理错误
		return response, ParseNetworkError(err)
	}
	return response, ErrNil
}

// createConnection 创建网络连接
func (s *ServiceScanner) createConnection(ctx context.Context, protocol string, address string, useSSL bool, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	// 检查是否需要 TLS 连接
	if useSSL {
		// 先创建普通连接
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		// TLS 配置
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // 跳过证书验证，用于扫描
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
		// 升级为 TLS 连接
		tlsConn := tls.Client(conn, tlsConfig)
		// 设置握手超时
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			conn.Close()
			return nil, err
		}
		// 执行 TLS 握手
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		// 重置超时
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			tlsConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	// 普通 TCP 连接
	return dialer.DialContext(ctx, protocol, address)
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
			return responseData, fmt.Errorf(fmt.Sprintf("max read timeout: %s", options.Timeout.String()))
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
			if errors.Is(err, io.EOF) {
				return responseData, err
			}
		}
	}
	return responseData, nil
}

// formatProbeData 格式化探针数据以便于日志输出
func formatProbeData(data []byte) string {
	if len(data) == 0 {
		return "<NULL>"
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
