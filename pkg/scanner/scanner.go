package scanner

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/xmap/pkg/probe"
	"github.com/tongchengbin/xmap/pkg/types"
)

// ServiceScanner 默认扫描器实现
type ServiceScanner struct {
	// 版本强度
	probeManager *probe.Manager
	dialer       *fastdialer.Dialer
	options      *types.Options
}

// NewServiceScanner 创建新的扫描器
func NewServiceScanner(options *types.Options) (*ServiceScanner, error) {
	// 创建默认选项
	probeManager, err := probe.GetManager(&probe.FingerprintOptions{
		VersionIntensity: options.VersionIntensity,
	})
	//var probeManager *probe.Manager
	if err != nil {
		gologger.Error().Msgf("获取指纹管理器失败: %v", err)
		return nil, err
	}
	// 创建fastdialer实例
	fdOptions := fastdialer.DefaultOptions
	// 使用系统默认DNS
	fdOptions.EnableFallback = true
	// 使用内存缓存
	fdOptions.CacheType = fastdialer.Memory
	fdOptions.CacheMemoryMaxItems = 1000
	if options.Proxy != "" {
		// 使用代理
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, err
		}
		dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			gologger.Error().Msgf("创建fastdialer失败: %v", err)
			return nil, err
		}
		fdOptions.ProxyDialer = &dialer
	}
	fd, err := fastdialer.NewDialer(fdOptions)
	if err != nil {
		gologger.Error().Msgf("创建fastdialer失败: %v", err)
		return nil, err
	}
	scanner := &ServiceScanner{
		options:      options,
		probeManager: probeManager,
		dialer:       fd,
	}
	return scanner, nil
}

// Scan 扫描单个目标
func (s *ServiceScanner) Scan(target *types.ScanTarget) (*types.ScanResult, error) {
	return s.ScanWithContext(context.Background(), target)
}

// ScanWithContext 带上下文的扫描
func (s *ServiceScanner) ScanWithContext(ctx context.Context, target *types.ScanTarget) (*types.ScanResult, error) {
	// 创建扫描结果
	result := types.NewScanResult(target)
	// 选择适用的探针
	var probes []*probe.Probe
	if target.Protocol == "tcp" {
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
	gologger.Debug().Msgf("start scan %s", target.String())
	if s.options.MaxTimeout > 0 {
		// ctx 包裹
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.options.MaxTimeout)*time.Second)
		defer cancel()
	}
	// 对探针进行排序，优先使用适合当前端口的探针
	probes = sortProbes(probes, target.Port, false)
	// 执行扫描
	err := s.executeProbes(ctx, target, probes, false, result)
	if result.Service == "ssl" {
		probes = sortProbes(probes, target.Port, true)
		err = s.executeProbes(ctx, target, probes, true, result)
	}
	result.Complete(err)
	return result, err
}

// executeProbes 执行探针扫描
func (s *ServiceScanner) executeProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, useSSl bool, result *types.ScanResult) error {
	// 根据协议类型选择不同的处理逻辑
	switch target.Protocol {
	case "udp":
		return s.executeUDPProbes(ctx, target, probes, result)
	default: // TCP
		return s.executeTCPProbes(ctx, target, probes, useSSl, result)
	}
}

// executeUDPProbes 执行 UDP 探针扫描
func (s *ServiceScanner) executeUDPProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, result *types.ScanResult) error {
	// 对每个探针执行扫描
	for _, pb := range probes {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 继续处理
		}
		// 执行 UDP 探针
		// UDP 不支持 SSL/TLS
		response, _ := s.executeUDPProbe(ctx, target, pb)
		if s.options.DebugResponse && len(response) > 0 {
			gologger.Print().Msgf("Read (%d bytes) for UDP probe %s on %s:%d:\n%s", len(response), pb.Name, target.IP, target.Port, formatProbeData(response))
		}

		if len(response) > 0 {
			// 匹配响应
			if sc, ok := target.StatusCheck.(*types.PortStatusCheck); ok {
				sc.SetOpen()
			}
			matchService, extra := pb.Match(response)
			if matchService != nil {
				// 设置服务信息
				result.Service = matchService.Service
				// 设置额外信息
				if extra != nil {
					if result.Extra == nil {
						result.Extra = make(map[string]interface{})
					}
					// 直接将 extra 中的键值对添加到 result.Extra 中
					for k, v := range extra {
						result.Extra[k] = v
					}
				}
				return nil
			}
		}
	}

	// 如果没有匹配到服务，但端口是开放的，设置为未知服务
	// 检查端口是否开放（如果有读取到数据或者成功连接过）
	if sc, ok := target.StatusCheck.(*types.PortStatusCheck); ok {
		if sc.Open > 0 || sc.ReadOk > 0 {
			result.Service = "unknown"
		}
	}
	return nil
}

// executeTCPProbes 执行 TCP 探针扫描
func (s *ServiceScanner) executeTCPProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, useSSl bool, result *types.ScanResult) error {
	// 对每个探针执行扫描
	for _, pb := range probes {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 继续处理
		}
		// 执行 TCP 探针
		response, errType := s.executeTCPProbe(ctx, target, pb, useSSl)
		if s.options.DebugResponse && len(response) > 0 {
			gologger.Print().Msgf("Read (%d bytes) for TCP probe %s on %s:%d:\n%s", len(response), pb.Name, target.IP, target.Port, formatProbeData(response))
		}
		if len(response) > 0 {
			// 匹配响应
			if sc, ok := target.StatusCheck.(*types.PortStatusCheck); ok {
				sc.SetOpen()
			}
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
		if sc, ok := target.StatusCheck.(*types.PortStatusCheck); ok {
			shouldTerminate := sc.HandleError(errType, target)
			if shouldTerminate {
				return sc.GetReason()
			}
		}
	}
	// 如果没有匹配到任何服务
	return errors.New("not matched")
}

// executeTCPProbe 执行 tcp 探针
func (s *ServiceScanner) executeTCPProbe(ctx context.Context, target *types.ScanTarget, probe *probe.Probe, useSSL bool) ([]byte, types.ErrorType) {
	// 创建连接超时上下文
	timeout := time.Duration(s.options.Timeout) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if s.options.DebugRequest {
		gologger.Debug().Msgf("Sending TCP probe %s to %s", probe.Name, target.Host)
	}

	// 创建 TCP 连接
	conn, err := s.createConnection(timeoutCtx, target, useSSL, timeout)
	if err != nil {
		gologger.Debug().Msgf("TCP connect to [%s:%d] failed (timeout: %ds): %s", target.IP, target.Port, s.options.Timeout, err)
		return nil, types.ParseNetworkError(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw)
	if useSSL {
		gologger.Debug().Msgf("Send %s %d bytes to [ssl://%s:%d]", probe.Name, len(raw), target.Host, target.Port)
	} else {
		gologger.Debug().Msgf("Send %s %d bytes to [tcp://%s:%d]", probe.Name, len(raw), target.Host, target.Port)
	}

	if err != nil {
		gologger.Debug().Msgf("TCP write failed for [%s:%d]: %v", target.IP, target.Port, err)
		return nil, types.ParseNetworkError(err)
	}
	response, err := s.readResponse(conn, timeout)
	if len(response) > 0 {
		return response, types.ErrNil
	}

	if err != nil {
		gologger.Debug().Msgf("TCP read failed for [%s:%d]: %v", target.Host, target.Port, err)
		return response, types.ParseNetworkError(err)
	}
	return response, types.ErrNil
}

// executeUDPProbe 执行 UDP 探针
func (s *ServiceScanner) executeUDPProbe(ctx context.Context, target *types.ScanTarget, probe *probe.Probe) ([]byte, types.ErrorType) {
	// 创建连接超时上下文
	timeout := time.Duration(s.options.Timeout) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if s.options.DebugRequest {
		gologger.Debug().Msgf("Sending UDP probe %s to %s", probe.Name, target.String())
	}
	// 创建 UDP 连接（UDP 不支持 SSL/TLS）
	conn, err := s.createConnection(timeoutCtx, target, false, timeout)
	if err != nil {
		gologger.Debug().Msgf("UDP connect to [%s:%d] failed (timeout: %ds): %s", target.Host, target.Port, s.options.Timeout, err)
		return nil, types.ParseNetworkError(err)
	}
	defer conn.Close()

	// 从 UDP 连接中获取实际的远程 IP 地址
	if udpConn, ok := conn.(*net.UDPConn); ok {
		if remoteAddr, ok := udpConn.RemoteAddr().(*net.UDPAddr); ok {
			resolvedIP := remoteAddr.IP.String()
			if target.IP == "" {
				target.IP = resolvedIP
				gologger.Debug().Msgf("%s:%d", resolvedIP, target.Port)
			}
		}
	}

	// 设置读写超时（UDP 需要更短的超时，因为它是无连接的）
	_ = conn.SetDeadline(time.Now().Add(timeout / 2))

	// 发送探针数据
	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw)
	gologger.Debug().Msgf("Sent %d bytes to [udp://%s:%d]", len(raw), target.Host, target.Port)

	if err != nil {
		gologger.Debug().Msgf("UDP write failed for [%s:%d]: %v", target.Host, target.Port, err)
		return nil, types.ParseNetworkError(err)
	}

	// 读取响应（UDP 可能不会有响应，所以要特别处理）
	response, err := s.readResponse(conn, timeout)

	if len(response) > 0 {
		// UDP 收到响应通常表示端口开放
		if sc, ok := target.StatusCheck.(*types.PortStatusCheck); ok {
			sc.SetOpen()
			sc.SetReadOK()
		}
		return response, types.ErrNil
	}

	if err != nil {
		// UDP 错误可能是端口过滤或关闭的标志
		gologger.Debug().Msgf("UDP read failed for [%s:%d]: %v", target.IP, target.Port, err)
		return response, types.ParseNetworkError(err)
	}

	return response, types.ErrNil
}

// createConnection 创建网络连接
func (s *ServiceScanner) createConnection(ctx context.Context, target *types.ScanTarget, useSSL bool, timeout time.Duration) (net.Conn, error) {
	// 构建连接地址
	address := fmt.Sprintf("%s:%d", target.Host, target.Port)
	// 使用fastdialer处理连接
	var conn net.Conn
	var err error
	// 根据协议类型创建不同类型的连接
	var network string
	switch target.Protocol {
	case "udp":
		network = "udp"
	default:
		network = "tcp" // 默认使用 TCP
	}
	// 设置超时上下文
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 检查是否需要 TLS 连接
	if useSSL {
		// 使用fastdialer的DialTLS方法进行TLS连接
		conn, err = s.dialer.DialTLS(dialCtx, network, address)
		if err != nil {
			gologger.Debug().Msgf("TLS连接失败: %v", err)
			return nil, err
		}
		// 获取目标IP
		if target.IP == "" && target.Host != "" {
			dnsData, err := s.dialer.GetDNSData(target.Host)
			if err == nil && dnsData != nil && len(dnsData.A) > 0 {
				target.IP = dnsData.A[0]
			}
		}
		return conn, nil
	}

	// 普通连接（TCP 或 UDP）
	conn, err = s.dialer.Dial(dialCtx, network, address)
	if err != nil {
		gologger.Debug().Msgf("连接失败: %v", err)
		return nil, err
	}

	// 获取目标IP
	if target.IP == "" && target.Host != "" {
		dnsData, err := s.dialer.GetDNSData(target.Host)
		if err == nil && dnsData != nil && len(dnsData.A) > 0 {
			target.IP = dnsData.A[0]
			gologger.Debug().Msgf("Resolved %s IP %s", target.Host, target.IP)
		} else {
			// 如果无法从 DNS 获取数据，尝试从连接中获取
			if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				target.IP = remoteAddr.IP.String()
				gologger.Debug().Msgf("从连接获取IP: %s", target.IP)
			}
		}
	}

	return conn, nil
}

// readResponse 从连接中读取响应数据
func (s *ServiceScanner) readResponse(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var responseData []byte
	buffer := make([]byte, 1024)
	// 设置最大读取时间
	maxReadTime := time.Now().Add(timeout)
	for {
		// 检查是否超过最大读取时间
		if time.Now().After(maxReadTime) {
			// 如果已经读取到了一些数据，则返回这些数据
			if len(responseData) > 0 {
				return responseData, nil
			}
			// 否则返回超时错误
			return responseData, fmt.Errorf(fmt.Sprintf("max read timeout: %s", timeout.String()))
		}
		// 设置单次读取超时
		remainingTime := maxReadTime.Sub(time.Now())
		if remainingTime <= 0 {
			remainingTime = 2 * time.Second // 最小超时时间
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

// replaceProbeRaw 替换探针原始数据中的占位符
func replaceProbeRaw(raw []byte, target *types.ScanTarget) []byte {
	var host string
	if target.Host != "" {
		host = target.Host
	} else {
		host = target.IP
	}
	return []byte(strings.ReplaceAll(string(raw), "{Host}", fmt.Sprintf("%s:%d", host, target.Port)))
}
