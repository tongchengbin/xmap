package types

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ScanStatus 扫描结果状态
type ScanStatus int

const (
	StatusUnknown ScanStatus = iota
	StatusMatched
	StatusNoMatch
	StatusError
	StatusClosed
	StatusInvalid    // 无效目标（如连续多次连接失败）
	StatusFirewalled // 可能被防火墙阻止
)

// ScanTarget 表示扫描目标
type ScanTarget struct {
	// Web 场景下的协议（http/https），与 Protocol (tcp/udp) 区分
	Scheme string `json:"-"`
	// 原始输入（用户提供的字符串）
	Raw string `json:"raw,omitempty"`
	// 解析后的信息
	Host     string `json:"host,omitempty"`     // 主机名或IP
	IP       string `json:"ip,omitempty"`       // IP地址
	Port     int    `json:"port,omitempty"`     // 端口
	Protocol string `json:"protocol,omitempty"` // 协议 (TCP/UDP)
	Path     string `json:"path,omitempty"`     // URL路径
	// 解析状态，不输出到JSON
	Parsed bool `json:"-"`
	// 状态检查器，用于跟踪连接状态，不输出到JSON
	StatusCheck interface{} `json:"-"`
	// TLS证书，不输出到JSON
	TLSCertificates []*x509.Certificate `json:"-"`
	// 证书信息，用于临时存储解析的证书数据
	Certificate map[string]interface{} `json:"-"`
}

func NewTarget(raw string) *ScanTarget {
	// 判断目标类型
	/*
		IP:PORT
		DOMAIN:PORT
		scheme://DOMAIN:PORT
		scheme://IP:PORT
		udp://DOMAIN:PORT
		tcp://DOMAIN:PORT
	*/
	target := &ScanTarget{
		Raw:      raw,
		Protocol: "tcp", // 默认协议为TCP
	}
	// 检查是否包含协议前缀
	if parts := strings.Split(raw, "://"); len(parts) > 1 {
		scheme := strings.ToLower(parts[0])
		host := parts[1]
		// 处理协议
		switch scheme {
		case "http", "https":
			target.Scheme = scheme
			target.Protocol = "tcp"
		case "tcp", "udp":
			target.Protocol = scheme
		default:
			// 未知协议，使用默认TCP
			target.Protocol = "tcp"
		}
		// 处理路径
		if pathIndex := strings.Index(host, "/"); pathIndex != -1 {
			target.Path = host[pathIndex:]
			host = host[:pathIndex]
		}
		// 解析主机和端口
		if hostPort := strings.Split(host, ":"); len(hostPort) > 1 {
			target.Host = hostPort[0]
			port, err := strconv.Atoi(hostPort[1])
			if err == nil && port > 0 && port < 65536 {
				target.Port = port
			} else {
				// 无效端口，使用默认端口
				if target.Scheme == "https" {
					target.Port = 443
				} else {
					target.Port = 80
				}
			}
		} else {
			target.Host = host
			// 根据协议设置默认端口
			if target.Scheme == "https" {
				target.Port = 443
			} else {
				target.Port = 80
			}
		}
	} else {
		// 没有协议前缀，检查是否有端口
		if hostPort := strings.Split(raw, ":"); len(hostPort) > 1 {
			sep := hostPort[0]
			target.Host = sep
			port, err := strconv.Atoi(hostPort[1])
			if err == nil && port > 0 && port < 65536 {
				target.Port = port
			} else {
				// 无效端口，使用默认端口
				target.Port = 80
			}
		} else {
			// 只有主机名，使用默认端口
			target.Host = raw
			target.Port = 80
		}
	}
	// 如果host 是IP，设置IP
	if ip := net.ParseIP(target.Host); ip != nil {
		target.IP = ip.String()
	}
	// 标记为已解析
	target.Parsed = true
	return target
}

// String 返回目标的字符串表示
func (t *ScanTarget) String() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// ScanResult 表示扫描结果
type ScanResult struct {
	// 目标信息
	Target *ScanTarget `json:"-"`
	// Protocol
	Protocol string `json:"protocol"`
	// 主机名
	Hostname string `json:"hostname"` // 域名或IP
	Port     int    `json:"port"`
	IP       string `json:"ip,omitempty"` // 解析IP，可能为空
	// Web 扫描相关字段
	URL    string                 `json:"url,omitempty"`
	Banner map[string]interface{} `json:"banner,omitempty"`
	// 通用组件信息
	Components []map[string]interface{} `json:"components,omitempty"`
	// 服务名称
	Service string `json:"service"`
	// 是否使用SSL
	SSL bool `json:"ssl,omitempty"`
	// 证书信息
	Certificate *SSLResponse `json:"certificate,omitempty"`
	// 附加信息
	Extra       map[string]interface{} `json:"extra,omitempty"`
	RawResponse []byte
	// 匹配的探针名称
	MatchedProbe string `json:"matched_probe"`
	// 匹配的正则表达式
	MatchedPattern string `json:"matched_pattern"`
	// 扫描耗时
	Duration float64 `json:"duration"`
	// 错误信息
	Error error `json:"error"`
	// 扫描状态
	Status    ScanStatus `json:"status"`
	startTime time.Time
	endTime   time.Time
}

// NewScanResult 创建新的扫描结果
func NewScanResult(target *ScanTarget) *ScanResult {
	return &ScanResult{
		Target:    target,
		startTime: time.Now(),
		IP:        target.IP,
		Port:      target.Port,
		Hostname:  target.Host,
		Protocol:  target.Protocol,
		Banner:    make(map[string]interface{}),
		Status:    StatusUnknown,
	}
}

// JSON 返回扫描结果的 JSON 字符串
func (r *ScanResult) JSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Complete 完成扫描结果
func (r *ScanResult) Complete(err error) {
	r.Error = err
	r.endTime = time.Now()
	r.Duration = r.endTime.Sub(r.startTime).Seconds()
	// 根据错误类型设置状态
	if err != nil && r.Service == "" {
		if err.Error() == "invalid target" {
			r.Status = StatusInvalid
		} else {
			r.Status = StatusError
		}
	} else if r.Service != "" {
		r.Status = StatusMatched
	} else {
		r.Status = StatusNoMatch
	}
	if r.Service == "ssl" || r.Service == "tls" {
		r.SSL = true
	}
}

// SetMatchResult 设置匹配结果
func (r *ScanResult) SetMatchResult(probeName, service, pattern string, softMatch bool) {
	r.MatchedProbe = probeName
	r.MatchedPattern = pattern
}
