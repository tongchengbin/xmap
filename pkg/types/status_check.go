package types

import (
	"errors"
	"io"
	"strings"
	"github.com/projectdiscovery/gologger"
)

// ParseNetworkError 解析网络错误并返回特定的错误类型
func ParseNetworkError(err error) ErrorType {
	if err == nil {
		return ErrNil
	}
	if errors.Is(err, io.EOF) {
		return ErrorEOF
	} else if strings.Contains(err.Error(), "max read timeout") {
		return ErrorTypeReadTimeout
	} else if strings.Contains(err.Error(), "refused it") {
		return ErrorTypeConnectionTimeout
	} else if strings.Contains(err.Error(), "i/o timeout") {
		return ErrorTypeReadTimeout
	} else {
		return ErrorType("") // Unknown, fallback
	}
}

// PortStatusCheck 添加状态管理器 优化扫描效率
type PortStatusCheck struct {
	Close                int    // 连接失败总次数
	Open                 int    // 连接成功总次数
	ReadOk               int    // 读取到数据的次数
	ConsecutiveClose     int    // 连续失败次数
	ConsecutiveOpen      int    // 连续成功次数
	LastFailureType      string // 最后一次失败类型（timeout, refused等）
	ReadTimeout          int    // 读取超时次数
	WriteTimeout         int    // 写入超时次数
	FailuresSinceSuccess int    // 上次成功后的失败次数
	reason               string
	NotMatch             int  // 未匹配上次数
	Terminate            bool // 是否可以判断端口已经关闭
}

type PortStatus int

// ErrorType 定义错误类型
type ErrorType string

const (
	ErrNil                   ErrorType = "nil"
	ErrorTypeReadTimeout     ErrorType = "read_timeout"
	ErrorTypeWriteTimeout    ErrorType = "write_timeout"
	ErrorTypeConnectionTimeout ErrorType = "connection_timeout"
	ErrorTypeNetworkUnreachable ErrorType = "network_unreachable"
	ErrorTypeHostUnreachable ErrorType = "host_unreachable"
	ErrorEOF                 ErrorType = "eof"
)

func (p *PortStatusCheck) SetOpen() {
	p.Open++
	p.ConsecutiveOpen++
	p.ConsecutiveClose = 0
	p.FailuresSinceSuccess = 0
}

func (p *PortStatusCheck) SetReadOK() {
	p.ReadOk++
}

func (p *PortStatusCheck) SetTerminate() {
	p.Terminate = true
}

func (p *PortStatusCheck) SetClose(failureType string) {
	p.Close++
	p.ConsecutiveClose++
	p.ConsecutiveOpen = 0
	p.LastFailureType = failureType
	p.FailuresSinceSuccess++
}

func (p *PortStatusCheck) GetReason() error {
	return errors.New(p.reason)
}

func (p *PortStatusCheck) IsClose() bool {
	// 判断端口是否关闭的条件：

	// 1. 从未成功连接且至少有3次连续失败
	if p.Open == 0 && p.ConsecutiveClose >= 6 {
		return true
	}

	// 2. 曾经成功连接，但之后有5次连续失败
	if p.Open > 0 && p.FailuresSinceSuccess >= 5 {
		return true
	}

	// 如果一次未成功连接
	if p.Open == 0 && (p.ReadTimeout > 5 || p.WriteTimeout > 5) {
		return true
	}
	if p.ConsecutiveClose > 10 {
		// 连续失败10次
		return true
	}

	return false
}

// IsLikelyFirewalled 检查目标是否可能被防火墙阻止
func (p *PortStatusCheck) IsLikelyFirewalled() bool {
	return p.LastFailureType == "timeout" && p.ConsecutiveClose >= 2
}

// HandleError 统一处理错误并更新状态检查器
// 返回：
// - 是否应该终止扫描
// - 包装后的错误
func (p *PortStatusCheck) HandleError(errType ErrorType, target *ScanTarget) bool {
	// 解析错误类型
	// 根据错误类型更新状态
	switch errType {
	case ErrNil:
		p.NotMatch++
	case ErrorTypeReadTimeout:
		p.ReadTimeout++
		p.reason = "read_timeout"
	case ErrorTypeWriteTimeout:
		p.WriteTimeout++
		p.reason = "write_timeout"
	case ErrorTypeConnectionTimeout:
		p.WriteTimeout++
		p.reason = "connection_timeout"
	case ErrorTypeNetworkUnreachable:
		p.reason = "network_unreachable"
		p.Terminate = true
		return true
	case ErrorTypeHostUnreachable:
		p.reason = "host_unreachable"
		p.SetTerminate()
		return true
	case ErrorEOF:
		p.reason = "EOF"
		p.ConsecutiveClose++
	default:
		p.SetClose("unknown")
		gologger.Debug().Msgf("未知错误: %s:%d - %v", target.IP, target.Port, errType)
	}
	// 检查是否应该终止扫描
	if p.IsClose() {
		return true
	}
	return false
}

type SocketStatus struct {
	status PortStatus
	data   []byte
	err    error
}
