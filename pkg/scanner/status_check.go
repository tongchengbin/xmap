package scanner

import (
	"github.com/projectdiscovery/gologger"
)

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
	reason               error
}

type PortStatus int

func (p *PortStatusCheck) SetOpen() {
	p.Open++
	p.ConsecutiveOpen++
	p.ConsecutiveClose = 0
	p.FailuresSinceSuccess = 0
}

func (p *PortStatusCheck) SetReadOK() {
	p.ReadOk++
}

func (p *PortStatusCheck) SetClose(failureType string) {
	p.Close++
	p.ConsecutiveClose++
	p.ConsecutiveOpen = 0
	p.LastFailureType = failureType
	p.FailuresSinceSuccess++
}

func (p *PortStatusCheck) GetReason() error {
	return p.reason
}
func (p *PortStatusCheck) IsClose() bool {
	// 判断端口是否关闭的条件：
	// 1. 从未成功连接且至少有3次连续失败
	if p.Open == 0 && p.ConsecutiveClose >= 3 {
		return true
	}

	// 2. 曾经成功连接，但之后有5次连续失败
	if p.Open > 0 && p.FailuresSinceSuccess >= 5 {
		return true
	}
	// read timeout max
	if p.ReadOk == 0 && (p.ReadTimeout > 10 || p.WriteTimeout > 10) {
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
func (p *PortStatusCheck) HandleError(err error, target *Target) (bool, error) {
	if err == nil {
		return false, nil
	}
	p.reason = err

	// 解析错误类型
	errType, specificErr, _ := ParseNetworkError(err)

	// 根据错误类型更新状态
	switch errType {
	case ErrorTypePortClosed:
		p.SetClose("refused")
		// 对于明确拒绝的连接，可以更快地判定为无效目标
		return true, ErrPortClosed
	case ErrorTypeReadTimeout:
		p.ReadTimeout++
		p.SetClose("read_timeout")
	case ErrorTypeWriteTimeout:
		p.WriteTimeout++
		p.SetClose("write_timeout")
	case ErrorTypeConnectionTimeout:
		p.WriteTimeout++ // 连接超时也计入写入超时
		p.SetClose("timeout")
	case ErrorTypeNetworkUnreachable:
		p.SetClose("network_unreachable")
	case ErrorTypeHostUnreachable:
		p.SetClose("host_unreachable")
	default:
		p.SetClose("unknown")
		gologger.Debug().Msgf("未知错误: %s:%d - %v", target.IP, target.Port, err)
	}

	// 检查是否应该终止扫描
	if p.IsClose() {
		return true, ErrPortClosed
	}
	return false, specificErr
}

type SocketStatus struct {
	status PortStatus
	data   []byte
	err    error
}
