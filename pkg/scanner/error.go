package scanner

import (
	"errors"
	"io"
	"strings"
)

// ErrorType 错误类型枚举
type ErrorType int

const (
	ErrNil ErrorType = iota
	ErrorTypeUnknown
	ErrorEOF
	ErrorTypeConnectionRefused
	ErrorTypeConnectionTimeout
	ErrorTypeReadTimeout
	ErrorTypeWriteTimeout
	ErrorTypeNetworkUnreachable
	ErrorTypeHostUnreachable
	ErrorTypeDNSError
	ErrorTypePermissionDenied
	ErrorTypeFirewalled
)

var (
	// ErrConnectionRefused 连接被拒绝
	ErrConnectionRefused = errors.New("connection refused")
	// ErrConnectionTimeout 连接超时
	ErrConnectionTimeout = errors.New("connection timeout")

	// ErrPortClosed 表示端口关闭（连接被拒绝）
	ErrPortClosed = errors.New("port closed")

	ErrNotMatched = errors.New("not matched")
	// ErrConnectionTimeout 表示连接超时

	// ErrReadTimeout 表示读取超时
	ErrReadTimeout = errors.New("read timeout")

	ErrEOF = errors.New("EOF")

	// ErrWriteTimeout 表示写入超时
	ErrWriteTimeout = errors.New("write timeout")

	// ErrFirewalled 表示目标可能被防火墙阻止
	ErrFirewalled = errors.New("target firewalled")

	// ErrNetworkUnreachable 表示网络不可达
	ErrNetworkUnreachable = errors.New("network unreachable")

	// ErrHostUnreachable 表示主机不可达
	ErrHostUnreachable = errors.New("host unreachable")

	// ErrDNSError 表示DNS解析错误
	ErrDNSError = errors.New("dns resolution error")

	// ErrPermissionDenied 表示权限错误
	ErrPermissionDenied = errors.New("permission denied")
)

// ParseNetworkError 解析网络错误并返回特定的错误类型和错误实例
// 返回值：
// - errorType: 错误类型枚举
func ParseNetworkError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	// 方法1：使用 errors.Is 检查标准 io.EOF
	if errors.Is(err, io.EOF) {
		return ErrorEOF
	} else if strings.Contains(err.Error(), "max read timeout") {
		return ErrorTypeReadTimeout
	} else {
		println(">>>>>>>>>>>>>>", err, err.Error())
		return ErrorTypeUnknown
	}
}
