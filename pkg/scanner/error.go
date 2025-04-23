package scanner

import (
	"errors"
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
