package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// 定义扫描过程中可能遇到的错误类型
var (
	// ErrPortClosed 表示端口关闭（连接被拒绝）
	ErrPortClosed = errors.New("port closed")

	ErrNotMatched = errors.New("not matched")
	// ErrConnectionTimeout 表示连接超时
	ErrConnectionTimeout = errors.New("connection timeout")

	// ErrReadTimeout 表示读取超时
	ErrReadTimeout = errors.New("read timeout")

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

// ErrorType 错误类型枚举
type ErrorType int

const (
	ErrorTypeUnknown ErrorType = iota
	ErrorTypePortClosed
	ErrorTypeConnectionTimeout
	ErrorTypeReadTimeout
	ErrorTypeWriteTimeout
	ErrorTypeNetworkUnreachable
	ErrorTypeHostUnreachable
	ErrorTypeDNSError
	ErrorTypePermissionDenied
	ErrorTypeFirewalled
)

// ParseNetworkError 解析网络错误并返回特定的错误类型和错误实例
// 返回值：
// - errorType: 错误类型枚举
// - specificError: 特定的错误实例
// - originalError: 原始错误（如果需要保留）
func ParseNetworkError(err error) (ErrorType, error, error) {
	if err == nil {
		return ErrorTypeUnknown, nil, nil
	}

	// 检查是否已经是我们定义的错误类型
	if errors.Is(err, ErrPortClosed) {
		return ErrorTypePortClosed, ErrPortClosed, err
	}
	if errors.Is(err, ErrConnectionTimeout) {
		return ErrorTypeConnectionTimeout, ErrConnectionTimeout, err
	}
	if errors.Is(err, ErrReadTimeout) {
		return ErrorTypeReadTimeout, ErrReadTimeout, err
	}
	if errors.Is(err, ErrWriteTimeout) {
		return ErrorTypeWriteTimeout, ErrWriteTimeout, err
	}
	if errors.Is(err, ErrNetworkUnreachable) {
		return ErrorTypeNetworkUnreachable, ErrNetworkUnreachable, err
	}
	if errors.Is(err, ErrHostUnreachable) {
		return ErrorTypeHostUnreachable, ErrHostUnreachable, err
	}
	if errors.Is(err, ErrDNSError) {
		return ErrorTypeDNSError, ErrDNSError, err
	}
	if errors.Is(err, ErrPermissionDenied) {
		return ErrorTypePermissionDenied, ErrPermissionDenied, err
	}
	if errors.Is(err, ErrFirewalled) {
		return ErrorTypeFirewalled, ErrFirewalled, err
	}

	// 解析错误字符串
	errStr := err.Error()

	// 连接被拒绝
	if strings.Contains(errStr, "refused") {
		return ErrorTypePortClosed, fmt.Errorf("%w: %v", ErrPortClosed, err), err
	}

	// 网络不可达
	if strings.Contains(errStr, "network is unreachable") {
		return ErrorTypeNetworkUnreachable, fmt.Errorf("%w: %v", ErrNetworkUnreachable, err), err
	}

	// 主机不可达
	if strings.Contains(errStr, "host is unreachable") || strings.Contains(errStr, "no route to host") {
		return ErrorTypeHostUnreachable, fmt.Errorf("%w: %v", ErrHostUnreachable, err), err
	}

	// DNS错误
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup") {
		return ErrorTypeDNSError, fmt.Errorf("%w: %v", ErrDNSError, err), err
	}

	// 权限错误
	if strings.Contains(errStr, "permission denied") {
		return ErrorTypePermissionDenied, fmt.Errorf("%w: %v", ErrPermissionDenied, err), err
	}
	if strings.Contains(errStr, "read timeout") {
		return ErrorTypeReadTimeout, fmt.Errorf("%w: %v", ErrReadTimeout, err), err
	}
	// 检查超时错误
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// 区分不同类型的超时
		if strings.Contains(errStr, "read") {
			return ErrorTypeReadTimeout, fmt.Errorf("%w: %v", ErrReadTimeout, err), err
		}
		if strings.Contains(errStr, "write") {
			return ErrorTypeWriteTimeout, fmt.Errorf("%w: %v", ErrWriteTimeout, err), err
		}
		// 默认为连接超时
		return ErrorTypeConnectionTimeout, fmt.Errorf("%w: %v", ErrConnectionTimeout, err), err
	}

	// 未知错误
	return ErrorTypeUnknown, err, err
}

// IsConnectionRefused 检查错误是否为连接被拒绝
func IsConnectionRefused(err error) bool {
	if err == nil {
		return false
	}

	errType, _, _ := ParseNetworkError(err)
	return errType == ErrorTypePortClosed
}

// IsTimeout 检查错误是否为超时
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}

	errType, _, _ := ParseNetworkError(err)
	return errType == ErrorTypeConnectionTimeout ||
		errType == ErrorTypeReadTimeout ||
		errType == ErrorTypeWriteTimeout
}

// IsReadTimeout 检查错误是否为读取超时
func IsReadTimeout(err error) bool {
	if err == nil {
		return false
	}

	errType, _, _ := ParseNetworkError(err)
	return errType == ErrorTypeReadTimeout
}

// IsWriteTimeout 检查错误是否为写入超时
func IsWriteTimeout(err error) bool {
	if err == nil {
		return false
	}

	errType, _, _ := ParseNetworkError(err)
	return errType == ErrorTypeWriteTimeout
}

// IsNetworkUnreachable 检查错误是否为网络不可达
func IsNetworkUnreachable(err error) bool {
	if err == nil {
		return false
	}

	errType, _, _ := ParseNetworkError(err)
	return errType == ErrorTypeNetworkUnreachable
}

// IsHostUnreachable 检查错误是否为主机不可达
func IsHostUnreachable(err error) bool {
	if err == nil {
		return false
	}

	errType, _, _ := ParseNetworkError(err)
	return errType == ErrorTypeHostUnreachable
}

// WrapNetworkError 将网络错误包装为自定义错误类型
func WrapNetworkError(err error) error {
	if err == nil {
		return nil
	}

	_, specificErr, _ := ParseNetworkError(err)
	return specificErr
}
