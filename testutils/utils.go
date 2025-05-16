package testutils

import (
	"bytes"
	"fmt"
)

// FormatBytes 格式化请求/响应内容，用于调试输出
// 可打印字符直接显示，不可打印字符转换为\xxx格式
func FormatBytes(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}
	
	var buf bytes.Buffer
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "\\%03x", b)
		}
	}
	return buf.String()
}
