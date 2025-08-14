package utils

import (
	"fmt"
	"strings"
)

// FormatBytes Format bytes to a readable string
func FormatBytes(data []byte) string {
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
