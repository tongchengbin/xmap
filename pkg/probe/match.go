package probe

import (
	"github.com/dlclark/regexp2"
	"strings"
)

// VersionInfo 表示版本信息
type VersionInfo struct {
	// 产品名称
	ProductName string
	// 版本号
	Version string
	// 附加信息
	Info string
	// 主机名
	Hostname string
	// 操作系统
	OS string
	// 设备类型
	DeviceType string
}



func getPatternRegexp(pattern string, opt string) *regexp2.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)
	var o regexp2.RegexOptions
	switch opt {
	case "i":
		o = regexp2.IgnoreCase
	case "s":
		o = regexp2.Singleline
	default:
		o = regexp2.None
	}
	return regexp2.MustCompile(pattern, o)
}

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}

func extractValues(s string) map[string]string {
	values := make(map[string]string)
	parts := strings.Split(s, " ")

	for _, part := range parts {
		if strings.HasPrefix(part, "p/") {
			values["p"] = extractValue(part, "p/")
		} else if strings.HasPrefix(part, "v/") {
			values["v"] = extractValue(part, "v/")
		} else if strings.HasPrefix(part, "i/") {
			values["i"] = extractValue(part, "i/")
		} else if strings.HasPrefix(part, "cpe:/a:") {
			values["cpe"] = extractCPEValue(part)
		}
	}

	return values
}
func extractValue(part, prefix string) string {
	start := len(prefix)
	end := strings.Index(part[start:], "/") + start
	if end > start {
		return part[start:end]
	}
	return part[start:]
}

func extractCPEValue(part string) string {
	start := len("cpe:/a:")
	end := strings.Index(part[start:], "/") + start
	if end > start {
		return part[start:end]
	}
	return part[start:]
}
