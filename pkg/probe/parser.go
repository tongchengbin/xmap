package probe

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// ParseProbes 解析探针文件内容并添加到指定的探针存储中
func ParseProbes(content string) ([]*Probe, error) {
	var currentProbe *Probe
	probes := make([]*Probe, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// 跳过注释和空行
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// 解析探针定义行
		if strings.HasPrefix(line, "Probe ") {
			currentProbe = parseProbeDefinition(line)
			if currentProbe != nil {
				probes = append(probes, currentProbe)
			}
			continue
		}

		// 如果没有当前探针，跳过
		if currentProbe == nil {
			continue
		}

		// 解析端口定义
		if strings.HasPrefix(line, "ports ") {
			parsePortsDefinition(currentProbe, line, false)
			continue
		}

		// 解析SSL端口定义
		if strings.HasPrefix(line, "sslports ") {
			parsePortsDefinition(currentProbe, line, true)
			continue
		}

		// 解析总等待时间
		if strings.HasPrefix(line, "totalwaitms ") {
			parseTotalWaitMS(currentProbe, line)
			continue
		}

		// 解析TCP包装等待时间
		if strings.HasPrefix(line, "tcpwrappedms ") {
			parseTCPWrappedMS(currentProbe, line)
			continue
		}

		// 解析稀有度
		if strings.HasPrefix(line, "rarity ") {
			parseRarityValue(currentProbe, line)
			continue
		}

		// 解析回退探针
		if strings.HasPrefix(line, "fallback ") {
			parseFallbackProbe(currentProbe, line)
			continue
		}

		// 解析匹配规则
		if strings.HasPrefix(line, "match ") || strings.HasPrefix(line, "softmatch ") {
			parseMatchRule(currentProbe, line, lineNum)
			continue
		}
	}

	// add last probe
	if currentProbe != nil {
		probes = append(probes, currentProbe)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("解析探针文件错误: %v", err)
	}

	return probes, nil
}

// parseProbeDefinition 解析探针定义行
func parseProbeDefinition(line string) *Probe {
	// 示例: Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		gologger.Warning().Msgf("无效的探针定义: %s", line)
		return nil
	}

	protocol := strings.ToLower(parts[1])
	name := parts[2]

	probe := &Probe{
		Name:       name,
		Protocol:   protocol,
		MatchGroup: make([]*Match, 0),
	}

	// 解析探针数据
	probeData := parts[3]
	if len(probeData) > 0 && probeData[0] == 'q' && probeData[1] == '|' {
		end := strings.LastIndex(probeData[2:], "|")
		if end == -1 {
			gologger.Warning().Msgf("无效的探针数据格式: %s", line)
			return nil
		}
		probe.SendData = []byte(parseEscapedString(probeData[2 : end+2]))
	}

	return probe
}

// parsePortsDefinition 解析端口定义
func parsePortsDefinition(probe *Probe, line string, isSSL bool) {
	if probe == nil {
		return
	}

	// 示例: ports 80,443,8080-8090 或 sslports 443,8443
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	ports := parsePortsList(parts[1])
	if isSSL {
		probe.SSLPorts = ports
	} else {
		probe.Ports = ports
	}
}

// parseTotalWaitMS 解析总等待时间
func parseTotalWaitMS(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: totalwaitms 6000
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	ms, err := strconv.Atoi(parts[1])
	if err != nil {
		gologger.Warning().Msgf("无效的等待时间值: %s", parts[1])
		return
	}

	probe.TotalWaitMS = time.Duration(ms) * time.Millisecond
}

// parseTCPWrappedMS 解析TCP包装等待时间
func parseTCPWrappedMS(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: tcpwrappedms 3000
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	ms, err := strconv.Atoi(parts[1])
	if err != nil {
		gologger.Warning().Msgf("无效的TCP包装等待时间值: %s", parts[1])
		return
	}

	probe.TCPWrappedMS = time.Duration(ms) * time.Millisecond
}

// parseRarityValue 解析稀有度
func parseRarityValue(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: rarity 5
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	rarity, err := strconv.Atoi(parts[1])
	if err != nil {
		gologger.Warning().Msgf("无效的稀有度值: %s", parts[1])
		return
	}

	probe.Rarity = rarity
}

// parseFallbackProbe 解析回退探针
func parseFallbackProbe(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: fallback GetRequest2
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	probe.Fallback = append(probe.Fallback, parts[1])
}

// parseMatchRule 解析匹配规则
func parseMatchRule(probe *Probe, line string, lineIndex int) {
	if probe == nil {
		return
	}

	// 判断是否为软匹配
	soft := strings.HasPrefix(line, "softmatch")

	// 示例: match http m|^HTTP/1\.[01] \d\d\d|
	// 或: softmatch http m|^HTTP/1\.[01] \d\d\d|
	var parts []string
	if soft {
		parts = strings.SplitN(line, " ", 3)
	} else {
		parts = strings.SplitN(line, " ", 3)
	}

	if len(parts) < 3 {
		gologger.Warning().Msgf("无效的匹配规则格式: %s", line)
		return
	}

	// 获取服务名称
	serviceName := parts[1]

	// 解析匹配模式
	patternPart := parts[2]
	patternType := ""
	var pattern string

	// 检查模式前缀：m|（普通匹配）、i|（不区分大小写）、s|（单行模式）
	if strings.HasPrefix(patternPart, "m|") || strings.HasPrefix(patternPart, "i|") || strings.HasPrefix(patternPart, "s|") {
		patternType = patternPart[0:1]
		mStart := 1
		if patternPart[mStart] != '|' {
			gologger.Warning().Msgf("无效的模式格式: %s", patternPart)
			return
		}

		// 寻找模式结束的分隔符
		// 模式部分应该是第一个 '|' 和第二个 '|' 之间的内容
		// 而不是整行中的最后一个 '|'
		patternStr := patternPart[mStart+1:]
		end := strings.Index(patternStr, "|")
		if end == -1 {
			gologger.Warning().Msgf("无效的模式格式，缺少结束分隔符: %s", patternPart)
			return
		}
		pattern = patternStr[:end]
	} else {
		gologger.Warning().Msgf("不支持的模式类型: %s", patternPart)
		return
	}
	decodePattern := parseRegexPattern(pattern)
	match := &Match{
		Line:    lineIndex,
		Soft:    soft,
		Service: FixProtocol(serviceName),
		Pattern: []byte(decodePattern),
	}
	// 编译正则表达式
	var err error
	match.regex, err = getPatternRegexp(decodePattern, patternType)
	if err != nil {
		gologger.Warning().Msgf("编译正则表达式失败: %s - %v", pattern, err)
		return
	}

	// 解析版本信息
	match.VersionInfo = parseVersionInfo(line)

	// 添加到当前探针的匹配组
	probe.MatchGroup = append(probe.MatchGroup, match)
}

// parseVersionInfo 解析版本信息
func parseVersionInfo(line string) *VersionInfo {
	info := &VersionInfo{}

	// 提取版本信息字段
	// 示例: p/Apache httpd/ v/$1/ i/Debian/ o/Linux/ cpe:/a:apache:http_server:$1/
	versionPart := line
	vIndex := strings.Index(line, " p/")
	if vIndex != -1 {
		versionPart = line[vIndex+1:]
	} else {
		return info
	}

	// 解析产品名称
	pMatch := regexp.MustCompile(`p/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(pMatch) > 1 {
		info.ProductName = pMatch[1]
	}

	// 解析版本
	vMatch := regexp.MustCompile(`v/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(vMatch) > 1 {
		info.Version = vMatch[1]
	}

	// 解析信息
	iMatch := regexp.MustCompile(`i/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(iMatch) > 1 {
		info.Info = iMatch[1]
	}

	// 解析操作系统
	oMatch := regexp.MustCompile(`o/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(oMatch) > 1 {
		info.OS = oMatch[1]
	}

	// 解析主机名
	hMatch := regexp.MustCompile(`h/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(hMatch) > 1 {
		info.Hostname = hMatch[1]
	}

	// 解析设备类型
	dMatch := regexp.MustCompile(`d/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(dMatch) > 1 {
		info.DeviceType = dMatch[1]
	}

	return info
}

// parsePortsList 解析端口列表
func parsePortsList(portsStr string) []int {
	var ports []int

	// 分割端口列表
	portParts := strings.Split(portsStr, ",")
	for _, part := range portParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否为端口范围
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0])
				end, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && start <= end {
					for port := start; port <= end; port++ {
						ports = append(ports, port)
					}
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err == nil {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// parseEscapedString 解析转义字符串
func parseEscapedString(s string) string {
	var result strings.Builder
	i := 0

	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			// 处理转义序列
			i++
			switch s[i] {
			case 'r':
				result.WriteByte('\r')
			case 'n':
				result.WriteByte('\n')
			case 't':
				result.WriteByte('\t')
			case '\\':
				result.WriteByte('\\')
			case '0':
				// 处理 \0 转义序列 (空字节)
				result.WriteByte(0)
			case 'x':
				// 十六进制转义序列 \xHH
				if i+2 < len(s) {
					hexStr := s[i+1 : i+3]
					val, err := strconv.ParseUint(hexStr, 16, 8)
					if err == nil {
						result.WriteByte(byte(val))
						i += 2 // 跳过已处理的两位十六进制数字
					} else {
						// 如果解析失败，保留原字符
						result.WriteByte('x')
					}
				} else {
					// 不完整的十六进制序列，保留原字符
					result.WriteByte('x')
				}
			default:
				// 对于其他转义序列，保留原始的反斜杠和字符
				// 这样可以保留 \d, \w 等正则表达式特殊序列
				result.WriteByte('\\')
				result.WriteByte(s[i])
			}
		} else {
			// 普通字符
			result.WriteByte(s[i])
		}
		i++
	}

	return result.String()
}

// parseRegexPattern 解析正则表达式模式
func parseRegexPattern(pattern string) string {
	// 首先对Regex 中的特殊字符进行转义
	pattern = strings.ReplaceAll(pattern, "\\x7c", "\\\\|")
	return parseEscapedString(pattern)
}
