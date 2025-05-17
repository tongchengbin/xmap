package probe

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/dlclark/regexp2"
)

var CPULimit sizedwaitgroup.SizedWaitGroup

// Probe 表示一个服务探针
type Probe struct {
	// 探针名称
	Name string
	// 探针适用的默认端口
	Ports []int
	// 探针适用的SSL端口
	SSLPorts []int
	// 探针总等待时间
	TotalWaitMS time.Duration
	// TCP包装等待时间
	TCPWrappedMS time.Duration
	// 探针稀有度
	Rarity int
	// 探针协议类型
	Protocol Protocol
	// 探针发送数据
	SendData []byte
	// 匹配组
	MatchGroup []*Match
	// 回退探针名称
	Fallback []string
	// 回退探针引用
	FallbackProbes []*Probe
}

// Match 表示匹配规则
type Match struct {
	// 是否为软匹配
	Soft bool
	// 服务名称
	Service string
	// 匹配模式
	Pattern string
	// 编译好的正则表达式
	regex *regexp2.Regexp
	// 版本信息
	VersionInfo *VersionInfo
	// 行号
	Line int
}

// HasPort 检查探针是否适用于指定端口
func (p *Probe) HasPort(port int) bool {
	for _, p := range p.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// HasSSLPort 检查探针是否适用于指定SSL端口
func (p *Probe) HasSSLPort(port int) bool {
	for _, p := range p.SSLPorts {
		if p == port {
			return true
		}
	}
	return false
}

func (p *Probe) Match(response []byte) (*Match, map[string]interface{}) {
	if &CPULimit != nil {
		CPULimit.Add()
		defer CPULimit.Done()
	}
	for _, m := range p.MatchGroup {
		matcher, err := m.regex.FindStringMatch(string(response))
		if err != nil {
			continue
		}
		if matcher == nil {
			continue
		}
		if len(matcher.Groups()) == 0 {
			continue
		}
		var groups = map[string]string{}
		if len(matcher.Groups()) > 1 {
			for index, group := range matcher.Groups() {
				groups[fmt.Sprintf("$%d", index)] = group.String()
			}
		}
		extra := map[string]interface{}{}
		if m.VersionInfo.Version != "" {
			extra["version"] = groups[m.VersionInfo.Version]
		}
		if m.VersionInfo.ProductName != "" {
			extra["product"] = m.VersionInfo.ProductName
		}
		if m.VersionInfo.OS != "" {
			extra["os"] = m.VersionInfo.OS
		}
		// replace extra with groups
		for k, v := range extra {
			// 需要类型断言将v转换为string
			vStr, ok := v.(string)
			if !ok {
				// 如果不是字符串，继续下一个
				continue
			}

			if strings.Contains(vStr, "$") {
				// 提取所有的$N引用
				varPattern := regexp.MustCompile(`\$(\d+|[a-zA-Z][a-zA-Z0-9_]*)`)
				// 替换所有的$N引用为相应的组值
				replacedValue := varPattern.ReplaceAllStringFunc(vStr, func(match string) string {
					groupKey := match[1:] // 去掉$前缀
					// 如果是数字，尝试使用索引获取
					if groupIndex, err := strconv.Atoi(groupKey); err == nil && groupIndex < len(matcher.Groups()) {
						group := matcher.Groups()[groupIndex]
						// 检查group是否为空指针和长度
						if group.Length > 0 {
							return group.String()
						}
						return ""
					}
					// 否则使用命名组
					if groupValue, ok := groups[groupKey]; ok {
						return groupValue
					}
					return "" // 如果没有找到对应的组，返回空字符串
				})
				extra[k] = replacedValue
			}
		}
		return m, extra
	}
	return nil, nil
}

// ProbeStore 存储和管理探针数据
// noinspection GoNameStartsWithPackageName
type ProbeStore struct {
	// 按名称索引的探针映射
	ProbesByName map[string]*Probe
	// TCP探针列表
	TCPProbes []*Probe
	// UDP探针列表
	UDPProbes []*Probe
}

// NewProbeStore 创建新的探针存储
func NewProbeStore() *ProbeStore {
	return &ProbeStore{
		ProbesByName: make(map[string]*Probe),
		TCPProbes:    make([]*Probe, 0),
		UDPProbes:    make([]*Probe, 0),
	}
}

// LoadProbes 从探针数据字符串加载探针列表
func LoadProbes(s string, versionIntensity int) []*Probe {
	scanner := bufio.NewScanner(strings.NewReader(s))
	var pb = &Probe{
		MatchGroup: make([]*Match, 0),
	}
	var probeList = make([]*Probe, 0)
	lineIndex := 1

	for scanner.Scan() {
		line := scanner.Text()
		if !isCommand(line) {
			lineIndex++
			continue
		}
		var err error
		if strings.HasPrefix(line, "Probe ") {
			if len(pb.MatchGroup) > 0 {
				if pb.Rarity <= versionIntensity || versionIntensity == 9 {
					probeList = append(probeList, pb)
				}
				pb = &Probe{
					MatchGroup: make([]*Match, 0),
				}
			}
			// 解析探针行
			parseProbe(pb, line)
		} else if strings.HasPrefix(line, "match ") {
			// 解析匹配行
			err = parseMatch(pb, line[len("match "):], false, lineIndex)
		} else if strings.HasPrefix(line, "softmatch ") {
			// 解析软匹配行
			err = parseMatch(pb, line[len("softmatch "):], true, lineIndex)
		} else if strings.HasPrefix(line, "ports ") {
			// 解析端口行
			parsePorts(pb, line, false)
		} else if strings.HasPrefix(line, "sslports ") {
			// 解析SSL端口行
			parsePorts(pb, line, true)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			// 解析总等待时间
			pb.TotalWaitMS = time.Duration(parseInteger(line[12:])) * time.Millisecond
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			// 解析TCP包装等待时间
			pb.TCPWrappedMS = time.Duration(parseInteger(line[13:])) * time.Millisecond
		} else if strings.HasPrefix(line, "rarity ") {
			// 解析稀有度
			pb.Rarity = parseInteger(line[7:])
		} else if strings.HasPrefix(line, "fallback ") {
			// 解析回退探针
			pb.Fallback = parseStringList(line[9:])
		}
		if err != nil {
			gologger.Debug().Msgf("parser probe line %d error: %v", lineIndex, err)
		}
		lineIndex++
	}

	if len(pb.MatchGroup) > 0 {
		probeList = append(probeList, pb)
	}

	// 设置回退探针引用
	setFallbackProbes(probeList)

	return probeList
}

// 判断一行是否是命令行
func isCommand(line string) bool {
	if line == "" || line[0] == '#' {
		return false
	}
	return true
}

// 解析探针行
func parseProbe(p *Probe, line string) {
	// 示例: Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return
	}

	p.Protocol = Protocol(parts[1])
	p.Name = parts[2]

	// 解析探针数据
	if strings.HasPrefix(parts[3], "q|") {
		endIndex := strings.Index(parts[3][2:], "|")
		if endIndex != -1 {
			probeData := parts[3][2 : 2+endIndex]
			p.SendData = []byte(parseEscapedString(probeData))
		}
	}
}

// 解析匹配行
func parseMatch(p *Probe, line string, soft bool, lineIndex int) error {
	match := &Match{
		Line:        lineIndex,
		VersionInfo: &VersionInfo{},
	}
	// 查找第一个空格前的字符串
	index := strings.Index(line, " ")
	match.Service = line[:index]
	s := strings.Trim(line[index+1:], " ")
	// 查找匹配的正则
	if s[:1] != "m" {
		return errors.New("match line must start with m: " + s)
	}
	var mf = s[1:2]
	var mStart = 2
	// 找到结束符
	var end = strings.Index(s[mStart:], mf)
	var pattern = s[mStart : mStart+end]
	// 判断是否有选项
	var patternOpt string
	if len(s) > (mStart+end+2) && s[mStart+end+1:mStart+end+2] != " " {
		patternOpt = s[mStart+end+1 : mStart+end+2]
	} else {
		patternOpt = ""
	}
	s = s[mStart+end+len(patternOpt):]
	match.Soft = soft
	match.Service = FixProtocol(match.Service)
	fixPattern := FixPattern(pattern)
	match.Pattern = fixPattern
	var err error
	match.regex, err = getPatternRegexp(fixPattern, patternOpt)
	if err != nil {
		return errors.New("regex compile error: " + pattern + " " + err.Error())
	}
	// 解析版本信息
	if len(s) > 1 {
		match.VersionInfo = parseVersionInfo(s)
	}
	p.MatchGroup = append(p.MatchGroup, match)
	return nil
}

// 解析端口行
func parsePorts(p *Probe, line string, ssl bool) {
	var prefix string
	if ssl {
		prefix = "sslports "
	} else {
		prefix = "ports "
	}

	portsStr := line[len(prefix):]
	ports := parsePortList(portsStr)

	if ssl {
		p.SSLPorts = ports
	} else {
		p.Ports = ports
	}
}

// 解析端口列表
func parsePortList(expr string) []int {
	var result []int
	parts := strings.Split(expr, ",")

	for _, part := range parts {
		rangeParts := strings.Split(part, "-")
		if len(rangeParts) == 1 {
			// 单个端口
			port := parseInteger(rangeParts[0])
			if port > 0 {
				result = append(result, port)
			}
		} else if len(rangeParts) == 2 {
			// 端口范围
			start := parseInteger(rangeParts[0])
			end := parseInteger(rangeParts[1])
			if start > 0 && end >= start {
				for i := start; i <= end; i++ {
					result = append(result, i)
				}
			}
		}
	}

	return removeDuplicatePorts(result)
}

// 移除重复端口
func removeDuplicatePorts(ports []int) []int {
	seen := make(map[int]struct{})
	var result []int

	for _, port := range ports {
		if _, exists := seen[port]; !exists {
			seen[port] = struct{}{}
			result = append(result, port)
		}
	}

	return result
}

// 解析整数
func parseInteger(s string) int {
	val, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return val
}

// 解析字符串列表
func parseStringList(s string) []string {
	var result []string
	parts := strings.Split(s, ",")

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// 解析转义字符串
func parseEscapedString(s string) string {
	// 处理常见的转义序列
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\\`, "\\")
	s = strings.ReplaceAll(s, `\"`, "\"")
	s = strings.ReplaceAll(s, `\0`, string(byte(0)))

	// 处理十六进制转义序列 \xHH
	re := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	s = re.ReplaceAllStringFunc(s, func(match string) string {
		hexVal := match[2:]
		val, err := strconv.ParseUint(hexVal, 16, 8)
		if err != nil {
			return match
		}
		return string(byte(val))
	})

	return s
}

// 解析版本信息
func parseVersionInfo(s string) *VersionInfo {
	vi := &VersionInfo{}
	parts := strings.Split(s, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "p/") {
			// 移除末尾的斜杠
			value := part[2:]
			if strings.HasSuffix(value, "/") {
				value = value[:len(value)-1]
			}
			vi.ProductName = value
		} else if strings.HasPrefix(part, "v/") {
			// 移除末尾的斜杠
			value := part[2:]
			if strings.HasSuffix(value, "/") {
				value = value[:len(value)-1]
			}
			vi.Version = value
		} else if strings.HasPrefix(part, "i/") {
			// 移除末尾的斜杠
			value := part[2:]
			if strings.HasSuffix(value, "/") {
				value = value[:len(value)-1]
			}
			vi.Info = value
		} else if strings.HasPrefix(part, "h/") {
			// 移除末尾的斜杠
			value := part[2:]
			if strings.HasSuffix(value, "/") {
				value = value[:len(value)-1]
			}
			vi.Hostname = value
		} else if strings.HasPrefix(part, "o/") {
			// 移除末尾的斜杠
			value := part[2:]
			if strings.HasSuffix(value, "/") {
				value = value[:len(value)-1]
			}
			vi.OS = value
		} else if strings.HasPrefix(part, "d/") {
			// 移除末尾的斜杠
			value := part[2:]
			if strings.HasSuffix(value, "/") {
				value = value[:len(value)-1]
			}
			vi.DeviceType = value
		}
	}
	return vi
}

// 设置回退探针引用
func setFallbackProbes(probes []*Probe) {
	// 创建探针名称到探针的映射
	probeMap := make(map[string]*Probe)
	for _, p := range probes {
		probeMap[p.Name] = p
	}

	// 设置回退探针引用
	for _, p := range probes {
		for _, fallbackName := range p.Fallback {
			if fallbackProbe, ok := probeMap[fallbackName]; ok {
				p.FallbackProbes = append(p.FallbackProbes, fallbackProbe)
			}
		}
	}
}

// GetTCPProbes 获取TCP探针列表
func (ps *ProbeStore) GetTCPProbes() []*Probe {
	return ps.TCPProbes
}

// GetUDPProbes 获取UDP探针列表
func (ps *ProbeStore) GetUDPProbes() []*Probe {
	return ps.UDPProbes
}

// GetAllProbes 获取所有探针列表
func (ps *ProbeStore) GetAllProbes() []*Probe {
	// 合并 TCP 和 UDP 探针
	allProbes := make([]*Probe, 0, len(ps.TCPProbes)+len(ps.UDPProbes))
	allProbes = append(allProbes, ps.TCPProbes...)
	allProbes = append(allProbes, ps.UDPProbes...)
	return allProbes
}

// GetProbeByName 根据名称获取探针
func (ps *ProbeStore) GetProbeByName(name string) *Probe {
	return ps.ProbesByName[name]
}

// AddProbe 添加探针到存储
func (ps *ProbeStore) AddProbe(probe *Probe) {
	ps.ProbesByName[probe.Name] = probe
	if probe.Protocol == "TCP" {
		ps.TCPProbes = append(ps.TCPProbes, probe)
	} else if probe.Protocol == "UDP" {
		ps.UDPProbes = append(ps.UDPProbes, probe)
	} else {
		log.Printf("Unsupported protocol: %s", probe.Protocol)
	}
}

// SetFallbackProbes 设置回退探针引用
func (ps *ProbeStore) SetFallbackProbes() {
	for _, probe := range ps.ProbesByName {
		for _, fallbackName := range probe.Fallback {
			if fallbackProbe, ok := ps.ProbesByName[fallbackName]; ok {
				probe.FallbackProbes = append(probe.FallbackProbes, fallbackProbe)
			}
		}
	}
}

// BytesToHex converts bytes to string, showing printable ASCII characters as-is
// and other bytes in \x hex format
func BytesToHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var buf strings.Builder
	for _, v := range b {
		if v >= 0x20 && v <= 0x7E { // printable ASCII range
			buf.WriteByte(v)
		} else {
			buf.WriteString(fmt.Sprintf("\\x%02x", v))
		}
	}
	return buf.String()
}
func FixPattern(s string) string {
	// 处理十六进制转义序列 \xHH
	hexPattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	s = hexPattern.ReplaceAllStringFunc(s, func(match string) string {
		hexStr := match[2:] // 获取十六进制部分
		val, _ := strconv.ParseUint(hexStr, 16, 8)
		si := string([]byte{byte(val)})
		// 对特殊字符进行转义
		switch si {
		case "|":
			return "\\|"
		case "$":
			return "\\$"
		case ".":
			return "\\."
		case "*":
			return "\\*"
		case "+":
			return "\\+"
		case "?":
			return "\\?"
		case "[":
			return "\\["
		case "]":
			return "\\]"
		case "(":
			return "\\("
		case ")":
			return "\\)"
		case "{":
			return "\\{"
		case "}":
			return "\\}"
		case "^":
			return "\\^"
		default:
			return si
		}
	})
	// 处理八进制转义序列 \0
	s = strings.ReplaceAll(s, "\\0", "\x00")
	// 处理其他常见转义序列
	s = strings.ReplaceAll(s, "\\t", "\t")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\n", "\n")
	// 最后处理反斜杠本身的转义，避免影响前面的替换
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}
