package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/xmap/pkg/types"
)

// ParsePorts 解析端口字符串为端口数组
func ParsePorts(portsStr string) []int {
	if portsStr == "" {
		return []int{80} // 默认端口
	}

	portStrs := strings.Split(portsStr, ",")
	ports := make([]int, 0, len(portStrs))

	for _, portStr := range portStrs {
		// 处理端口范围 (例如 8080-8090)
		if strings.Contains(portStr, "-") {
			rangeParts := strings.Split(portStr, "-")
			if len(rangeParts) != 2 {
				continue
			}

			var startPort, endPort int
			_, err1 := fmt.Sscanf(rangeParts[0], "%d", &startPort)
			_, err2 := fmt.Sscanf(rangeParts[1], "%d", &endPort)

			if err1 != nil || err2 != nil || startPort > endPort {
				continue
			}

			for port := startPort; port <= endPort; port++ {
				if port > 0 && port < 65536 {
					ports = append(ports, port)
				}
			}
			continue
		}

		// 处理单个端口
		var port int
		_, err := fmt.Sscanf(portStr, "%d", &port)
		if err != nil {
			continue
		}
		if port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}

	if len(ports) == 0 {
		return []int{80} // 默认端口
	}

	return ports
}

// ParseIPPort 解析IP和端口
func ParseIPPort(target string) (string, int, error) {
	// 检查是否包含端口
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) != 2 {
			return "", 0, fmt.Errorf("无效的目标格式: %s", target)
		}

		ip := parts[0]
		var port int
		_, err := fmt.Sscanf(parts[1], "%d", &port)
		if err != nil || port <= 0 || port >= 65536 {
			return "", 0, fmt.Errorf("无效的端口: %s", parts[1])
		}

		return ip, port, nil
	}

	// 没有端口，只返回IP
	return target, 0, nil
}

// ParseTargetString 解析目标字符串
func ParseTargetString(targetStr string, ports []int) []*types.ScanTarget {
	targets := make([]*types.ScanTarget, 0)

	// 处理多个目标，以逗号分隔
	targetStrs := strings.Split(targetStr, ",")
	for _, target := range targetStrs {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// 解析IP和端口
		ip, port, err := ParseIPPort(target)
		if err != nil {
			gologger.Warning().Msgf("解析目标失败: %v", err)
			continue
		}

		// 如果指定了端口，只使用该端口
		if port > 0 {
			targets = append(targets, &types.ScanTarget{
				IP:       ip,
				Port:     port,
				Protocol: "tcp",
			})
		} else {
			// 否则使用所有指定的端口
			for _, p := range ports {
				targets = append(targets, &types.ScanTarget{
					IP:       ip,
					Port:     p,
					Protocol: "tcp",
				})
			}
		}
	}

	return targets
}

// ParseTargetFile 从文件解析目标
func ParseTargetFile(filename string, ports []int) ([]*types.ScanTarget, error) {
	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取目标文件失败: %v", err)
	}

	// 解析每一行
	lines := strings.Split(string(data), "\n")
	targets := make([]*types.ScanTarget, 0, len(lines)*len(ports))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 将每一行作为目标字符串解析
		lineTargets := ParseTargetString(line, ports)
		targets = append(targets, lineTargets...)
	}

	return targets, nil
}

// ParseTargets 解析所有目标
func ParseTargets(targetStrs []string, targetFile string, ports []int) ([]*types.ScanTarget, error) {
	targets := make([]*types.ScanTarget, 0)

	// 从命令行参数解析目标
	if len(targetStrs) > 0 {
		for _, target := range targetStrs {
			parsedTargets := ParseTargetString(target, ports)
			targets = append(targets, parsedTargets...)
		}
	}

	// 从文件解析目标
	if targetFile != "" {
		fileTargets, err := ParseTargetFile(targetFile, ports)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	return targets, nil
}
