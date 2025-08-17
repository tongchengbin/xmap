package scanner

import "github.com/tongchengbin/xmap/pkg/probe"

var PortRequest = map[int]string{
	80:    "GetRequest",
	110:   "NULL",
	443:   "GetRequest",
	445:   "SMBProgNeg",
	554:   "RTSPRequest",
	25:    "NULL",
	22:    "NULL",
	587:   "NULL",
	3389:  "TerminalServerCookie",
	6379:  "GetRequest",
	8008:  "GetRequest",
	8080:  "GetRequest",
	61616: "NULL",
}

func HasPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func sortProbes(probes []*probe.Probe, port int, ssl bool) []*probe.Probe {
	// 根据端口信息返回检测序列包
	/*
		总共的探针不超过100 所以这里直接遍历 不需要考虑性能
	*/

	// 1. 首先检查是否有端口特定的首选探针
	if pn, ok := PortRequest[port]; ok && pn != "" {
		// 如果有首选探针，将其放在最前面
		var preferredProbe *probe.Probe
		for _, pb := range probes {
			if pb.Name == pn {
				preferredProbe = pb
				break
			}
		}

		if preferredProbe != nil {
			// 创建一个新的探针列表，将首选探针放在最前面
			result := []*probe.Probe{preferredProbe}
			for _, pb := range probes {
				if pb != preferredProbe {
					result = append(result, pb)
				}
			}
			probes = result
		}
	}

	// 2. 按端口匹配和稀有度排序
	var portSpecificProbes []*probe.Probe
	var fallbackProbes []*probe.Probe
	var otherProbes []*probe.Probe

	for _, pb := range probes {
		// 检查是否是端口特定的探针
		if (pb.HasPort(port) && !ssl) || (pb.HasSSLPort(port) && ssl) {
			portSpecificProbes = append(portSpecificProbes, pb)
		} else if len(pb.Fallback) > 0 {
			// 如果探针有fallback机制，优先级等级高于其他探针
			fallbackProbes = append(fallbackProbes, pb)
		} else {
			otherProbes = append(otherProbes, pb)
		}
	}

	// 3. 按稀有度排序端口特定的探针
	sortProbesByRarity(portSpecificProbes)

	// 4. 按稀有度排序回退探针
	sortProbesByRarity(fallbackProbes)

	// 5. 按稀有度排序其他探针
	sortProbesByRarity(otherProbes)

	// 6. 合并所有探针列表
	result := append(portSpecificProbes, fallbackProbes...)
	result = append(result, otherProbes...)

	return result
}

// sortProbesByRarity 按探针的稀有度对探针进行排序
// 稀有度越低，优先级越高
func sortProbesByRarity(probes []*probe.Probe) {
	// 使用冒泡排序按稀有度排序
	for i := 0; i < len(probes)-1; i++ {
		for j := 0; j < len(probes)-i-1; j++ {
			// 稀有度越低，优先级越高
			if probes[j].Rarity > probes[j+1].Rarity {
				probes[j], probes[j+1] = probes[j+1], probes[j]
			}
		}
	}
}

func perfSort(port int, ps []*probe.Probe) []*probe.Probe {
	if pn, ok := PortRequest[port]; ok {
		for i, pb := range ps {
			if pb.Name == pn {
				return append([]*probe.Probe{pb}, append(ps[:i], ps[i+1:]...)...)
			}
		}
	}
	return ps
}
