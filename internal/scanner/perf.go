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
	var probesSorts []*probe.Probe
	var others []*probe.Probe
	for _, pb := range probes {
		if (pb.HasPort(port) && !ssl) || (pb.HasSSLPort(port) && ssl) {
			probesSorts = append(probesSorts, pb)
			continue
		}
		others = append(others, pb)
	}
	probesSorts = append(probesSorts, others...)
	return probesSorts
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
