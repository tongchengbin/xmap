package api

import (
	"github.com/tongchengbin/xmap/pkg/probe"
)

// ReloadServiceFingerprints 重新加载服务指纹库
func ReloadServiceFingerprints() error {
	return probe.ForceReload()
}

// GetServiceFingerprintManager 获取服务指纹管理器
func GetServiceFingerprintManager(options *probe.FingerprintOptions) (*probe.Manager, error) {
	return probe.GetManager(options)
}
