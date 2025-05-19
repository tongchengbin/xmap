package probe

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Manager 负责管理指纹库
type Manager struct {
	// 指纹库存储
	probeStore *ProbeStore
	// 加载锁，确保并发安全
	loadMutex sync.RWMutex
	// 配置选项
	options *FingerprintOptions
	// 错误信息
	lastError error
	// 最后加载时间
	lastLoadTime time.Time
}

var (
	// 确保线程安全的初始化
	managerMutex sync.Mutex
	// 管理器实例映射，用于存储不同配置的管理器实例
	managerInstances = make(map[string]*Manager)
)

// 生成配置的唯一键
func generateConfigKey(options *FingerprintOptions) string {
	return fmt.Sprintf("%s:%d", options.ProbeFilePath, options.VersionIntensity)
}

// GetDefaultProbeFilePath 获取默认的探针文件路径
func GetDefaultProbeFilePath() string {
	// 首先尝试从环境变量获取
	if path := os.Getenv("NMAP_PROBE_FILE"); path != "" {
		return path
	}
	// home 目录
	homeDir, _ := os.UserHomeDir()
	// 然后尝试常见的位置
	commonPaths := []string{
		"nmap-service-probes",
		homeDir + "/nmap-service-probes",
	}
	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// 如果都找不到，返回空字符串，将使用内嵌的默认探针数据
	return ""
}

// GetManager 根据选项获取指纹管理器
func GetManager(options *FingerprintOptions) (*Manager, error) {
	if options == nil {
		options = &FingerprintOptions{
			ProbeFilePath:    GetDefaultProbeFilePath(),
			VersionIntensity: 7,
		}
	}
	// 标准化选项
	if options.VersionIntensity < 0 {
		options.VersionIntensity = 7
	}
	// 生成配置键
	configKey := generateConfigKey(options)

	// 获取锁，确保并发安全
	managerMutex.Lock()
	defer managerMutex.Unlock()
	
	// 检查是否已存在实例
	manager, exists := managerInstances[configKey]
	if exists {
		return manager, nil
	}
	
	// 创建新实例
	manager = &Manager{
		options:    options,
		probeStore: NewProbeStore(),
	}
	
	// 加载指纹库
	err := manager.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load probe data: %w", err)
	}
	
	// 存储实例
	managerInstances[configKey] = manager
	return manager, nil
}

// updateOptions 更新指纹管理器选项
func (fm *Manager) updateOptions(options *FingerprintOptions) {
	if options == nil {
		return
	}

	// 更新版本强度
	if options.VersionIntensity > 0 {
		fm.options.VersionIntensity = options.VersionIntensity
	}
	// 更新探针文件路径
	if options.ProbeFilePath != "" {
		fm.options.ProbeFilePath = options.ProbeFilePath
	}
}

// Load 加载指纹库
func (fm *Manager) Load() error {
	// 获取写锁，确保并发安全
	fm.loadMutex.Lock()
	defer fm.loadMutex.Unlock()

	// 创建探针源
	var source ProbeSource
	if fm.options.ProbeFilePath != "" {
		source = &FileProbeSource{
			FilePath: fm.options.ProbeFilePath,
		}
	} else {
		// 使用内嵌的默认探针数据
		source = &EmbeddedProbeSource{
			Data:    defaultProbes,
			Version: "embedded",
		}
	}

	// 加载探针数据
	probeData, err := source.Load()
	if err != nil {
		fm.lastError = err
		gologger.Error().Msgf("Failed to load probe data: %v", err)
		return err
	}

	// 使用内部实现的 LoadProbes 函数加载探针
	probes := LoadProbes(probeData, fm.options.VersionIntensity)
	if len(probes) == 0 {
		fm.lastError = errors.New("no probes loaded")
		gologger.Error().Msg("No probes loaded")
		return fm.lastError
	}

	// 创建新的探针存储
	newProbeStore := NewProbeStore()

	// 添加探针到存储
	for _, probe := range probes {
		newProbeStore.AddProbe(probe)
	}

	// 设置回退探针
	newProbeStore.SetFallbackProbes()

	// 更新探针存储
	fm.probeStore = newProbeStore
	fm.lastLoadTime = time.Now()

	gologger.Debug().Msgf("Loaded %d TCP probes and %d UDP probes",
		len(fm.probeStore.TCPProbes), len(fm.probeStore.UDPProbes))

	return nil
}

// GetLastError 获取最后一次错误
func (fm *Manager) GetLastError() error {
	fm.loadMutex.RLock()
	defer fm.loadMutex.RUnlock()
	return fm.lastError
}

// GetProbeStore 获取探针存储
func (fm *Manager) GetProbeStore() *ProbeStore {
	fm.loadMutex.RLock()
	defer fm.loadMutex.RUnlock()
	return fm.probeStore
}

// GetTCPProbes 获取TCP探针列表
func (fm *Manager) GetTCPProbes() []*Probe {
	store := fm.GetProbeStore()
	if store == nil {
		return nil
	}
	return store.GetTCPProbes()
}

// GetUDPProbes 获取UDP探针列表
func (fm *Manager) GetUDPProbes() []*Probe {
	store := fm.GetProbeStore()
	if store == nil {
		return nil
	}
	return store.GetUDPProbes()
}

// GetProbeByName 根据名称获取探针
func (fm *Manager) GetProbeByName(name string) *Probe {
	store := fm.GetProbeStore()
	if store == nil {
		return nil
	}
	return store.GetProbeByName(name)
}

// GetProbesByVersionIntensity 根据版本强度级别获取探针组
func (fm *Manager) GetProbesByVersionIntensity(intensity int) ([]*Probe, []*Probe) {
	store := fm.GetProbeStore()
	if store == nil {
		return nil, nil
	}

	// 获取所有探针
	tcpProbes := store.GetTCPProbes()
	udpProbes := store.GetUDPProbes()

	// 按版本强度过滤
	var filteredTCPProbes, filteredUDPProbes []*Probe

	// 过滤 TCP 探针
	for _, probe := range tcpProbes {
		if probe.Rarity <= intensity {
			filteredTCPProbes = append(filteredTCPProbes, probe)
		}
	}

	// 过滤 UDP 探针
	for _, probe := range udpProbes {
		if probe.Rarity <= intensity {
			filteredUDPProbes = append(filteredUDPProbes, probe)
		}
	}

	return filteredTCPProbes, filteredUDPProbes
}

// ForceReload 强制重新加载所有指纹管理器
func ForceReload() error {
	managerMutex.Lock()
	defer managerMutex.Unlock()

	var lastErr error
	for _, manager := range managerInstances {
		if err := manager.Load(); err != nil {
			lastErr = err
			gologger.Error().Msgf("重新加载指纹管理器失败: %v", err)
		}
	}
	return lastErr
}

// Load 从文件加载探针数据
func (s *FileProbeSource) Load() (string, error) {
	data, err := os.ReadFile(s.FilePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetVersion 获取探针数据版本
func (s *FileProbeSource) GetVersion() string {
	info, err := os.Stat(s.FilePath)
	if err != nil {
		return "unknown"
	}
	return info.ModTime().Format(time.RFC3339)
}

//go:embed nmap-service-probes
var defaultProbes string
