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
	// DefaultProbeManager 默认的探针管理器
	DefaultProbeManager *Manager
)

// NewManager 创建新的指纹管理器
func NewManager(options *FingerprintOptions) (*Manager, error) {
	if options == nil {
		options = &FingerprintOptions{
			ProbeFilePath:    getDefaultProbeFilePath(),
			VersionIntensity: 7,
		}
	} else if options.ProbeFilePath == "" {
		options.ProbeFilePath = getDefaultProbeFilePath()
	}

	manager := &Manager{
		options:    options,
		probeStore: NewProbeStore(),
	}

	err := manager.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load probe data: %w", err)
	}
	return manager, nil
}

// getDefaultProbeFilePath 获取默认的探针文件路径
func getDefaultProbeFilePath() string {
	// 首先尝试从环境变量获取
	if path := os.Getenv("XMAP_PROBE_FILE"); path != "" {
		return path
	}

	// 然后尝试常见的位置
	commonPaths := []string{
		"nmap-service-probes",
		"./nmap-service-probes",
		"/etc/xmap/nmap-service-probes",
		"/usr/share/nmap/nmap-service-probes",
		"/usr/local/share/nmap/nmap-service-probes",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// 如果都找不到，返回空字符串，将使用内嵌的默认探针数据
	return ""
}

// InitDefaultManager 初始化默认的探针管理器
func InitDefaultManager(options *FingerprintOptions) error {
	if DefaultProbeManager != nil {
		return nil // 已经初始化
	}
	var err error
	DefaultProbeManager, err = NewManager(options)
	return err
}

// GetManager 根据选项获取指纹管理器
func GetManager(options *FingerprintOptions) (*Manager, error) {
	// 确保默认管理器已初始化
	if DefaultProbeManager == nil {
		if err := InitDefaultManager(options); err != nil {
			return nil, fmt.Errorf("failed to initialize default probe manager: %w", err)
		}
	}
	if options.ProbeFilePath == DefaultProbeManager.options.ProbeFilePath && options.VersionIntensity == DefaultProbeManager.options.VersionIntensity {
		return DefaultProbeManager, nil
	}
	// 创建新的管理器
	return NewManager(options)
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

	// 根据版本强度筛选探针
	var filteredTCPProbes []*Probe
	var filteredUDPProbes []*Probe

	// 根据稀有度筛选TCP探针
	for _, probe := range tcpProbes {
		if probe.Rarity <= intensity || intensity == 9 {
			filteredTCPProbes = append(filteredTCPProbes, probe)
		}
	}

	// 根据稀有度筛选UDP探针
	for _, probe := range udpProbes {
		if probe.Rarity <= intensity || intensity == 9 {
			filteredUDPProbes = append(filteredUDPProbes, probe)
		}
	}

	return filteredTCPProbes, filteredUDPProbes
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
