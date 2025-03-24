package api

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/appfinger/pkg/rule"
)

// InitRuleManager 初始化规则管理器
func InitRuleManager(fingerprintsPath string) error {
	// 获取规则管理器实例
	ruleManager := rule.GetRuleManager()

	// 检查规则库是否已加载
	if ruleManager.IsLoaded() {
		gologger.Debug().Msgf("指纹库已加载，上次加载时间: %s", ruleManager.GetLastLoadTime().Format("2006-01-02 15:04:05"))
		return nil
	}

	// 如果未指定指纹库路径，使用默认路径
	if fingerprintsPath == "" {
		// 尝试几个可能的路径
		fingerprintsPath = customrules.GetDefaultDirectory()
	}
	// 加载指定路径的指纹库
	if err := ruleManager.LoadRules(fingerprintsPath); err != nil {
		return fmt.Errorf("加载指纹库失败: %v", err)
	}
	return nil
}

// ReloadRules 重新加载指纹库规则
func ReloadRules() error {
	return rule.GetRuleManager().ReloadRules()
}
