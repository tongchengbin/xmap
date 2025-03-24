package api

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"os"
	"os/exec"
	"path/filepath"
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

// UpdateRules 从远程更新指纹库规则
func UpdateRules() error {
	gologger.Info().Msg("正在从远程更新指纹库规则...")
	
	// 直接使用git拉取最新规则
	// 这里假设规则库在customrules包中有定义
	rulesDir := customrules.GetDefaultDirectory()
	gologger.Info().Msgf("指纹库路径: %s", rulesDir)
	
	// 检查是否是git仓库
	if _, err := os.Stat(filepath.Join(rulesDir, ".git")); os.IsNotExist(err) {
		return fmt.Errorf("指纹库目录不是git仓库，无法更新: %s", rulesDir)
	}
	
	// 执行git pull命令
	cmd := exec.Command("git", "-C", rulesDir, "pull", "origin", "master")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("更新指纹库失败: %v, 输出: %s", err, string(output))
	}
	
	gologger.Info().Msgf("指纹库更新成功: %s", string(output))
	
	// 重新加载规则
	return ReloadRules()
}
