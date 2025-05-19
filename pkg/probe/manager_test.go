package probe

import (
	"sync"
	"testing"
)

// TestManagerSingleton 测试指纹管理器单例模式
func TestManagerSingleton(t *testing.T) {
	// 清理测试环境
	managerMutex.Lock()
	managerInstances = make(map[string]*Manager)
	managerMutex.Unlock()

	// 测试默认配置下获取相同实例
	manager1, err := GetManager(nil)
	if err != nil {
		t.Fatalf("获取指纹管理器失败: %v", err)
	}

	manager2, err := GetManager(nil)
	if err != nil {
		t.Fatalf("获取指纹管理器失败: %v", err)
	}

	// 应该是同一个实例
	if manager1 != manager2 {
		t.Error("默认配置下应该返回相同的指纹管理器实例")
	}

	// 测试不同配置下获取不同实例
	customOptions := &FingerprintOptions{
		VersionIntensity: 9,
		ProbeFilePath:    "",
	}

	manager3, err := GetManager(customOptions)
	if err != nil {
		t.Fatalf("获取自定义指纹管理器失败: %v", err)
	}

	// 应该是不同的实例
	if manager1 == manager3 {
		t.Error("不同配置下应该返回不同的指纹管理器实例")
	}

	// 测试相同自定义配置下获取相同实例
	manager4, err := GetManager(customOptions)
	if err != nil {
		t.Fatalf("获取自定义指纹管理器失败: %v", err)
	}

	// 应该是同一个实例
	if manager3 != manager4 {
		t.Error("相同自定义配置下应该返回相同的指纹管理器实例")
	}
}

// TestConcurrentAccess 测试并发访问
func TestConcurrentAccess(t *testing.T) {
	// 清理测试环境
	managerMutex.Lock()
	managerInstances = make(map[string]*Manager)
	managerMutex.Unlock()

	// 并发获取指纹管理器
	var wg sync.WaitGroup
	instanceCount := 100
	instances := make([]*Manager, instanceCount)

	for i := 0; i < instanceCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			manager, err := GetManager(nil)
			if err != nil {
				t.Errorf("并发获取指纹管理器失败: %v", err)
				return
			}
			instances[index] = manager
		}(i)
	}

	wg.Wait()

	// 检查所有实例是否相同
	for i := 1; i < instanceCount; i++ {
		if instances[0] != instances[i] {
			t.Errorf("并发获取的指纹管理器实例不同: %d != %d", 0, i)
		}
	}

	// 检查实例映射中是否只有一个实例
	managerMutex.Lock()
	if len(managerInstances) != 1 {
		t.Errorf("实例映射中应该只有一个实例，实际有 %d 个", len(managerInstances))
	}
	managerMutex.Unlock()
}

// TestForceReload 测试强制重新加载
func TestForceReload(t *testing.T) {
	// 清理测试环境
	managerMutex.Lock()
	managerInstances = make(map[string]*Manager)
	managerMutex.Unlock()

	// 创建多个不同配置的实例
	_, err := GetManager(nil)
	if err != nil {
		t.Fatalf("获取默认指纹管理器失败: %v", err)
	}

	customOptions1 := &FingerprintOptions{
		VersionIntensity: 8,
		ProbeFilePath:    "",
	}
	_, err = GetManager(customOptions1)
	if err != nil {
		t.Fatalf("获取自定义指纹管理器1失败: %v", err)
	}

	customOptions2 := &FingerprintOptions{
		VersionIntensity: 9,
		ProbeFilePath:    "",
	}
	_, err = GetManager(customOptions2)
	if err != nil {
		t.Fatalf("获取自定义指纹管理器2失败: %v", err)
	}

	// 检查实例映射中是否有3个实例
	managerMutex.Lock()
	if len(managerInstances) != 3 {
		t.Errorf("实例映射中应该有3个实例，实际有 %d 个", len(managerInstances))
	}
	managerMutex.Unlock()

	// 强制重新加载
	err = ForceReload()
	if err != nil {
		t.Fatalf("强制重新加载失败: %v", err)
	}

	// 实例映射中应该仍然有3个实例
	managerMutex.Lock()
	if len(managerInstances) != 3 {
		t.Errorf("重新加载后实例映射中应该有3个实例，实际有 %d 个", len(managerInstances))
	}
	managerMutex.Unlock()
}
