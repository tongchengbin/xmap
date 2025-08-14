package probe

import (
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"
)

// 创建测试用的正则表达式
func createTestRegex(pattern string) *regexp2.Regexp {
	r, _ := regexp2.Compile(pattern, regexp2.None)
	return r
}

func TestMatch(t *testing.T) {
	// 创建测试用的探针和匹配规则
	mainProbe := &Probe{
		Name:     "MainProbe",
		SendData: []byte("MAIN"),
		MatchGroup: []*Match{
			{
				Service: "main-service",
				Pattern: []byte("MAIN-PATTERN ([\\d\\.]+)"),
				Soft:    false,
				VersionInfo: &VersionInfo{
					Version: "$1",
				},
				regex: createTestRegex("MAIN-PATTERN ([\\d\\.]+)"),
			},
		},
	}

	// 创建回退探针
	fallbackProbe := &Probe{
		Name:     "FallbackProbe",
		SendData: []byte("FALLBACK"),
		MatchGroup: []*Match{
			{
				Service: "fallback-service",
				Pattern: []byte("FALLBACK-PATTERN ([\\d\\.]+)"),
				Soft:    false,
				VersionInfo: &VersionInfo{
					Version: "$1",
				},
				regex: createTestRegex("FALLBACK-PATTERN ([\\d\\.]+)"),
			},
		},
	}
	mainProbe.Fallback = []string{"FallbackProbe"}
	mainProbe.FallbackProbes = []*Probe{fallbackProbe}
	t.Run("DirectMatch", func(t *testing.T) {
		response := []byte("MAIN-PATTERN 1.0")
		result, _ := mainProbe.Match(response)

		assert.NotNil(t, result)
		assert.Equal(t, "main-service", result.Match.Service)
		assert.Equal(t, "1.0", result.VersionInfo["version"])
		assert.False(t, result.IsFallback)
		assert.Empty(t, result.FallbackPath)
	})

	// 测试场景2: 直接匹配失败，回退匹配成功
	t.Run("FallbackMatch", func(t *testing.T) {
		response := []byte("FALLBACK-PATTERN 2.0")
		result, err := mainProbe.Match(response)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "fallback-service", result.Match.Service)
		assert.Equal(t, "2.0", result.VersionInfo["version"])
	})

	// 测试场景3: 所有匹配都失败
	t.Run("NoMatch", func(t *testing.T) {
		response := []byte("NO-MATCH")
		result, err := mainProbe.Match(response)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

}

// 测试常见协议匹配是否正确
func TestCommonProtocolMatch(t *testing.T) {
	store := GetDefaultStore()
	// 测试HTTP
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "tcp/GetRequest",
			data: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n<html><body><h1>Test HTTP Server</h1></body></html>"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			probe := store.GetProbesByName(tc.name)
			assert.NotNil(t, probe)
			result, err := probe.Match(tc.data)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}

}
