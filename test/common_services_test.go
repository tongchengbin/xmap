package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/model"
)

// 测试服务器类型常量 (仅用于测试标识)
const (
	ServerTypeHTTP   = "http"
	ServerTypeHTTPS  = "https"
	ServerTypeSSH    = "ssh"
	ServerTypeMySQL  = "mysql"
	ServerTypeRedis  = "redis"
	ServerTypeApache = "apache"
	ServerTypeNginx  = "nginx"
)

// TestCommonServices 测试XMap对常见服务的扫描能力
func TestCommonServices(t *testing.T) {
	// 创建测试服务
	services := createTestServices(t)
	defer stopTestServices(services)

	// 创建XMap实例
	xmap := api.NewXMap(
		api.WithTimeout(5*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(9),
		api.WithMaxParallelism(100),
	)

	// 创建上下文
	ctx := context.Background()

	// 测试每个服务
	for name, server := range services {
		t.Run(name, func(t *testing.T) {
			// 创建扫描目标
			target := &model.ScanTarget{
				IP:       server.GetIP(),
				Port:     server.GetPort(),
				Protocol: "tcp",
			}

			// 执行扫描
			scanTask := &model.ScanTask{
				Targets: []*model.ScanTarget{target},
			}

			_, results, err := xmap.ExecuteTask(ctx, scanTask)
			assert.NoError(t, err, "扫描应该成功完成")
			assert.NotEmpty(t, results, "应该返回扫描结果")

			// 验证结果
			if len(results) > 0 {
				result := results[0]
				assert.NotEmpty(t, result.Service, "应该识别出服务类型")

				// 根据服务类型验证结果
				switch name {
				case ServerTypeSSH:
					assert.True(t, strings.Contains(strings.ToLower(result.Service), "ssh"),
						"应该识别为SSH服务")
				case ServerTypeHTTP, ServerTypeApache, ServerTypeNginx:
					assert.True(t, strings.Contains(strings.ToLower(result.Service), "http") ||
						strings.Contains(strings.ToLower(result.Service), "apache") ||
						strings.Contains(strings.ToLower(result.Service), "nginx"),
						"应该识别为HTTP相关服务")
				case ServerTypeHTTPS:
					assert.True(t, strings.Contains(strings.ToLower(result.Service), "http") ||
						strings.Contains(strings.ToLower(result.Service), "ssl") ||
						strings.Contains(strings.ToLower(result.Service), "tls"),
						"应该识别为HTTPS相关服务")
				case ServerTypeMySQL:
					assert.True(t, strings.Contains(strings.ToLower(result.Service), "mysql"),
						"应该识别为MySQL服务")
				case ServerTypeRedis:
					assert.True(t, strings.Contains(strings.ToLower(result.Service), "redis"),
						"应该识别为Redis服务")
				}
			}
		})
	}
}

// TestBatchScanCommonServices 测试XMap批量扫描常见服务的能力
func TestBatchScanCommonServices(t *testing.T) {
	// 创建测试服务
	services := createTestServices(t)
	defer stopTestServices(services)

	// 创建XMap实例
	xmap := api.NewXMap(
		api.WithTimeout(10*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(7),
		api.WithMaxParallelism(50),
	)

	// 创建上下文
	ctx := context.Background()

	// 创建测试目标列表
	var targets []*model.ScanTarget
	for _, server := range services {
		target := &model.ScanTarget{
			IP:       server.GetIP(),
			Port:     server.GetPort(),
			Protocol: "tcp",
		}
		targets = append(targets, target)
	}

	// 创建扫描任务
	scanTask := &model.ScanTask{
		Targets: targets,
	}

	// 执行批量扫描
	_, results, err := xmap.ExecuteTask(ctx, scanTask)
	assert.NoError(t, err, "批量扫描应该成功完成")
	assert.NotEmpty(t, results, "应该返回扫描结果")
	assert.Equal(t, len(targets), len(results), "结果数量应该与目标数量一致")

	// 验证每个结果
	for _, result := range results {
		assert.NotEmpty(t, result.Service, "应该识别出服务类型")
	}
}

// createTestServices 创建测试服务
func createTestServices(t *testing.T) map[string]*TestServer {
	services := make(map[string]*TestServer)

	// 创建各种测试服务
	serviceTypes := []string{
		ServerTypeHTTP,
		ServerTypeHTTPS,
		ServerTypeSSH,
		ServerTypeMySQL,
		ServerTypeRedis,
		ServerTypeApache,
		ServerTypeNginx,
	}

	for _, serviceType := range serviceTypes {
		server := createTestServerByType(t, serviceType)
		if server != nil {
			services[serviceType] = server
			fmt.Printf("已启动%s测试服务，地址: 127.0.0.1:%d\n", serviceType, server.GetPort())
		}
	}

	return services
}

// createTestServerByType 根据类型创建并配置测试服务器
func createTestServerByType(t *testing.T, serverType string) *TestServer {
	server := NewTestServer("tcp")

	// 根据服务类型配置响应
	switch serverType {
	case ServerTypeHTTP, ServerTypeApache:
		// HTTP/Apache 响应
		httpResponse := "HTTP/1.1 200 OK\r\n" +
			"Server: Apache/2.4.41 (Ubuntu)\r\n" +
			"Date: Sun, 23 Mar 2025 06:00:00 GMT\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"Content-Length: 145\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"<!DOCTYPE html>\r\n" +
			"<html>\r\n" +
			"<head>\r\n" +
			"<title>Apache Test Server</title>\r\n" +
			"</head>\r\n" +
			"<body>\r\n" +
			"<h1>Welcome to Apache Test Server</h1>\r\n" +
			"</body>\r\n" +
			"</html>"
		server.AddStringRule("", []byte(httpResponse), 5)
		server.AddStringRule("GET", []byte(httpResponse), 10)
		server.AddStringRule("HEAD", []byte(httpResponse), 10)

	case ServerTypeNginx:
		// Nginx 响应
		nginxResponse := "HTTP/1.1 200 OK\r\n" +
			"Server: nginx/1.18.0 (Ubuntu)\r\n" +
			"Date: Sun, 23 Mar 2025 06:00:00 GMT\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"Content-Length: 145\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"<!DOCTYPE html>\r\n" +
			"<html>\r\n" +
			"<head>\r\n" +
			"<title>Welcome to nginx!</title>\r\n" +
			"</head>\r\n" +
			"<body>\r\n" +
			"<h1>Welcome to nginx!</h1>\r\n" +
			"</body>\r\n" +
			"</html>"
		server.AddStringRule("", []byte(nginxResponse), 5)
		server.AddStringRule("GET", []byte(nginxResponse), 10)
		server.AddStringRule("HEAD", []byte(nginxResponse), 10)

	case ServerTypeHTTPS:
		// HTTPS 响应 (TLS握手)
		tlsResponse := []byte{
			0x16,       // Content Type: Handshake
			0x03, 0x03, // TLS Version: TLS 1.2
			0x00, 0x02, // Length
			0x01, 0x00, // Handshake Type: Client Hello
		}
		server.AddStringRule("", tlsResponse, 5)

	case ServerTypeSSH:
		// SSH 响应
		sshResponse := "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
		server.AddStringRule("", []byte(sshResponse), 10)
		server.AddStringRule("SSH", []byte(sshResponse), 10)

	case ServerTypeMySQL:
		// MySQL 响应
		mysqlResponse := []byte{
			0x4a, 0x00, 0x00, 0x00, 0x0a, 0x38, 0x2e, 0x30,
			0x2e, 0x32, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		server.AddStringRule("", mysqlResponse, 10)

	case ServerTypeRedis:
		// Redis 响应
		redisResponse := "-ERR unknown command\r\n"
		server.AddStringRule("", []byte(redisResponse), 10)

	default:
		t.Logf("未知的服务类型: %s", serverType)
		return nil
	}

	// 启动服务器
	err := server.Start()
	if err != nil {
		t.Logf("无法启动%s测试服务: %v", serverType, err)
		return nil
	}

	return server
}

// stopTestServices 停止所有测试服务
func stopTestServices(services map[string]*TestServer) {
	for name, server := range services {
		if err := server.Stop(); err != nil {
			fmt.Printf("停止%s服务时出错: %v\n", name, err)
		}
	}
}
