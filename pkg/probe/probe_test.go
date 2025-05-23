package probe

import (
	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadProbes(t *testing.T) {
	// 测试数据
	testProbeData := `
# Service Detection Probes
# 
# This file contains the probes used for service detection by Nmap.
# 
# Format:
# Probe <protocol> <probename> <probestring>
# ports <ports>
# sslports <ports>
# totalwaitms <milliseconds>
# tcpwrappedms <milliseconds>
# rarity <value>
# fallback <fallbackprobe>
# match <service> <pattern> [<versioninfo>]
# softmatch <service> <pattern>

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
ports 80,81,631,8080,8081
sslports 443,8443
totalwaitms 5000
tcpwrappedms 3000
rarity 1
match http m|^HTTP/1\.[01]| p/Apache httpd/ v/2.4.6/ i/CentOS/
softmatch http m|^<HTML|
softmatch http m|^<html|

Probe TCP SSLSessionReq q|\x16\x03\x01\x00\x40\x01\x00\x00\x3c\x03\x01|
ports 443,465,993,995,8443
sslports 443,465,993,995,8443
totalwaitms 6000
rarity 1
match ssl m|^(\x16\x03[\x00-\x03]..\x02...\x03[\x00-\x03])|
match tls m|^\x16\x03[\x00-\x03]..\x02|
`

	// 加载探针
	probes := LoadProbes(testProbeData, 9)

	// 验证结果
	if len(probes) != 2 {
		t.Errorf("Expected 2 probes, got %d", len(probes))
	}

	// 验证第一个探针
	if probes[0].Name != "GetRequest" {
		t.Errorf("Expected probe name 'GetRequest', got '%s'", probes[0].Name)
	}

	if probes[0].Protocol != "TCP" {
		t.Errorf("Expected protocol 'TCP', got '%s'", probes[0].Protocol)
	}

	if len(probes[0].Ports) != 5 {
		t.Errorf("Expected 5 ports, got %d", len(probes[0].Ports))
	}

	if len(probes[0].SSLPorts) != 2 {
		t.Errorf("Expected 2 SSL ports, got %d", len(probes[0].SSLPorts))
	}

	if probes[0].TotalWaitMS != 5000000000 { // 5000ms in nanoseconds
		t.Errorf("Expected TotalWaitMS 5000000000, got %d", probes[0].TotalWaitMS)
	}

	if probes[0].TCPWrappedMS != 3000000000 { // 3000ms in nanoseconds
		t.Errorf("Expected TCPWrappedMS 3000000000, got %d", probes[0].TCPWrappedMS)
	}

	if probes[0].Rarity != 1 {
		t.Errorf("Expected rarity 1, got %d", probes[0].Rarity)
	}

	// 验证匹配组
	if len(probes[0].MatchGroup) != 3 {
		t.Errorf("Expected 3 matches, got %d", len(probes[0].MatchGroup))
	}

	// 验证第一个匹配
	if probes[0].MatchGroup[0].Service != "http" {
		t.Errorf("Expected service 'http', got '%s'", probes[0].MatchGroup[0].Service)
	}

	if probes[0].MatchGroup[0].Pattern != "^HTTP/1\\.[01]" {
		t.Errorf("Expected pattern '^HTTP/1\\.[01]', got '%s'", probes[0].MatchGroup[0].Pattern)
	}

	if probes[0].MatchGroup[0].VersionInfo.ProductName != "Apache" {
		t.Errorf("Expected product name 'Apache', got '%s'", probes[0].MatchGroup[0].VersionInfo.ProductName)
	}

	if probes[0].MatchGroup[0].VersionInfo.Version != "2.4.6" {
		t.Errorf("Expected version '2.4.6', got '%s'", probes[0].MatchGroup[0].VersionInfo.Version)
	}

	if probes[0].MatchGroup[0].VersionInfo.Info != "CentOS" {
		t.Errorf("Expected info 'CentOS', got '%s'", probes[0].MatchGroup[0].VersionInfo.Info)
	}

	// 验证软匹配
	if !probes[0].MatchGroup[1].Soft {
		t.Errorf("Expected soft match, got hard match")
	}

	if probes[0].MatchGroup[1].Service != "http" {
		t.Errorf("Expected service 'http', got '%s'", probes[0].MatchGroup[1].Service)
	}

	if probes[0].MatchGroup[1].Pattern != "^<HTML" {
		t.Errorf("Expected pattern '^<HTML', got '%s'", probes[0].MatchGroup[1].Pattern)
	}
}

func TestProbe_Match(t *testing.T) {
	data := []byte("\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\nFGT101E - FortiOS v6.4.8 FN1EDGE003\r\nUser Access Verification\r\n\r\nUsername: ")
	manage, _ := GetManager(&FingerprintOptions{VersionIntensity: 8})
	err := manage.Load()
	assert.Nil(t, err)
	var r *Match
	for _, p := range manage.GetTCPProbes() {
		r, _ = p.Match(data)
		if r == nil {
			continue
		}
		break
	}
	assert.NotNil(t, r)
	if r != nil {
		assert.Equal(t, r.Service, "telnet")
	}

}

func TestMatch(t *testing.T) {
	data := []byte("\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\nFGT101E - FortiOS v6.4.8 FN1EDGE003\r\nUser Access Verification\r\n\r\nUsername: ")
	pat := []byte("^\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\n.*User Access Verification\r\n\r\nUsername: ")
	com, err := regexp2.Compile(string(pat), regexp2.Singleline)
	assert.Nil(t, err)
	ok, s := com.MatchString(string(data))
	assert.True(t, ok)
	assert.Nil(t, s)
}

func TestFixPattern(t *testing.T) {
	s1 := "\\xff\\xfb\\x01\\xff\\xfb\\x03\\xff\\xfb\\0\\xff\\xfd\\0\\xff\\xfd\\x1f\\r\\n"
	s2 := "\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\n"
	assert.Equal(t, s2, FixPattern(s1))
}

func TestMatch2(t *testing.T) {
	pat := []byte("^\\+-{26}\\+\\r\\n\\x7c {6}Welcome to use {6}\\x7c\\r\\n\\x7c >Destiny DPS Mini shell< \\x7c\\r\\n\\+-{9}\\+-{16}\\+\\r\\n\\x7c Author  \\x7c TimesWu {8}\\x7c\\r\\n\\+-{9}\\+-{16}\\+\\r\\n\\x7c Version \\x7c V([\\d.]+) {10}\\x7c\\r\\n\\+-{9}\\+-{16}\\+\\r\\n")
	response := []byte("^\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\n.*User Access Verification\r\n\r\nUsername: ")
	s2 := FixPattern(string(pat))
	com, err := regexp2.Compile(s2, regexp2.Singleline)
	assert.Nil(t, err)
	ok, s := com.MatchString(string(response))
	assert.Nil(t, s)
	assert.False(t, ok)
}
func TestProbe(t *testing.T) {
	pattern := "^.\\x10\\0\\0\\0\\0\\0\\0.\\0\\0\\0\\n\\0\\\\Invalid or unsupported protocol version \\(71\\); supported versions are \\((\\d+[^)]+)\\)"
	pattern = FixPattern(pattern)
	regexp2.Compile(pattern, regexp2.Singleline)

}
