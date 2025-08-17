package probe

import (
	"encoding/hex"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"
)

func HexToBytes(h string) []byte {
	data, _ := hex.DecodeString(h)
	return data
}

func TestRegex(t *testing.T) {
	data := []byte("\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\nFGT101E - FortiOS v6.4.8 FN1EDGE003\r\nUser Access Verification\r\n\r\nUsername: ")
	pat := []byte("^\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\n.*User Access Verification\r\n\r\nUsername: ")
	com, err := regexp2.Compile(string(pat), regexp2.Singleline)
	assert.Nil(t, err)
	ok, s := com.MatchString(string(data))
	assert.True(t, ok)
	assert.Nil(t, s)
}

// 测试正则匹配
func TestMultiMatch(t *testing.T) {
	testCases := []struct {
		name string
		pat  []byte
		data []byte
	}{
		{
			name: "test1",
			pat:  []byte("^\x15\x03\x01\\0\x02\x02\x0a$"),
			data: HexToBytes("1503010002020a"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			com, err := regexp2.Compile(string(tc.pat), regexp2.Singleline)
			assert.Nil(t, err)
			ok, s := com.MatchString(string(tc.data))
			assert.Nil(t, s)
			assert.True(t, ok)
		})
	}
}

// 测试sendData 解析是否正确
func TestParseSendData(t *testing.T) {
	store, err := GetStoreWithOptions("", 9, false)
	assert.Nil(t, err)
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "tcp/GenericLines",
			data: []byte("\r\n\r\n"),
		},
		{
			name: "udp/Sqlping",
			data: []byte{2},
		},
		{
			// \0\0\0\0\0\x01\0\0\0\0\0\0\x09_services\x07_dns-sd\x04_udp\x05local\0\0\x0c\0\x01
			name: "udp/DNS-SD",
			// 正确的二进制表示，不包含反斜杠字符
			data: []byte{0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0, 0x9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 0x7, '_', 'd', 'n', 's', '-', 's', 'd', 0x4, '_', 'u', 'd', 'p', 0x5, 'l', 'o', 'c', 'a', 'l', 0x0, 0x0, 0x0c, 0x0, 0x01},
		},
		{
			name: "tcp/SSLSessionReq",
			data: []byte("\x15\x03\x01\x00\x02\x02\x00"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			probe := store.GetProbesByName(tc.name)
			assert.NotNil(t, probe)
			assert.Equal(t, tc.data, probe.SendData)
		})
	}
}
