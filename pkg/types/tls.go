package types

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// TLSInfo 包含 TLS 连接的信息
type TLSInfo struct {
	Certificates []*x509.Certificate
	Version      string
	TLSVersion   string
	CipherSuite  string
	JA3S         string
	RawData      []byte
}

// SSLResponse 包含 SSL/TLS 响应的完整信息
type SSLResponse struct {
	// 基本字段
	TLSVersion  string `json:"tls_version"`  // TLS 版本
	CipherSuite string `json:"cipher_suite"` // 加密套件
	RawData     string `json:"raw_data"`     // 原始 SSL 数据
	// JA3S指纹
	JA3S string `json:"ja3s,omitempty"` // JA3S指纹
	// 结构化证书信息
	CertInfo map[string]any `json:"cert_info"`
}

// FromTlsConnectionState 从 tls.ConnectionState 创建 SSLResponse
func FromTlsConnectionState(state *tls.ConnectionState) *SSLResponse {
	// 创建基本的 SSLResponse 结构
	sslResponse := &SSLResponse{
		TLSVersion:  tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		CertInfo:    make(map[string]interface{}),
		// 如果需要原始数据，应该在调用该函数后单独设置
		RawData: "",
	}
	var extensions []uint16

	// 检查是否支持ALPN
	if state.NegotiatedProtocol != "" {
		extensions = append(extensions, 16) // ALPN扩展ID
	}

	// 检查是否使用了会话票证
	if state.DidResume {
		extensions = append(extensions, 35) // Session Ticket扩展ID
	}

	// 检查是否有证书
	if len(state.PeerCertificates) == 0 {
		return sslResponse
	}

	// 获取主证书
	cert := state.PeerCertificates[0]

	// 提取证书信息
	// 格式化证书主题
	subject := make(map[string]interface{})
	if cert.Subject.CommonName != "" {
		subject["common_name"] = cert.Subject.CommonName
	}
	if len(cert.Subject.Country) > 0 {
		subject["country"] = cert.Subject.Country[0]
	}
	if len(cert.Subject.Organization) > 0 {
		subject["org"] = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		subject["org_unit"] = cert.Subject.OrganizationalUnit[0]
	}
	sslResponse.CertInfo["subject"] = subject

	// 格式化证书颁发者
	issuer := make(map[string]interface{})
	if cert.Issuer.CommonName != "" {
		issuer["common_name"] = cert.Issuer.CommonName
	}
	if len(cert.Issuer.Country) > 0 {
		issuer["country"] = cert.Issuer.Country[0]
	}
	if len(cert.Issuer.Organization) > 0 {
		issuer["org"] = cert.Issuer.Organization[0]
	}
	sslResponse.CertInfo["issuer"] = issuer

	// 证书序列号
	sslResponse.CertInfo["serial_number"] = cert.SerialNumber.String()

	// 证书有效期
	sslResponse.CertInfo["not_before"] = cert.NotBefore.Format(time.RFC3339)
	sslResponse.CertInfo["not_after"] = cert.NotAfter.Format(time.RFC3339)

	// 签名算法
	sslResponse.CertInfo["signature_algorithm"] = cert.SignatureAlgorithm.String()

	// 替代名称 (SANs)
	if len(cert.DNSNames) > 0 {
		sslResponse.CertInfo["dns_names"] = cert.DNSNames
	}

	// 计算证书指纹
	fingerprint := sha256.Sum256(cert.Raw)
	hexStr := hex.EncodeToString(fingerprint[:])
	var formatted []string
	for i := 0; i < len(hexStr); i += 2 {
		formatted = append(formatted, hexStr[i:i+2])
	}
	sslResponse.CertInfo["fingerprint"] = strings.Join(formatted, ":")

	// 获取公钥信息
	var pubKeyType string
	var pubKeyBits int
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubKeyType = "RSA"
		pubKeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		pubKeyType = "ECDSA"
		pubKeyBits = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		pubKeyType = "Ed25519"
		pubKeyBits = 256
	case *dsa.PublicKey:
		pubKeyType = "DSA"
		pubKeyBits = pub.Parameters.P.BitLen()
	default:
		pubKeyType = "Unknown"
		pubKeyBits = 0
	}

	sslResponse.CertInfo["public_key_type"] = pubKeyType
	sslResponse.CertInfo["public_key_bits"] = pubKeyBits

	// 证书链信息
	if len(state.PeerCertificates) > 1 {
		chainInfo := make([]map[string]interface{}, 0, len(state.PeerCertificates)-1)
		for i := 1; i < len(state.PeerCertificates); i++ {
			chainCert := state.PeerCertificates[i]
			chainItem := make(map[string]interface{})

			// 提取链证书的主题
			chainSubject := make(map[string]interface{})
			if chainCert.Subject.CommonName != "" {
				chainSubject["common_name"] = chainCert.Subject.CommonName
			}
			chainItem["subject"] = chainSubject
			// 提取链证书的颁发者
			chainIssuer := make(map[string]interface{})

			if chainCert.Issuer.CommonName != "" {
				chainIssuer["common_name"] = chainCert.Issuer.CommonName
			}
			chainItem["issuer"] = chainIssuer

			// 计算链证书的指纹
			chainFingerprint := sha256.Sum256(chainCert.Raw)
			chainHexStr := hex.EncodeToString(chainFingerprint[:])
			var chainFormatted []string
			for j := 0; j < len(chainHexStr); j += 2 {
				chainFormatted = append(chainFormatted, chainHexStr[j:j+2])
			}
			chainItem["fingerprint"] = strings.Join(chainFormatted, ":")

			chainInfo = append(chainInfo, chainItem)
		}
		sslResponse.CertInfo["chain"] = chainInfo
	}

	return sslResponse
}

// stringifyExtensions 将扩展ID列表转换为字符串列表
func stringifyExtensions(extensions []uint16) []string {
	var result []string
	for _, ext := range extensions {
		result = append(result, strconv.Itoa(int(ext)))
	}
	return result
}

// containsExtension 检查扩展列表是否包含指定的扩展ID
func containsExtension(extensions []uint16, target uint16) bool {
	for _, ext := range extensions {
		if ext == target {
			return true
		}
	}
	return false
}

// sortExtensions 对扩展ID列表进行排序
func sortExtensions(extensions []uint16) {
	// 简单的冒泡排序
	for i := 0; i < len(extensions); i++ {
		for j := i + 1; j < len(extensions); j++ {
			if extensions[i] > extensions[j] {
				extensions[i], extensions[j] = extensions[j], extensions[i]
			}
		}
	}
}
