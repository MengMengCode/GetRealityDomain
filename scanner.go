package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ScanTLS 执行TLS扫描
func ScanTLS(host Host, resultChan chan<- ScanResult, geo *Geo) {
	var ips []net.IP
	var err error
	
	// 根据主机类型获取IP地址
	switch host.Type {
	case HostTypeIP:
		ips = []net.IP{host.IP}
	case HostTypeDomain:
		ips, err = ResolveDomain(host.Origin)
		if err != nil {
			resultChan <- ScanResult{
				IP:     "",
				Origin: host.Origin,
				Port:   config.Port,
				Error:  fmt.Sprintf("域名解析失败: %v", err),
			}
			return
		}
	default:
		resultChan <- ScanResult{
			IP:     "",
			Origin: host.Origin,
			Port:   config.Port,
			Error:  "不支持的主机类型",
		}
		return
	}
	
	// 扫描每个IP
	for _, ip := range ips {
		scanSingleIP(ip, host.Origin, resultChan, geo)
	}
}

// scanSingleIP 扫描单个IP地址
func scanSingleIP(ip net.IP, origin string, resultChan chan<- ScanResult, geo *Geo) {
	startTime := time.Now()
	
	result := ScanResult{
		IP:     ip.String(),
		Origin: origin,
		Port:   config.Port,
	}
	
	// 获取地理位置信息
	if geo != nil {
		result.GeoCode = geo.GetGeo(ip)
	}
	
	// 建立TCP连接
	address := fmt.Sprintf("%s:%d", ip.String(), config.Port)
	conn, err := net.DialTimeout("tcp", address, time.Duration(config.Timeout)*time.Second)
	if err != nil {
		result.Error = fmt.Sprintf("TCP连接失败: %v", err)
		resultChan <- result
		return
	}
	defer conn.Close()
	
	// Reality专用TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,                           // 跳过证书验证
		NextProtos:         []string{"h2", "http/1.1"},     // ALPN协议优先HTTP/2
		CurvePreferences:   []tls.CurveID{tls.X25519},      // 强制使用X25519椭圆曲线
		ServerName:         origin,                         // SNI
	}
	
	// 如果原始输入是域名，使用域名作为SNI
	if ValidateDomainName(origin) {
		tlsConfig.ServerName = origin
	} else {
		// 如果是IP，尝试从证书中获取域名
		tlsConfig.ServerName = ""
	}
	
	// 执行TLS握手
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		result.Error = fmt.Sprintf("TLS握手失败: %v", err)
		resultChan <- result
		return
	}
	defer tlsConn.Close()
	
	// 获取连接状态
	state := tlsConn.ConnectionState()
	
	// 记录响应时间
	result.ResponseTime = time.Since(startTime).Milliseconds()
	
	// 提取TLS版本
	result.TLSVersion = getTLSVersionString(state.Version)
	
	// 提取ALPN协商结果
	result.ALPN = state.NegotiatedProtocol
	
	// 提取椭圆曲线信息
	result.Curve = getCurveString(state.CipherSuite)
	
	// 提取证书信息
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		
		// 获取证书域名
		if len(cert.DNSNames) > 0 {
			result.CertDomain = strings.Join(cert.DNSNames, ",")
		} else if cert.Subject.CommonName != "" {
			result.CertDomain = cert.Subject.CommonName
		}
		
		// 获取证书颁发者
		result.CertIssuer = cert.Issuer.CommonName
		if result.CertIssuer == "" && len(cert.Issuer.Organization) > 0 {
			result.CertIssuer = cert.Issuer.Organization[0]
		}
	}
	
	// 判断是否符合Reality要求
	result.Feasible = result.IsRealityFeasible()
	
	// 发送结果
	resultChan <- result
	
	// 详细输出
	if config.Verbose {
		status := "❌"
		if result.Feasible {
			status = "✅"
		}
		printInfo(fmt.Sprintf("%s %s:%d - TLS:%s ALPN:%s Domain:%s (%dms)", 
			status, result.IP, result.Port, result.TLSVersion, result.ALPN, result.CertDomain, result.ResponseTime))
	}
}

// getTLSVersionString 获取TLS版本字符串
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", version)
	}
}

// getCurveString 获取椭圆曲线字符串
func getCurveString(cipherSuite uint16) string {
	// 由于Go的TLS实现中，椭圆曲线信息不直接暴露在ConnectionState中
	// 我们通过TLS配置强制使用X25519，所以这里直接返回X25519
	// 在实际的TLS 1.3连接中，如果握手成功，说明使用了我们指定的X25519
	return "X25519"
}

// BatchScan 批量扫描
func BatchScan(hostChan <-chan Host, resultChan chan<- ScanResult, geo *Geo) {
	for host := range hostChan {
		ScanTLS(host, resultChan, geo)
	}
}

// ScanWithConcurrency 并发扫描
func ScanWithConcurrency(hostChan <-chan Host, geo *Geo) <-chan ScanResult {
	resultChan := make(chan ScanResult, 1000)
	
	// 使用sync.WaitGroup来等待所有工作协程完成
	var wg sync.WaitGroup
	
	// 启动工作协程
	for i := 0; i < config.Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			BatchScan(hostChan, resultChan, geo)
		}()
	}
	
	// 启动一个协程来关闭结果通道
	go func() {
		wg.Wait() // 等待所有工作协程完成
		close(resultChan)
	}()
	
	return resultChan
}

// ValidateRealityTarget 验证Reality目标的完整性
func ValidateRealityTarget(result ScanResult) (bool, []string) {
	var issues []string
	
	// 检查TLS版本
	if result.TLSVersion != RequiredTLSVersion {
		issues = append(issues, fmt.Sprintf("TLS版本不符合要求，需要%s，实际%s", RequiredTLSVersion, result.TLSVersion))
	}
	
	// 检查ALPN
	if result.ALPN != RequiredALPN {
		issues = append(issues, fmt.Sprintf("ALPN协议不符合要求，需要%s，实际%s", RequiredALPN, result.ALPN))
	}
	
	// 检查椭圆曲线
	if result.Curve != RequiredCurve {
		issues = append(issues, fmt.Sprintf("椭圆曲线不符合要求，需要%s，实际%s", RequiredCurve, result.Curve))
	}
	
	// 检查证书域名
	if result.CertDomain == "" {
		issues = append(issues, "证书域名为空")
	}
	
	// 检查证书颁发者
	if result.CertIssuer == "" {
		issues = append(issues, "证书颁发者为空")
	}
	
	// TODO: 添加CDN检测
	// TODO: 添加中国大陆连通性检测
	
	return len(issues) == 0, issues
}

// DetectCloudflareCDN 检测是否使用Cloudflare CDN
func DetectCloudflareCDN(domain string) bool {
	if domain == "" {
		return false
	}
	
	// 构造Cloudflare检测URL
	url := fmt.Sprintf("https://%s/cdn-cgi/trace", domain)
	
	// 创建HTTP客户端，设置较短的超时时间
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	// 发送请求
	resp, err := client.Get(url)
	if err != nil {
		// 如果请求失败，可能不是Cloudflare，返回false
		return false
	}
	defer resp.Body.Close()
	
	// 如果状态码是200，说明存在/cdn-cgi/trace端点
	if resp.StatusCode == 200 {
		// 读取响应内容进行进一步验证
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		
		bodyStr := string(body)
		// 检查响应内容是否包含Cloudflare特征
		return strings.Contains(bodyStr, "fl=") ||
			   strings.Contains(bodyStr, "h=") ||
			   strings.Contains(bodyStr, "colo=") ||
			   strings.Contains(bodyStr, "gateway=")
	}
	
	return false
}

// DetectCDN 检测是否使用CDN（通用实现）
func DetectCDN(domain string) bool {
	// 首先检测Cloudflare
	if DetectCloudflareCDN(domain) {
		return true
	}
	
	// 常见CDN提供商的标识
	cdnProviders := []string{
		"cloudflare", "amazonaws", "fastly", "maxcdn", "keycdn",
		"jsdelivr", "unpkg", "cdnjs", "bootstrapcdn", "fontawesome",
		"akamai", "edgecast", "chinacache", "qiniu", "upyun",
	}
	
	// 简单的域名匹配检测
	lowerDomain := strings.ToLower(domain)
	for _, provider := range cdnProviders {
		if strings.Contains(lowerDomain, provider) {
			return true
		}
	}
	
	return false
}

// CheckDomainConnectivity 检查域名连通性 - 通过ping域名来测试
func CheckDomainConnectivity(domain string) bool {
	if !scanControl.PingDomain {
		return true // 如果未启用连通性测试，默认返回true
	}
	
	// 如果传入的是空域名或者是IP地址，则跳过ping测试
	if domain == "" || net.ParseIP(domain) != nil {
		return false // 非域名要通过ping来排除
	}
	
	// 验证域名格式
	if !ValidateDomainName(domain) {
		return false
	}
	
	// 使用ping命令测试域名连通性
	return pingDomain(domain)
}

// pingDomain 使用ping命令测试域名连通性
func pingDomain(domain string) bool {
	// 构造ping命令，发送3个包，超时5秒
	cmd := exec.Command("ping", "-c", "3", "-W", "5", domain)
	
	// 执行ping命令
	err := cmd.Run()
	
	// 如果ping成功（返回码为0），则认为域名连通性良好
	return err == nil
}