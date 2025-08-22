package main

import (
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// HostType 定义主机类型常量
type HostType int

const (
	HostTypeIP     HostType = 1 // 单个IP地址
	HostTypeCIDR   HostType = 2 // IP段(CIDR格式)
	HostTypeDomain HostType = 3 // 域名
)

// Host 结构体表示一个扫描目标
type Host struct {
	IP     net.IP   // IP地址
	Origin string   // 原始输入(IP/域名/CIDR)
	Type   HostType // 主机类型(IP/CIDR/域名)
}

// ScanResult 表示扫描结果
type ScanResult struct {
	IP          string // IP地址
	Origin      string // 原始输入
	Port        int    // 端口
	CertDomain  string // 证书域名
	CertIssuer  string // 证书颁发者
	TLSVersion  string // TLS版本
	ALPN        string // ALPN协商结果
	Curve       string // 椭圆曲线算法
	GeoCode     string // 地理位置代码
	Feasible    bool   // 是否符合Reality要求
	ResponseTime int64 // 响应时间(毫秒)
	Error       string // 错误信息
}

// Geo 地理位置查询结构体
type Geo struct {
	geoReader *geoip2.Reader
	mu        sync.Mutex // 保证线程安全
}

// NewGeo 创建新的地理位置查询实例
func NewGeo(dbPath string) (*Geo, error) {
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	
	return &Geo{
		geoReader: reader,
	}, nil
}

// GetGeo 获取IP的地理位置代码
func (g *Geo) GetGeo(ip net.IP) string {
	if g.geoReader == nil {
		return "UNKNOWN"
	}
	
	g.mu.Lock()
	defer g.mu.Unlock()
	
	country, err := g.geoReader.Country(ip)
	if err != nil {
		return "UNKNOWN"
	}
	
	return country.Country.IsoCode
}

// Close 关闭地理位置数据库
func (g *Geo) Close() error {
	if g.geoReader != nil {
		return g.geoReader.Close()
	}
	return nil
}

// ScanConfig 扫描配置
type ScanConfig struct {
	Port        int    // 扫描端口
	Thread      int    // 并发线程数
	Timeout     int    // 连接超时时间(秒)
	Output      string // 输出文件路径
	Verbose     bool   // 是否详细输出
	IPv6        bool   // 是否支持IPv6
	GeoDBPath   string // GeoIP数据库路径
}

// DefaultScanConfig 返回默认扫描配置
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Port:      443,
		Thread:    2,
		Timeout:   10,
		Output:    "out.csv",
		Verbose:   false,
		IPv6:      false,
		GeoDBPath: "Country.mmdb",
	}
}

// RealityRequirements Reality协议要求的常量
const (
	RequiredTLSVersion = "TLS 1.3"
	RequiredALPN       = "h2"
	RequiredCurve      = "X25519"
)

// IsRealityFeasible 检查扫描结果是否符合Reality协议要求
func (sr *ScanResult) IsRealityFeasible() bool {
	// Reality协议的5个要求：
	// 1. 使用 TLS 1.3 协议
	// 2. 使用 X25519 签名算法
	// 3. 支持 HTTP/2 协议（H2）
	// 4. 不使用 CDN (特别是Cloudflare)
	// 5. 中国境内可直接访问
	
	if sr.TLSVersion != RequiredTLSVersion {
		return false
	}
	
	if sr.ALPN != RequiredALPN {
		return false
	}
	
	if sr.Curve != RequiredCurve {
		return false
	}
	
	if sr.CertDomain == "" {
		return false
	}
	
	// 检查证书域名是否有效
	if !isValidRealityDomain(sr.CertDomain) {
		return false
	}
	
	if sr.CertIssuer == "" {
		return false
	}
	
	// 检测是否使用Cloudflare CDN
	if DetectCloudflareCDN(sr.CertDomain) {
		return false
	}
	
	// 检测域名连通性（如果启用）
	if scanControl.PingDomain && !CheckDomainConnectivity(sr.CertDomain) {
		return false
	}
	
	return true
}

// String 返回HostType的字符串表示
func (ht HostType) String() string {
	switch ht {
	case HostTypeIP:
		return "IP"
	case HostTypeCIDR:
		return "CIDR"
	case HostTypeDomain:
		return "DOMAIN"
	default:
		return "UNKNOWN"
	}
}

// String 返回Host的字符串表示
func (h Host) String() string {
	return h.Origin + " (" + h.Type.String() + ")"
}