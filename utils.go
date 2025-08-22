package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// ExistOnlyOne 检查字符串数组中是否只有一个非空元素
func ExistOnlyOne(strs []string) bool {
	count := 0
	for _, s := range strs {
		if s != "" {
			count++
		}
	}
	return count == 1
}

// ValidateDomainName 验证域名格式是否正确
func ValidateDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// 基本的域名正则表达式
	r := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return r.MatchString(domain)
}

// isValidRealityDomain 检查域名是否适合用于Reality
func isValidRealityDomain(domain string) bool {
	// 只要域名不为空就认为有效，能ping通就是好域名
	return domain != ""
}

// NextIP 获取下一个或上一个IP地址
func NextIP(ip net.IP, increment bool) net.IP {
	// 将IP转换为大整数
	ipb := big.NewInt(0).SetBytes(ip)
	
	if increment {
		ipb.Add(ipb, big.NewInt(1))
	} else {
		ipb.Sub(ipb, big.NewInt(1))
	}
	
	// 转换回IP格式
	b := ipb.Bytes()
	
	// 确保字节长度正确
	if len(ip) == 4 { // IPv4
		b = append(make([]byte, 4-len(b)), b...)
	} else { // IPv6
		b = append(make([]byte, 16-len(b)), b...)
	}
	
	return net.IP(b)
}

// ParseHost 解析主机字符串，返回Host结构体
func ParseHost(hostStr string) (Host, error) {
	hostStr = strings.TrimSpace(hostStr)
	
	// 尝试解析为IP地址
	if ip := net.ParseIP(hostStr); ip != nil {
		return Host{
			IP:     ip,
			Origin: hostStr,
			Type:   HostTypeIP,
		}, nil
	}
	
	// 尝试解析为CIDR
	if _, _, err := net.ParseCIDR(hostStr); err == nil {
		return Host{
			Origin: hostStr,
			Type:   HostTypeCIDR,
		}, nil
	}
	
	// 尝试解析为域名
	if ValidateDomainName(hostStr) {
		return Host{
			Origin: hostStr,
			Type:   HostTypeDomain,
		}, nil
	}
	
	return Host{}, fmt.Errorf("无法解析主机: %s", hostStr)
}

// Iterate 从Reader中迭代读取主机信息
func Iterate(reader io.Reader) <-chan Host {
	hostChan := make(chan Host, 100) // 带缓冲的channel
	
	go func() {
		defer close(hostChan)
		
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			
			// 跳过空行和注释行
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			// 解析主机
			host, err := ParseHost(line)
			if err != nil {
				if config.Verbose {
					printError(fmt.Sprintf("解析失败: %s - %v", line, err))
				}
				continue
			}
			
			// 如果是CIDR，展开所有IP
			if host.Type == HostTypeCIDR {
				expandCIDR(host, hostChan)
			} else {
				hostChan <- host
			}
		}
		
		if err := scanner.Err(); err != nil {
			printError(fmt.Sprintf("读取输入时出错: %v", err))
		}
	}()
	
	return hostChan
}

// expandCIDR 展开CIDR为所有包含的IP地址
func expandCIDR(host Host, hostChan chan<- Host) {
	_, ipNet, err := net.ParseCIDR(host.Origin)
	if err != nil {
		printError(fmt.Sprintf("解析CIDR失败: %s - %v", host.Origin, err))
		return
	}
	
	count := 0
	maxHosts := 65536 // 限制最大主机数，防止内存溢出
	
	// 获取网络地址和掩码
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	
	// 计算网络中的主机数
	ones, bits := ipNet.Mask.Size()
	if bits-ones > 16 { // 如果主机位超过16位，限制扫描范围
		printError(fmt.Sprintf("CIDR %s 包含的主机数过多，已限制为前%d个", host.Origin, maxHosts))
	}
	
	// 遍历网络中的所有IP
	for {
		if !ipNet.Contains(ip) {
			break
		}
		
		if count >= maxHosts {
			printError(fmt.Sprintf("CIDR %s 包含的主机数超过限制(%d)，已截断", host.Origin, maxHosts))
			break
		}
		
		// 创建新的Host并发送到channel
		newHost := Host{
			IP:     make(net.IP, len(ip)),
			Origin: host.Origin,
			Type:   HostTypeIP,
		}
		copy(newHost.IP, ip)
		hostChan <- newHost
		
		// 递增IP地址
		ip = NextIP(ip, true)
		count++
	}
	
	if config.Verbose {
		printInfo(fmt.Sprintf("CIDR %s 展开为 %d 个IP地址", host.Origin, count))
	}
}

// IterateAddr 无限扫描模式，从指定IP开始向上下扩展
func IterateAddr(addr string) <-chan Host {
	hostChan := make(chan Host, 100)
	
	go func() {
		defer close(hostChan)
		
		// 解析初始IP
		initialIP := net.ParseIP(addr)
		if initialIP == nil {
			printError(fmt.Sprintf("无效的IP地址: %s", addr))
			return
		}
		
		// 发送初始IP
		hostChan <- Host{
			IP:     initialIP,
			Origin: addr,
			Type:   HostTypeIP,
		}
		
		// 设置上下扩展的IP
		lowIP := make(net.IP, len(initialIP))
		highIP := make(net.IP, len(initialIP))
		copy(lowIP, initialIP)
		copy(highIP, initialIP)
		
		// 交替向上下扩展
		for i := 0; i < math.MaxInt; i++ {
			if i%2 == 0 {
				// 向下扩展
				lowIP = NextIP(lowIP, false)
				if !isValidIP(lowIP) {
					continue
				}
				newLowHost := Host{
					IP:     make(net.IP, len(lowIP)),
					Origin: addr,
					Type:   HostTypeIP,
				}
				copy(newLowHost.IP, lowIP)
				hostChan <- newLowHost
			} else {
				// 向上扩展
				highIP = NextIP(highIP, true)
				if !isValidIP(highIP) {
					continue
				}
				newHighHost := Host{
					IP:     make(net.IP, len(highIP)),
					Origin: addr,
					Type:   HostTypeIP,
				}
				copy(newHighHost.IP, highIP)
				hostChan <- newHighHost
			}
		}
	}()
	
	return hostChan
}

// IterateCIDR 迭代CIDR网段中的所有IP地址
func IterateCIDR(cidr string) <-chan Host {
	hostChan := make(chan Host, 100)
	
	go func() {
		defer close(hostChan)
		
		// 解析CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			printError(fmt.Sprintf("解析CIDR失败: %s - %v", cidr, err))
			return
		}
		
		count := 0
		maxHosts := 65536 // 限制最大主机数，防止内存溢出
		
		// 获取网络地址和掩码
		ip := make(net.IP, len(ipNet.IP))
		copy(ip, ipNet.IP)
		
		// 计算网络中的主机数
		ones, bits := ipNet.Mask.Size()
		if bits-ones > 16 { // 如果主机位超过16位，限制扫描范围
			printError(fmt.Sprintf("CIDR %s 包含的主机数过多，已限制为前%d个", cidr, maxHosts))
		}
		
		// 遍历网络中的所有IP
		for {
			if !ipNet.Contains(ip) {
				break
			}
			
			if count >= maxHosts {
				printError(fmt.Sprintf("CIDR %s 包含的主机数超过限制(%d)，已截断", cidr, maxHosts))
				break
			}
			
			// 创建新的Host并发送到channel
			newHost := Host{
				IP:     make(net.IP, len(ip)),
				Origin: cidr,
				Type:   HostTypeIP,
			}
			copy(newHost.IP, ip)
			hostChan <- newHost
			
			// 递增IP地址
			ip = NextIP(ip, true)
			count++
		}
		
		if config.Verbose {
			printInfo(fmt.Sprintf("CIDR %s 展开为 %d 个IP地址", cidr, count))
		}
	}()
	
	return hostChan
}

// isValidIP 检查IP是否有效（避免广播地址、回环地址等）
func isValidIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	
	// 跳过回环地址
	if ip.IsLoopback() {
		return false
	}
	
	// 跳过多播地址
	if ip.IsMulticast() {
		return false
	}
	
	// 跳过私有地址（可选）
	// if ip.IsPrivate() {
	//     return false
	// }
	
	return true
}

// FetchDomainsFromURL 从URL获取域名列表
func FetchDomainsFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取URL内容失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应内容失败: %v", err)
	}
	
	// 使用正则表达式提取域名
	re := regexp.MustCompile(`(http|https)://(.*?)[/"\s<>]+`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	
	domains := make(map[string]bool) // 使用map去重
	for _, match := range matches {
		if len(match) >= 3 {
			domain := strings.TrimSpace(match[2])
			if ValidateDomainName(domain) {
				domains[domain] = true
			}
		}
	}
	
	// 转换为切片
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}
	
	return result, nil
}

// ResolveDomain 解析域名为IP地址
func ResolveDomain(domain string) ([]net.IP, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("域名解析失败: %v", err)
	}
	
	// 过滤IPv4或IPv6地址
	var result []net.IP
	for _, ip := range ips {
		if config.IPv6 || ip.To4() != nil {
			result = append(result, ip)
		}
	}
	
	if len(result) == 0 {
		return nil, fmt.Errorf("没有找到有效的IP地址")
	}
	
	return result, nil
}

// FormatBytes 格式化字节数为人类可读的格式
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// IsPrivateIP 检查IP是否为私有地址
func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4私有地址范围
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	
	// IPv6私有地址检查
	return len(ip) == 16 && ip[0] == 0xfc || ip[0] == 0xfd
}

// DownloadGeoLite2DB 下载GeoLite2-Country.mmdb文件
func DownloadGeoLite2DB(filePath string) error {
	// MaxMind的免费GeoLite2数据库下载链接
	// 注意：这个链接可能需要注册账户才能使用，这里使用一个公开的镜像链接
	url := "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
	
	printInfo("正在下载GeoLite2-Country.mmdb数据库...")
	
	// 创建HTTP请求
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("下载请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，HTTP状态码: %d", resp.StatusCode)
	}
	
	// 创建目标文件
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()
	
	// 复制数据到文件
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		// 如果下载失败，删除不完整的文件
		os.Remove(filePath)
		return fmt.Errorf("写入文件失败: %v", err)
	}
	
	printSuccess(fmt.Sprintf("GeoLite2数据库下载成功: %s", filePath))
	return nil
}

// TryDownloadGeoLite2DB 尝试下载GeoLite2数据库，失败时不报错
func TryDownloadGeoLite2DB(filePath string) bool {
	err := DownloadGeoLite2DB(filePath)
	if err != nil {
		printError(fmt.Sprintf("下载GeoLite2数据库失败: %v", err))
		printInfo("将跳过地理位置功能")
		return false
	}
	return true
}