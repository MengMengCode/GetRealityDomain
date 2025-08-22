package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// 全局配置
type Config struct {
	Port    int
	Thread  int
	Timeout int
	Output  string
	Verbose bool
	IPv6    bool
}

var config = Config{
	Port:    443,
	Thread:  2,
	Timeout: 10,
	Output:  "out.csv",
	Verbose: false,
	IPv6:    false,
}

// 扫描控制配置
var scanControl = struct {
	MaxResults int  // 最大结果数，0表示无限制
	StopOnMax  bool // 达到最大结果数时是否停止
	PingDomain bool // 是否ping域名测试连通性
}{
	MaxResults: 0,
	StopOnMax:  false,
	PingDomain: true,
}

func main() {
	// 显示大字标题
	showTitle()

	// 获取本机IP
	localIP, err := getLocalIP()
	if err != nil {
		printError(fmt.Sprintf("获取本机IP失败: %v", err))
		localIP = "127.0.0.1" // 默认值
	}

	// 询问是否使用本机IP
	useLocalIP := askYesNo(fmt.Sprintf("本机IP为：%s，是否使用该IP？", localIP), true)
	var targetIP string
	if useLocalIP {
		targetIP = localIP
	} else {
		fmt.Print("请输入要使用的IP地址: ")
		targetIP = getStringInput()
		if net.ParseIP(targetIP) == nil {
			printError("无效的IP地址格式，使用默认IP")
			targetIP = localIP
		}
	}

	// 询问是否使用/24段
	use24Subnet := askYesNo("是否使用/24段？", true)
	var scanTarget string
	if use24Subnet {
		scanTarget = targetIP + "/24"
	} else {
		fmt.Print("请输入子网掩码位数 (如: /20, /16): ")
		maskInput := getStringInput()
		if maskInput == "" {
			scanTarget = targetIP + "/24"
			printInfo("使用默认/24段")
		} else {
			// 处理用户输入，确保以/开头
			if !strings.HasPrefix(maskInput, "/") {
				maskInput = "/" + maskInput
			}
			
			// 验证掩码位数是否有效
			if isValidMask(maskInput) {
				// 计算网络地址
				networkAddr, err := calculateNetworkAddress(targetIP, maskInput)
				if err != nil {
					printError("计算网络地址失败，使用默认/24段")
					scanTarget = targetIP + "/24"
				} else {
					scanTarget = networkAddr + maskInput
					printInfo(fmt.Sprintf("计算得到网段: %s", scanTarget))
				}
			} else {
				printError("无效的子网掩码位数，使用默认/24段")
				scanTarget = targetIP + "/24"
			}
		}
	}

	// 询问是否找到10个符合的就停止
	stopAt10 := askYesNo("是否找到10个符合的就停止？", true)
	if stopAt10 {
		scanControl.MaxResults = 10
		scanControl.StopOnMax = true
	} else {
		fmt.Print("请输入最大结果数 (0表示无限制): ")
		maxStr := getStringInput()
		if maxStr == "" {
			scanControl.MaxResults = 0
			scanControl.StopOnMax = false
		} else {
			if max, err := strconv.Atoi(maxStr); err == nil && max > 0 {
				scanControl.MaxResults = max
				scanControl.StopOnMax = true
			} else {
				scanControl.MaxResults = 0
				scanControl.StopOnMax = false
			}
		}
	}

	// 询问并发线程数
	fmt.Printf("请输入并发线程数 (当前: %d, 建议1-100): ", config.Thread)
	threadStr := getStringInput()
	if threadStr != "" {
		if thread, err := strconv.Atoi(threadStr); err == nil && thread > 0 && thread <= 1000 {
			config.Thread = thread
		} else {
			printError("无效的线程数，使用默认值")
		}
	}

	// 询问是否启用ping域名测试连通性
	scanControl.PingDomain = askYesNo("是否启用ping域名测试连通性？", true)

	// 使用系统清屏命令
	clearScreenSystem()
	printInfo("开始扫描...")

	err = scanAddress(scanTarget)
	if err != nil {
		printError(fmt.Sprintf("扫描失败: %v", err))
		pause()
		return
	}

	// 扫描完成后显示结果
	showResultsPaginated(config.Output)
}

// 显示大字标题
func showTitle() {
	clearScreen()
	fmt.Println()
	fmt.Println("  ╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("  ║                                                           ║")
	fmt.Println("  ║    ██████╗ ███████╗████████╗██████╗ ███████╗ █████╗      ║")
	fmt.Println("  ║   ██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗     ║")
	fmt.Println("  ║   ██║  ███╗█████╗     ██║   ██████╔╝█████╗  ███████║     ║")
	fmt.Println("  ║   ██║   ██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██╔══██║     ║")
	fmt.Println("  ║   ╚██████╔╝███████╗   ██║   ██║  ██║███████╗██║  ██║     ║")
	fmt.Println("  ║    ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ║")
	fmt.Println("  ║                                                           ║")
	fmt.Println("  ║   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗      ║")
	fmt.Println("  ║   ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║      ║")
	fmt.Println("  ║   ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║      ║")
	fmt.Println("  ║   ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║      ║")
	fmt.Println("  ║   ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║      ║")
	fmt.Println("  ║   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝      ║")
	fmt.Println("  ║                                                           ║")
	fmt.Println("  ║                Reality协议目标域名扫描器                    ║")
	fmt.Println("  ║                        v1.0                               ║")
	fmt.Println("  ╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// 询问是否选择（y/n），支持默认值
func askYesNo(question string, defaultYes bool) bool {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}

	fmt.Printf("%s [%s]: ", question, defaultStr)
	input := strings.ToLower(strings.TrimSpace(getStringInput()))

	if input == "" {
		return defaultYes
	}

	return input == "y" || input == "yes"
}

// 获取本机IP地址
func getLocalIP() (string, error) {
	// 使用ipify.org API获取公网IP
	resp, err := http.Get("https://api.ipify.org/")
	if err != nil {
		return "", fmt.Errorf("获取公网IP失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %v", err)
	}

	ip := strings.TrimSpace(string(body))

	// 验证返回的是否为有效IP地址
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("返回的不是有效的IP地址: %s", ip)
	}

	return ip, nil
}

// 实际的扫描函数
func scanAddress(addr string) error {
	printInfo("正在初始化扫描...")

	// 初始化地理位置查询
	geoPaths := []string{
		"Country.mmdb",
		"GeoLite2-Country.mmdb",
		"/usr/share/GeoIP/GeoLite2-Country.mmdb",
		"/var/lib/GeoIP/GeoLite2-Country.mmdb",
		config.Output + ".geo.mmdb",
	}

	var geo *Geo
	var geoErr error
	for _, path := range geoPaths {
		if geo, geoErr = NewGeo(path); geoErr == nil {
			printInfo(fmt.Sprintf("地理位置数据库加载成功: %s", path))
			break
		}
	}

	// 如果没有找到地理位置数据库，尝试自动下载
	if geo == nil {
		printInfo("未找到地理位置数据库，正在尝试自动下载...")

		// 尝试下载到程序目录
		downloadPath := "GeoLite2-Country.mmdb"
		if TryDownloadGeoLite2DB(downloadPath) {
			// 下载成功，尝试加载
			if geo, geoErr = NewGeo(downloadPath); geoErr == nil {
				printInfo(fmt.Sprintf("地理位置数据库下载并加载成功: %s", downloadPath))
			} else {
				printError(fmt.Sprintf("下载的数据库文件加载失败: %v", geoErr))
				printInfo("将跳过地理位置查询")
			}
		} else {
			printInfo("自动下载失败，将跳过地理位置查询")
			printInfo("提示: 可手动下载 GeoLite2-Country.mmdb 文件到程序目录以启用地理位置功能")
		}
	}
	defer func() {
		if geo != nil {
			geo.Close()
		}
	}()

	// 解析主机
	host, err := ParseHost(addr)
	if err != nil {
		return fmt.Errorf("解析地址失败: %v", err)
	}

	var hostChan <-chan Host
	var totalTargets int

	// 根据主机类型创建迭代器和计算总数
	if host.Type == HostTypeIP {
		// 单个IP的无限扫描模式
		printInfo("启动无限扫描模式（从指定IP向上下扩展）")
		hostChan = IterateAddr(addr)
		totalTargets = 0 // 无限扫描，总数未知
	} else if host.Type == HostTypeCIDR {
		// CIDR网段扫描
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("解析CIDR失败: %v", err)
		}

		// 计算CIDR中的主机数
		ones, bits := ipNet.Mask.Size()
		hostBits := bits - ones
		if hostBits > 16 {
			totalTargets = 65536 // 限制最大主机数
		} else {
			totalTargets = 1 << hostBits
		}

		// 使用CIDR展开迭代器
		printInfo(fmt.Sprintf("扫描CIDR网段: %s (预计%d个主机)", addr, totalTargets))
		hostChan = IterateCIDR(addr)
	} else {
		// 单个域名或其他类型
		totalTargets = 1
		ch := make(chan Host, 1)
		ch <- host
		close(ch)
		hostChan = ch
	}

	// 创建带进度条的结果处理器
	processor, err := NewResultProcessorWithProgress(config.Output, totalTargets)
	if err != nil {
		return fmt.Errorf("创建结果处理器失败: %v", err)
	}
	defer processor.Close()

	// 启动并发扫描
	resultChan := ScanWithConcurrency(hostChan, geo)

	// 处理结果
	processor.ProcessResults(resultChan)

	return nil
}

// 分页显示结果
func showResultsPaginated(filename string) {
	// 读取符合条件的结果
	feasibleResults, err := loadFeasibleResults(filename)
	if err != nil {
		printError(fmt.Sprintf("加载结果失败: %v", err))
		return
	}

	if len(feasibleResults) == 0 {
		printInfo("没有找到符合条件的目标")
		return
	}

	pageSize := 10
	totalPages := (len(feasibleResults) + pageSize - 1) / pageSize
	currentPage := 1

	for {
		clearScreen()
		printBox([]string{
			"",
			fmt.Sprintf("                    ═══ Reality目标列表 (第%d/%d页) ═══", currentPage, totalPages),
			"",
			fmt.Sprintf("    总共找到 %d 个符合条件的目标", len(feasibleResults)),
			"",
		})

		// 显示当前页的结果
		start := (currentPage - 1) * pageSize
		end := start + pageSize
		if end > len(feasibleResults) {
			end = len(feasibleResults)
		}

		fmt.Printf("%-4s %-15s %-25s %-10s %-15s\n",
			"序号", "IP地址", "证书域名", "地理位置", "响应时间(ms)")
		fmt.Println(strings.Repeat("-", 75))

		for i := start; i < end; i++ {
			result := feasibleResults[i]
			fmt.Printf("%-4d %-15s %-25s %-10s %-15s\n",
				i+1,
				result[0],                     // IP
				truncateString(result[3], 25), // CERT_DOMAIN
				result[8],                     // GEO_CODE
				result[10],                    // RESPONSE_TIME_MS
			)
		}

		fmt.Println("\n操作选项:")
		if currentPage > 1 {
			fmt.Print("  [P] 上一页  ")
		}
		if currentPage < totalPages {
			fmt.Print("  [N] 下一页  ")
		}
		fmt.Print("  [Q] 返回")
		fmt.Print("\n请选择: ")

		input := getStringInput()
		switch strings.ToUpper(input) {
		case "P":
			if currentPage > 1 {
				currentPage--
			}
		case "N":
			if currentPage < totalPages {
				currentPage++
			}
		case "Q":
			return
		default:
			printError("无效的选择")
			pause()
		}
	}
}

// 加载符合条件的结果
func loadFeasibleResults(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewScanner(file)
	var results [][]string

	// 跳过头部
	if reader.Scan() {
		// 头部行
	}

	for reader.Scan() {
		line := reader.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 10 && parts[9] == "true" {
			results = append(results, parts)
		}
	}

	return results, nil
}

// 工具函数

// 清屏
func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

// 使用系统清屏命令
func clearScreenSystem() {
	// 尝试使用系统的clear命令
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		// 如果clear命令失败，使用ANSI转义序列
		fmt.Print("\033[2J\033[H")
	}
}

// 打印带边框的文本
func printBox(lines []string) {
	maxLen := 0
	for _, line := range lines {
		displayWidth := getDisplayWidth(line)
		if displayWidth > maxLen {
			maxLen = displayWidth
		}
	}

	if maxLen < 60 {
		maxLen = 60
	}

	// 顶部边框
	fmt.Print("╔")
	for i := 0; i < maxLen+2; i++ {
		fmt.Print("═")
	}
	fmt.Println("╗")

	// 内容
	for _, line := range lines {
		displayWidth := getDisplayWidth(line)
		padding := maxLen - displayWidth
		fmt.Printf("║ %s%s ║\n", line, strings.Repeat(" ", padding))
	}

	// 底部边框
	fmt.Print("╚")
	for i := 0; i < maxLen+2; i++ {
		fmt.Print("═")
	}
	fmt.Println("╝")
}

// 计算字符串的显示宽度（中文字符占2个宽度，英文字符占1个宽度）
func getDisplayWidth(s string) int {
	width := 0
	for _, r := range s {
		if r <= 127 {
			width++ // ASCII字符占1个宽度
		} else {
			width += 2 // 中文字符占2个宽度
		}
	}
	return width
}

// 获取整数输入
func getIntInput() int {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if num, err := strconv.Atoi(input); err == nil {
			return num
		}
		fmt.Print("请输入有效的数字: ")
	}
}

// 获取字符串输入
func getStringInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// 暂停等待用户按键
func pause() {
	fmt.Print("\n按回车键继续...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// 打印信息
func printInfo(msg string) {
	fmt.Printf("ℹ️  %s\n", msg)
}

// 打印成功信息
func printSuccess(msg string) {
	fmt.Printf("✅ %s\n", msg)
}

// 打印错误信息
func printError(msg string) {
	fmt.Printf("❌ %s\n", msg)
}

// isValidMask 验证子网掩码位数是否有效
func isValidMask(mask string) bool {
	if !strings.HasPrefix(mask, "/") {
		return false
	}
	
	maskStr := mask[1:] // 去掉/前缀
	maskBits, err := strconv.Atoi(maskStr)
	if err != nil {
		return false
	}
	
	// IPv4的有效掩码位数范围是0-32
	return maskBits >= 0 && maskBits <= 32
}

// calculateNetworkAddress 根据IP地址和子网掩码计算网络地址
func calculateNetworkAddress(ipStr, mask string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("无效的IP地址")
	}
	
	// 转换为IPv4
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("不是有效的IPv4地址")
	}
	
	// 解析掩码位数
	maskStr := mask[1:] // 去掉/前缀
	maskBits, err := strconv.Atoi(maskStr)
	if err != nil {
		return "", fmt.Errorf("无效的掩码位数")
	}
	
	// 创建子网掩码
	maskValue := net.CIDRMask(maskBits, 32)
	
	// 计算网络地址
	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip[i] & maskValue[i]
	}
	
	return network.String(), nil
}
