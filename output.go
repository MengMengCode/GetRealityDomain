package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)


// CSVWriter CSV输出写入器
type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
}

// NewCSVWriter 创建新的CSV写入器
func NewCSVWriter(filename string) (*CSVWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("创建输出文件失败: %v", err)
	}
	
	writer := csv.NewWriter(file)
	
	// 写入CSV头部
	headers := []string{
		"IP",
		"ORIGIN", 
		"PORT",
		"CERT_DOMAIN",
		"CERT_ISSUER",
		"TLS_VERSION",
		"ALPN",
		"CURVE",
		"GEO_CODE",
		"FEASIBLE",
		"RESPONSE_TIME_MS",
		"ERROR",
		"SCAN_TIME",
	}
	
	if err := writer.Write(headers); err != nil {
		file.Close()
		return nil, fmt.Errorf("写入CSV头部失败: %v", err)
	}
	
	writer.Flush()
	
	return &CSVWriter{
		file:   file,
		writer: writer,
	}, nil
}

// WriteResult 写入扫描结果
func (cw *CSVWriter) WriteResult(result ScanResult) error {
	record := []string{
		result.IP,
		result.Origin,
		strconv.Itoa(result.Port),
		result.CertDomain,
		result.CertIssuer,
		result.TLSVersion,
		result.ALPN,
		result.Curve,
		result.GeoCode,
		strconv.FormatBool(result.Feasible),
		strconv.FormatInt(result.ResponseTime, 10),
		result.Error,
		time.Now().Format("2006-01-02 15:04:05"),
	}
	
	if err := cw.writer.Write(record); err != nil {
		return fmt.Errorf("写入CSV记录失败: %v", err)
	}
	
	cw.writer.Flush()
	return nil
}

// Close 关闭CSV写入器
func (cw *CSVWriter) Close() error {
	if cw.writer != nil {
		cw.writer.Flush()
	}
	if cw.file != nil {
		return cw.file.Close()
	}
	return nil
}

// ResultProcessor 结果处理器
type ResultProcessor struct {
	csvWriter     *CSVWriter
	totalCount    int
	feasibleCount int
	errorCount    int
	startTime     time.Time
	totalTargets  int // 总目标数
	lastUpdate    time.Time
}

// NewResultProcessor 创建新的结果处理器
func NewResultProcessor(outputFile string) (*ResultProcessor, error) {
	csvWriter, err := NewCSVWriter(outputFile)
	if err != nil {
		return nil, err
	}
	
	return &ResultProcessor{
		csvWriter: csvWriter,
		startTime: time.Now(),
	}, nil
}

// NewResultProcessorWithProgress 创建带进度的结果处理器
func NewResultProcessorWithProgress(outputFile string, totalTargets int) (*ResultProcessor, error) {
	csvWriter, err := NewCSVWriter(outputFile)
	if err != nil {
		return nil, err
	}
	
	return &ResultProcessor{
		csvWriter:    csvWriter,
		startTime:    time.Now(),
		totalTargets: totalTargets,
		lastUpdate:   time.Now(),
	}, nil
}

// ProcessResults 处理扫描结果
func (rp *ResultProcessor) ProcessResults(resultChan <-chan ScanResult) {
	// 显示初始状态
	fmt.Printf("扫描进行中...\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	
	// 初始化进度条显示
	rp.printCurrentStatus()
	
	for result := range resultChan {
		rp.totalCount++
		
		// 统计计数和输出日志
		if result.Error != "" {
			rp.errorCount++
			// 不输出错误日志，减少噪音
		} else if result.Feasible {
			rp.feasibleCount++
			
			// 只有通过所有检测的结果才写入CSV文件
			if err := rp.csvWriter.WriteResult(result); err != nil {
				printError(fmt.Sprintf("写入结果失败: %v", err))
				continue
			}
			
			// 只输出成功日志到进度条下面
			fmt.Printf("✅ %s (%s) - %s [%dms]\n",
				result.IP, result.CertDomain, result.GeoCode, result.ResponseTime)
			
			// 检查是否达到最大结果数
			if scanControl.StopOnMax && rp.feasibleCount >= scanControl.MaxResults {
				fmt.Printf("\n🎉 已找到 %d 个符合条件的目标，达到设定上限，停止扫描\n", rp.feasibleCount)
				break
			}
		} else {
			// 不输出不符合条件的日志，减少噪音
		}
		
		// 每3秒更新一次状态信息
		if time.Since(rp.lastUpdate) >= 3*time.Second {
			rp.printCurrentStatus()
			rp.lastUpdate = time.Now()
		}
	}
	
	// 最终更新进度条
	rp.printCurrentStatus()
	
	// 输出最终统计
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	rp.printFinalStats()
}

// printCurrentStatus 打印当前状态信息
func (rp *ResultProcessor) printCurrentStatus() {
	// 计算进度百分比
	var percentage float64
	if rp.totalTargets > 0 {
		percentage = float64(rp.totalCount) / float64(rp.totalTargets) * 100
	}
	
	// 计算进度条长度（总共50个字符）
	const progressBarLength = 50
	filledLength := int(percentage / 100 * progressBarLength)
	
	// 构建进度条
	progressBar := ""
	for i := 0; i < progressBarLength; i++ {
		if i < filledLength {
			progressBar += "▋"
		} else {
			progressBar += " "
		}
	}
	
	// 向上移动3行，清除进度条区域
	fmt.Print("\033[3A")
	
	// 清除并显示进度条
	fmt.Printf("\033[K[%s] %.1f%%\n", progressBar, percentage)
	
	// 清除并显示统计信息
	fmt.Printf("\033[K已扫描: %d | 发现合规: %d | 错误: %d\n",
		rp.totalCount, rp.feasibleCount, rp.errorCount)
	
	// 清除并显示剩余信息
	if rp.totalTargets > 0 {
		remaining := rp.totalTargets - rp.totalCount
		fmt.Printf("\033[K剩余: %d\n", remaining)
	} else {
		fmt.Printf("\033[K\n")
	}
}

// printProgress 打印进度信息
func (rp *ResultProcessor) printProgress() {
	printInfo(fmt.Sprintf("已扫描: %d, 符合条件: %d, 错误: %d",
		rp.totalCount, rp.feasibleCount, rp.errorCount))
}

// printFinalStats 打印最终统计信息
func (rp *ResultProcessor) printFinalStats() {
	elapsed := time.Since(rp.startTime)
	
	fmt.Printf("\n扫描完成！\n")
	fmt.Printf("总扫描数量: %d\n", rp.totalCount)
	fmt.Printf("符合条件数: %d (%.1f%%)\n", rp.feasibleCount,
		float64(rp.feasibleCount)/float64(rp.totalCount)*100)
	fmt.Printf("错误数量: %d (%.1f%%)\n", rp.errorCount,
		float64(rp.errorCount)/float64(rp.totalCount)*100)
	fmt.Printf("扫描用时: %v\n", elapsed.Round(time.Second))
	
	// 根据结果数量显示不同的消息
	if rp.feasibleCount > 0 {
		fmt.Printf("\n🎉 找到 %d 个符合Reality协议要求的目标！\n", rp.feasibleCount)
		fmt.Printf("详细结果已保存到CSV文件中。\n")
	} else {
		fmt.Printf("\nℹ️  没有找到符合条件的目标\n")
	}
}

// Close 关闭结果处理器
func (rp *ResultProcessor) Close() error {
	if rp.csvWriter != nil {
		return rp.csvWriter.Close()
	}
	return nil
}

// PrintRealityTargets 打印符合Reality要求的目标
func PrintRealityTargets(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()
	
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("读取CSV文件失败: %v", err)
	}
	
	if len(records) < 2 {
		printInfo("没有找到扫描结果")
		return nil
	}
	
	// 查找符合条件的记录
	var feasibleTargets [][]string
	for i, record := range records {
		if i == 0 { // 跳过头部
			continue
		}
		
		if len(record) >= 10 && record[9] == "true" { // FEASIBLE字段
			feasibleTargets = append(feasibleTargets, record)
		}
	}
	
	if len(feasibleTargets) == 0 {
		printInfo("没有找到符合Reality要求的目标")
		return nil
	}
	
	// 打印结果
	fmt.Println()
	printBox([]string{
		"",
		"                    ═══ Reality目标列表 ═══",
		"",
		fmt.Sprintf("    找到 %d 个符合条件的目标:", len(feasibleTargets)),
		"",
	})
	
	fmt.Printf("%-15s %-25s %-10s %-20s %-15s\n", 
		"IP地址", "证书域名", "地理位置", "证书颁发者", "响应时间(ms)")
	fmt.Println(strings.Repeat("-", 85))
	
	for _, record := range feasibleTargets {
		fmt.Printf("%-15s %-25s %-10s %-20s %-15s\n",
			record[0],  // IP
			truncateString(record[3], 25), // CERT_DOMAIN
			record[8],  // GEO_CODE
			truncateString(record[4], 20), // CERT_ISSUER
			record[10], // RESPONSE_TIME_MS
		)
	}
	
	fmt.Println()
	return nil
}

// truncateString 截断字符串到指定长度
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ExportRealityConfig 导出Reality配置文件
func ExportRealityConfig(filename string, configFile string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()
	
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("读取CSV文件失败: %v", err)
	}
	
	// 查找符合条件的记录
	var feasibleTargets [][]string
	for i, record := range records {
		if i == 0 { // 跳过头部
			continue
		}
		
		if len(record) >= 10 && record[9] == "true" { // FEASIBLE字段
			feasibleTargets = append(feasibleTargets, record)
		}
	}
	
	if len(feasibleTargets) == 0 {
		return fmt.Errorf("没有找到符合条件的目标")
	}
	
	// 创建配置文件
	configFileHandle, err := os.Create(configFile)
	if err != nil {
		return fmt.Errorf("创建配置文件失败: %v", err)
	}
	defer configFileHandle.Close()
	
	// 写入Reality配置模板
	fmt.Fprintf(configFileHandle, "# Reality目标配置文件\n")
	fmt.Fprintf(configFileHandle, "# 生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(configFileHandle, "# 总共找到 %d 个符合条件的目标\n\n", len(feasibleTargets))
	
	for i, record := range feasibleTargets {
		fmt.Fprintf(configFileHandle, "# 目标 %d\n", i+1)
		fmt.Fprintf(configFileHandle, "dest: %s:443\n", record[0]) // IP
		fmt.Fprintf(configFileHandle, "serverNames: [\"%s\"]\n", record[3]) // CERT_DOMAIN
		fmt.Fprintf(configFileHandle, "# 地理位置: %s\n", record[8]) // GEO_CODE
		fmt.Fprintf(configFileHandle, "# 证书颁发者: %s\n", record[4]) // CERT_ISSUER
		fmt.Fprintf(configFileHandle, "# 响应时间: %sms\n\n", record[10]) // RESPONSE_TIME_MS
	}
	
	printSuccess(fmt.Sprintf("Reality配置已导出到: %s", configFile))
	return nil
}