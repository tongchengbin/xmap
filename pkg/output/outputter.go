package output

import (
	"bufio"
	"fmt"
	"github.com/logrusorgru/aurora"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"

	"github.com/tongchengbin/xmap/pkg/types"
)

// Outer 定义结果输出接口
type Outer interface {
	// Output 输出扫描结果
	Output(results *types.ScanResult) error
}

// ConsoleOuter 控制台输出实现
type ConsoleOuter struct {
	OutputFile string
	Silent     bool

	// 文件写入相关
	file   *os.File
	writer *bufio.Writer
	mutex  *sync.Mutex
}

// NewConsoleOuter 创建一个新的控制台输出器
func NewConsoleOuter(outputFile string, silent bool) *ConsoleOuter {
	outer := &ConsoleOuter{
		OutputFile: outputFile,
		Silent:     silent,
		mutex:      &sync.Mutex{},
	}

	// 如果指定了输出文件，初始化文件写入器
	if outputFile != "" {
		// 使用 O_TRUNC 模式，如果文件存在则先清空
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			outer.file = file
			outer.writer = bufio.NewWriter(file)
		} else {
			gologger.Error().Msgf("Could not create output file '%s': %s", outputFile, err)
		}
	}

	return outer
}

// Output 实现Outer接口
func (o *ConsoleOuter) Output(results *types.ScanResult) error {
	if o.Silent {
		return nil
	}

	// 格式化组件信息
	var componentsList []string
	for _, component := range results.Components {
		name, hasName := component["name"]
		if !hasName {
			continue
		}
		si := fmt.Sprintf("%v", name)
		for k, v := range component {
			if k != "name" {
				si += fmt.Sprintf(" %v=%v", k, v)
			}
		}
		componentsList = append(componentsList, aurora.Cyan(si).String())
	}
	componentsStr := strings.Join(componentsList, "|")
	// 构建目标URL
	targetURL := fmt.Sprintf("%s://%s:%d", results.Service, results.Target.Host, results.Target.Port)
	outputFields := []string{fmt.Sprintf("[%s]", aurora.Green(targetURL)),

		componentsStr}
	if title, ok := results.Banner["title"]; ok {
		outputFields = append(outputFields, fmt.Sprintf("[%s]", aurora.Green(title)))
	}
	outputFields = append(outputFields, fmt.Sprintf("[%s]", aurora.Green(results.Duration).String()))
	outputStr := strings.Join(outputFields, " ")
	// 如果有输出文件，写入文件
	if o.file != nil && o.writer != nil {
		o.mutex.Lock()
		defer o.mutex.Unlock()

		// 写入到缓冲区
		_, err := o.writer.WriteString(outputStr)
		if err != nil {
			return err
		}

		// 立即刷新缓冲区到文件
		err = o.writer.Flush()
		if err != nil {
			return err
		}
	} else {
		// 输出到控制台
		fmt.Print(outputStr)
	}

	return nil
}

// Close 关闭输出器
func (o *ConsoleOuter) Close() error {
	if o.file != nil {
		// 先刷新缓冲区
		if o.writer != nil {
			o.mutex.Lock()
			err := o.writer.Flush()
			o.mutex.Unlock()
			if err != nil {
				return err
			}
		}

		// 关闭文件
		err := o.file.Close()
		o.file = nil
		o.writer = nil
		return err
	}
	return nil
}

// JSONOuter JSON输出实现
type JSONOuter struct {
	OutputFile string

	// 文件写入相关
	file   *os.File
	writer *bufio.Writer
	mutex  *sync.Mutex
}

// NewJSONOuter 创建一个新的JSON输出器
func NewJSONOuter(outputFile string) *JSONOuter {
	outer := &JSONOuter{
		OutputFile: outputFile,
		mutex:      &sync.Mutex{},
	}

	// 如果指定了输出文件，初始化文件写入器
	if outputFile != "" {
		// 使用 O_TRUNC 模式，如果文件存在则先清空
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			outer.file = file
			outer.writer = bufio.NewWriter(file)
		} else {
			gologger.Error().Msgf("Could not create output file '%s': %s", outputFile, err)
		}
	}

	return outer
}

// Output 实现Outputter接口
func (o *JSONOuter) Output(results *types.ScanResult) error {
	// 获取JSON字符串
	jsonStr := results.JSON() + "\n"

	// 如果有输出文件，写入文件
	if o.file != nil && o.writer != nil {
		o.mutex.Lock()
		defer o.mutex.Unlock()

		// 写入到缓冲区
		_, err := o.writer.WriteString(jsonStr)
		if err != nil {
			return err
		}

		// 立即刷新缓冲区到文件
		err = o.writer.Flush()
		if err != nil {
			return err
		}
	} else {
		// 输出到控制台
		fmt.Print(jsonStr)
	}

	return nil
}

// Close 关闭输出器
func (o *JSONOuter) Close() error {
	if o.file != nil {
		// 先刷新缓冲区
		if o.writer != nil {
			o.mutex.Lock()
			err := o.writer.Flush()
			o.mutex.Unlock()
			if err != nil {
				return err
			}
		}

		// 关闭文件
		err := o.file.Close()
		o.file = nil
		o.writer = nil
		return err
	}
	return nil
}

// CSVOuter CSV输出实现
type CSVOuter struct {
	OutputFile string
}

// NewCSVOuter 创建一个新的CSV输出器
func NewCSVOuter(outputFile string) *CSVOuter {
	return &CSVOuter{
		OutputFile: outputFile,
	}
}

// Output 实现Outer接口
func (o *CSVOuter) Output(results *types.ScanResult) error {
	// 如果指定了输出文件，则输出到文件
	if o.OutputFile != "" {
		// 使用 O_APPEND 模式打开文件，如果文件不存在则创建
		file, err := os.OpenFile(o.OutputFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer file.Close()

		// 重定向标准输出到文件
		oldStdout := os.Stdout
		os.Stdout = file
		o.printCSV(results)
		os.Stdout = oldStdout
		return nil
	}

	// 否则输出到控制台
	o.printCSV(results)
	return nil
}

// printCSV 打印CSV格式结果
func (o *CSVOuter) printCSV(results *types.ScanResult) {
	// 打印CSV头
	fmt.Println("IP,Port,Protocol,Service,MatchedProbe,MatchedService,Duration")
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func ComponentsToString(components []map[string]interface{}) string {
	var result string
	for i, component := range components {
		if i > 0 {
			result += ", "
		}

		name, hasName := component["name"]
		version, hasVersion := component["version"]

		if hasName {
			result += fmt.Sprintf("%v", name)
			if hasVersion {
				result += fmt.Sprintf(" %v", version)
			}
		}
	}
	return result
}
