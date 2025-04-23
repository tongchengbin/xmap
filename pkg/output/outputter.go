package output

import (
	"fmt"
	"os"

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
}

// NewConsoleOuter 创建一个新的控制台输出器
func NewConsoleOuter(outputFile string, silent bool) *ConsoleOuter {
	return &ConsoleOuter{
		OutputFile: outputFile,
		Silent:     silent,
	}
}

// Output 实现Outer接口
func (o *ConsoleOuter) Output(results *types.ScanResult) error {
	if o.Silent {
		return nil
	}

	// 如果指定了输出文件，则输出到文件
	if o.OutputFile != "" {
		file, err := os.Create(o.OutputFile)
		if err != nil {
			return err
		}
		defer file.Close()

		// 重定向标准输出到文件
		oldStdout := os.Stdout
		os.Stdout = file
		o.displayResults(results)
		os.Stdout = oldStdout
		return nil
	}

	// 否则输出到控制台
	o.displayResults(results)
	return nil
}

// displayResults 显示结果
func (o *ConsoleOuter) displayResults(result *types.ScanResult) {
	// 格式化组件信息
	componentsStr := ""
	for i, component := range result.Components {
		if i > 0 {
			componentsStr += ", "
		}
		name, hasName := component["name"]
		version, hasVersion := component["version"]

		if hasName {
			componentsStr += fmt.Sprintf("%v", name)
			if hasVersion {
				componentsStr += fmt.Sprintf(" %v", version)
			}
		}
	}

	// 使用Nuclei风格的输出格式
	// 构建目标URL
	targetURL := fmt.Sprintf("%s://%s:%d", result.Service, result.Target.Host, result.Target.Port)

	// 根据服务类型选择不同的颜色
	serviceColor := "\x1b[32m" // 默认绿色
	if result.Service == "https" || result.Service == "ssl" {
		serviceColor = "\x1b[36m" // https/ssl使用青色
	} else if result.Service == "http" {
		serviceColor = "\x1b[33m" // http使用黄色
	}

	// 打印格式化的结果
	gologger.Info().Msgf("[%s] %s\x1b[0m [\x1b[36m%s\x1b[0m] [\x1b[31m%.2fs\x1b[0m]",
		serviceColor+result.Service,
		targetURL,
		componentsStr,
		result.Duration)
}

// JSONOuter JSON输出实现
type JSONOuter struct {
	OutputFile string
}

// NewJSONOuter 创建一个新的JSON输出器
func NewJSONOuter(outputFile string) *JSONOuter {
	return &JSONOuter{
		OutputFile: outputFile,
	}
}

// Output 实现Outputter接口
func (o *JSONOuter) Output(results *types.ScanResult) error {
	// 如果指定了输出文件，则输出到文件
	if o.OutputFile != "" {
		file, err := os.Create(o.OutputFile)
		if err != nil {
			return err
		}
		defer file.Close()

		// 重定向标准输出到文件
		oldStdout := os.Stdout
		os.Stdout = file
		o.printJSON(results)
		os.Stdout = oldStdout
		return nil
	}

	// 否则输出到控制台
	o.printJSON(results)
	return nil
}

// printJSON 打印JSON格式结果
func (o *JSONOuter) printJSON(results *types.ScanResult) {
	fmt.Println(results.JSON())
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
		file, err := os.Create(o.OutputFile)
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
