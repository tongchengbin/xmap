package output

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"

	"github.com/tongchengbin/xmap/pkg/model"
)

// Outer 定义结果输出接口
type Outer interface {
	// Output 输出扫描结果
	Output(results *model.ScanResult) error
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
func (o *ConsoleOuter) Output(results *model.ScanResult) error {
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
func (o *ConsoleOuter) displayResults(result *model.ScanResult) {
	gologger.Print().Msgf("%s://%s:%d components: %s\n", result.Service, result.Target.IP, result.Target.Port, ComponentsToString(result.Components))
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
func (o *JSONOuter) Output(results *model.ScanResult) error {
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
func (o *JSONOuter) printJSON(results *model.ScanResult) {
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
func (o *CSVOuter) Output(results *model.ScanResult) error {
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
func (o *CSVOuter) printCSV(results *model.ScanResult) {
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
	for _, component := range components {
		for key, value := range component {
			result += fmt.Sprintf("%s: %s\n", key, value)
		}
	}
	return result
}
