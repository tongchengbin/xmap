package utils

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Progress 表示一个进度跟踪器
type Progress struct {
	name      string
	total     int
	completed int32
	mutex     sync.Mutex
	stop      chan struct{}
}

// NewProgress 创建一个新的进度跟踪器
func NewProgress(name string, total int) *Progress {
	return &Progress{
		name:  name,
		total: total,
		stop:  make(chan struct{}),
	}
}

// Start 开始显示进度
func (p *Progress) Start() {
	ticker := time.NewTicker(5 * time.Second) // 每秒更新一次，与Nuclei类似
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.printProgress()
		case <-p.stop:
			p.printProgress()
			return
		}
	}
}

// Stop 停止显示进度
func (p *Progress) Stop() {
	close(p.stop)
}

// Increment 增加已完成的数量
func (p *Progress) Increment() {
	atomic.AddInt32(&p.completed, 1)
}

// printProgress 打印当前进度
func (p *Progress) printProgress() {
	completed := atomic.LoadInt32(&p.completed)
	percentage := float64(completed) / float64(p.total) * 100

	// 计算成功和失败数量（简化实现）
	success := completed
	failed := 0

	// 使用gologger打印进度信息，类似Nuclei的风格
	gologger.Info().Msgf("扫描进度: [%d/%d] %.2f%% | 成功: \x1b[32m%d\x1b[0m | 失败: \x1b[31m%d\x1b[0m",
		completed,
		p.total,
		percentage,
		success,
		failed)
}
