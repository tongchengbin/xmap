package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Task 表示工作任务接口
type Task interface {
	// Execute 执行任务
	Execute(ctx context.Context) (interface{}, error)
}

// TaskFunc 任务函数类型
type TaskFunc func(ctx context.Context) (interface{}, error)

// Execute 实现 Task 接口
func (f TaskFunc) Execute(ctx context.Context) (interface{}, error) {
	return f(ctx)
}

// Result 表示任务执行结果
type Result struct {
	// 任务索引
	Index int
	// 任务结果
	Value interface{}
	// 错误信息
	Error error
	// 执行时间
	Duration time.Duration
}

// WorkerPool 工作池
type WorkerPool struct {
	// 工作协程数量
	workerCount int
	// 任务通道
	taskChan chan *taskWrapper
	// 结果通道
	resultChan chan *Result
	// 等待组
	wg sync.WaitGroup
	// 已完成任务数
	completedTasks int64
	// 总任务数
	totalTasks int64
	// 上下文
	ctx context.Context
	// 取消函数
	cancel context.CancelFunc
	// 是否已启动
	started bool
	// 互斥锁
	mu sync.Mutex
}

// taskWrapper 任务包装器
type taskWrapper struct {
	// 任务索引
	index int
	// 任务
	task Task
}

// NewWorkerPool 创建新的工作池
func NewWorkerPool(workerCount int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = 10
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workerCount: workerCount,
		taskChan:    make(chan *taskWrapper, workerCount*2),
		resultChan:  make(chan *Result, workerCount*2),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start 启动工作池
func (p *WorkerPool) Start() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return
	}

	// 启动工作协程
	p.wg.Add(p.workerCount)
	for i := 0; i < p.workerCount; i++ {
		go p.worker()
	}

	p.started = true
}

// Stop 停止工作池
func (p *WorkerPool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		return
	}

	// 取消上下文
	p.cancel()

	// 关闭任务通道
	close(p.taskChan)

	// 等待所有工作协程完成
	p.wg.Wait()

	// 关闭结果通道
	close(p.resultChan)

	p.started = false
}

// AddTask 添加任务
func (p *WorkerPool) AddTask(index int, task Task) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		p.Start()
	}

	atomic.AddInt64(&p.totalTasks, 1)
	p.taskChan <- &taskWrapper{index: index, task: task}
}

// AddTaskFunc 添加任务函数
func (p *WorkerPool) AddTaskFunc(index int, taskFunc TaskFunc) {
	p.AddTask(index, taskFunc)
}

// Results 获取结果通道
func (p *WorkerPool) Results() <-chan *Result {
	return p.resultChan
}

// WaitAll 等待所有任务完成
func (p *WorkerPool) WaitAll() {
	// 等待所有任务被添加到任务通道
	for {
		completedTasks := atomic.LoadInt64(&p.completedTasks)
		totalTasks := atomic.LoadInt64(&p.totalTasks)

		if completedTasks >= totalTasks && totalTasks > 0 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// worker 工作协程
func (p *WorkerPool) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			// 上下文已取消
			return
		case wrapper, ok := <-p.taskChan:
			if !ok {
				// 任务通道已关闭
				return
			}

			// 执行任务
			startTime := time.Now()
			value, err := wrapper.task.Execute(p.ctx)
			duration := time.Since(startTime)

			// 发送结果
			p.resultChan <- &Result{
				Index:    wrapper.index,
				Value:    value,
				Error:    err,
				Duration: duration,
			}

			// 更新已完成任务数
			atomic.AddInt64(&p.completedTasks, 1)
		}
	}
}

// Progress 获取进度信息
func (p *WorkerPool) Progress() (completed, total int64) {
	completed = atomic.LoadInt64(&p.completedTasks)
	total = atomic.LoadInt64(&p.totalTasks)
	return
}

// ExecuteBatch 批量执行任务
func ExecuteBatch(ctx context.Context, tasks []Task, workerCount int) []*Result {
	if workerCount <= 0 {
		workerCount = min(len(tasks), 10)
	}

	// 创建工作池
	pool := NewWorkerPool(workerCount)
	defer pool.Stop()

	// 添加任务
	for i, task := range tasks {
		pool.AddTask(i, task)
	}

	// 收集结果
	results := make([]*Result, len(tasks))
	for i := 0; i < len(tasks); i++ {
		select {
		case <-ctx.Done():
			// 上下文已取消
			return results
		case result := <-pool.Results():
			results[result.Index] = result
		}
	}

	return results
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
