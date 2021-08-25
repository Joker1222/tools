// -------------------------------------------------------------------------
//    @FileName         ：    schan.go
//    @Author           ：    Joker
//    @Date             ：    2020-11-12
//    @Module           ：    tools
//    @Desc             :     可以叫同步管道也可以叫线程安全的管道
//   诞生原因 go的channel在发送端无法检查该channel是否已经关闭，如果继续写入则会引发panic
//   目前已知三种方法在发送端检查该管道是否已经关闭
//	 1.recover方式 (允许panic后自动恢复,有点暴力不推荐)
//   2.cgo方式查看close指针 （比较另类,麻烦）
//   3.读写加锁加变量 (注意:schan采用的方式，如果同步锁的力度较大,不适合使用schan,比较耗性能)
//
//   该管道使用规则: 可以定义为是一个有缓冲的安全管道,内部会加入计数器,记录当前缓冲区使用长度.
//   1.当前管道已满时，不允许继续写入，直接返回错误(避免写阻塞)
//   2.当前管道关闭时，不允许继续写入，直接返回错误(避免panic)
//   3.当前管道关闭时，不允许继续关闭，直接返回错误(避免panic)
//   4.支持查看当前可用空间
// -------------------------------------------------------------------------
package tools

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type SChan struct {
	tc      chan interface{} //truest channel
	isClose bool             //标记着是否已关闭
	s       int32            //总长度
	nl      int32            //当前缓冲数量     总长度-当前缓冲数量=剩余空闲空间
	mu      sync.Mutex
	desc    string
}

/**
 * @desc: 返回一个SChan实例
 * @param: 缓冲区大小
 * @return: 管道满会返回错误,管道已关闭会返回错误
 */
func NewSChan(size int32) *SChan {
	return &SChan{
		tc:      make(chan interface{}, size),
		isClose: false,
		s:       size,
		nl:      0}
}
func (p *SChan) SetDesc(s string) {
	p.desc = fmt.Sprintf("\x1b[31m%s\x1b[0m", s)
}
func (p *SChan) GetDesc() string {
	return p.desc
}

/**
 * @desc: 同步写数据
 * @param: 要写入的数据
 * @return: 管道满会返回错误,管道已关闭会返回错误
 */
func (p *SChan) Write(v interface{}) error {
	p.mu.Lock() //同一时刻只允许一个协程进行写操作
	defer p.mu.Unlock()
	if p.nl == p.s { //
		return fmt.Errorf("SChan is full ! Last write desc : %v", v, p.desc)
	}
	if p.isClose {
		return fmt.Errorf("SChan is closed ! Last write desc : %v", v, p.desc)
	}
	p.tc <- v
	atomic.AddInt32(&p.nl, 1) //缓冲区数量加1  原子操作+1
	return nil
}

/**
 * @desc: 读数据,允许并发读,允许读时管道被关闭
 * @param: nil
 * @return: 1.读到的数据 2. true代表成功,false代表管道被关闭
 */
func (p *SChan) Read() (interface{}, bool) { //允许并发读,这里不加锁,并且读写间不锁
	v, ok := <-p.tc
	if ok { //读到了才-1
		atomic.AddInt32(&p.nl, -1) //缓冲区数量减1    原子操作 -1
	}
	return v, ok
}

/**
 * @desc: 主动关闭该管道 ps:Close()和Read()间没有锁的,如果Read()时Close()，Read会返回(nil,false) (这是golang的机制)
 * @param: nil
 * @return: 如果该管道已经关闭则会返回错误,不允许重复关闭
 */
func (p *SChan) Close() error { //已经关闭
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isClose {
		close(p.tc)
		p.isClose = true
		return nil
	}
	return fmt.Errorf("this channel is closed . ")
}

/**
 * @desc: 返回管道当前剩余空间，如果管道已关闭则返回-1
 * @param: nil
 * @return: 剩余空间大小
 */
func (p *SChan) GetAvail() int32 { //如果管道关闭则返回-1 ,代表管道不可用
	if p.isClose {
		return -1
	}
	return p.s - p.nl
}
