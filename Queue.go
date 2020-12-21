// -------------------------------------------------------------------------
//    @FileName         ：    Queue.go
//    @Author           ：    Joker
//    @Date             ：    2019-11-22
//    @Module           ：    Queue
//    @Desc             :     先进后出队列,堆内存,非线程安全
// -------------------------------------------------------------------------
package tools

type Queue struct {
	head *node
	tail *node
	len int32
}

type node struct {
	next  *node
	Value interface{}
}

func NewQueue() *Queue {
	return &Queue{nil, nil,0}
}

func (p *Queue) Push(Value interface{}) {
	n := &node{nil, Value}
	if p.head == nil {
		p.head = n
	} else {
		p.tail.next = n
	}
	p.tail = n
	p.len++
}

func (p *Queue) Pop() interface{} {
	if p.head == nil {
		return nil
	}
	r := p.head.Value
	p.head = p.head.next
	p.len--
	return r
}

/* func (p *Queue) Clear() {
	p = nil
} */

/* func (p *Queue) Remove(val interface{}) {
	pTmp := p.head
	for {
		if pTmp == nil {
			break
		} else {
			if p
		}
		pTmp = pTmp.next
	}
} */

func (p *Queue) Len() int32 {
	return p.len
}
