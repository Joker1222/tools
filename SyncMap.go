// -------------------------------------------------------------------------
//    @FileName         ：    SyncMap.go
//    @Author           ：    Joker
//    @Date             ：    2019-11-22
//    @Module           ：    SyncMap
//    @Desc             :     线程安全的Map,可放心食用
// -------------------------------------------------------------------------
package tools

import "sync"

type Map struct {
	m sync.Map
	l int
}

func (p *Map) Len() int {
	return p.l
}
func (p *Map) Store(key, value interface{}) {
	p.m.Store(key, value)
	p.l++
}
func (p *Map) Delete(key interface{}) {
	p.m.Delete(key)
	p.l--
}

func (p *Map) Load(key interface{}) (value interface{}, ok bool) {
	return p.m.Load(key)
}

func (p *Map) LoadOrStore(key, value interface{}) (actual interface{}, loaded bool) {
	v, ok := p.m.LoadOrStore(key, value)
	if !ok {
		p.l++
	}
	return v, ok
}

func (p *Map) Range(f func(key, value interface{}) bool) {
	p.m.Range(f)
}
func (p *Map) Clear() {
	p.m.Range(func(k, v interface{}) bool {
		p.m.Delete(k)
		return true
	})
}
