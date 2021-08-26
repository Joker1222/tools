package tools

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//加载Json 参数1 文件名 参数2 结构体地址
func LoadJSONConfig(filename string, JSONConfig interface{}) error {
	file, err := os.Open(filename) // For read access.
	if err != nil {
		return fmt.Errorf("open %s err:%s", filename, err.Error())
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Errorf("readAll %s err:%s", filename, err.Error())
	}
	err = json.Unmarshal(data, &JSONConfig)
	if err != nil {
		return fmt.Errorf("json.Unmarshal %s err:%s", filename, err.Error())
	}
	return nil
}

//加载XML 参数1 文件名 参数2 结构体地址
func LoadXMLConfig(filename string, XMLConfig interface{}) error {
	file, err := os.Open(filename) // For read access.
	if err != nil {
		return fmt.Errorf("open %s err:%s", filename, err.Error())
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Errorf("readAll %s err:%s", filename, err.Error())
	}
	err = xml.Unmarshal(data, &XMLConfig)
	if err != nil {
		return fmt.Errorf("xml.Unmarshal %s err:%s", filename, err.Error())
	}
	return nil
}

//随机一个int64
func RandInt64(min, max int64) int64 {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int63n(max-min) + min
}

//随机一个int
func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}

//返回调用栈信息
func CallFuncName(skip int) string {
	pc, path, line, _ := runtime.Caller(skip)
	return "\n[Call:" + runtime.FuncForPC(pc).Name() + "]\n[Path:" + path + "]\n[line:" + strconv.Itoa(line) + "]"
}

//一次生成若干不同的随机数 数组形式返回
func GenerateRandomNumber(start int, end int, count int) []int {
	//范围检查
	if end < start || (end-start) < count {
		return nil
	}
	//存放结果的slice
	nums := make([]int, 0)
	//随机数生成器，加入时间戳保证每次生成的随机数不一样
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(nums) < count {
		//生成随机数
		num := r.Intn((end - start)) + start
		//查重
		exist := false
		for _, v := range nums {
			if v == num {
				exist = true
				break
			}
		}
		if !exist {
			nums = append(nums, num)
		}
	}
	return nums
}

//Uint32ToBytes 整形转换成字节 大端序
func Uint32ToBytesBigEndian(n uint32) []byte {
	x := uint32(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

//BytesToUint32 字节转换成整形 大端序
func BytesToUint32BigEndian(b []byte) uint32 {
	bytesBuffer := bytes.NewBuffer(b)
	var x uint32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return x
}

//BytesToInt32
func BytesToInt32BigEndian(b []byte) int32 {
	bytesBuffer := bytes.NewBuffer(b)
	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return x
}

//BytesToUint32 字节转换成整形 小端序
func BytesToUint32LittleEndian(b []byte) uint32 {
	bytesBuffer := bytes.NewBuffer(b)

	var x uint32
	binary.Read(bytesBuffer, binary.LittleEndian, &x)
	return x
}

func BytesToInt32LittleEndian(b []byte) int32 {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.LittleEndian, &x)
	return x
}

//Int16ToBytes 整形转换成字节
func Int16ToBytesBigEndian(n int) []byte {
	x := uint16(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

//BytesToInt16 字节转换成整形
func BytesToInt16BigEndian(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x uint16
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}
func Int64ToBytesBigEndian(i int64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToInt64BigEndian(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}

//UintToBytes 整形转换成字节
func UintToBytesBigEndian(n uint32, nSize int) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	if nSize == 2 {
		x := uint16(n)
		binary.Write(bytesBuffer, binary.BigEndian, x)
	} else if nSize == 4 {
		x := uint32(n)
		binary.Write(bytesBuffer, binary.BigEndian, x)
	}
	return bytesBuffer.Bytes()
}
func Int32ToBytesBigEndian(n int32) []byte {

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, n)
	return bytesBuffer.Bytes()
}
func Bar(percentage int, w int) {
	str1 := "[" + strconv.Itoa(percentage) + "%]["
	str2 := "="
	str3 := ">]"
	fmt.Printf("\r")
	if percentage != 0 {
		str2 = strings.Repeat("=", (w-10)*percentage/100)
	}
	fmt.Printf("%s", str1+str2+str3)
}

//CSV 一次读取所有行
func CSV_ReadAllLineWithFD(fd *os.File) [][]string {
	var Content [][]string
	fd.Seek(0, io.SeekStart)
	r := csv.NewReader(fd)
	//针对大文件，一行一行的读取文件
	for {
		row, err := r.Read()
		//字段必须全部对其才能读出来
		/* if err != nil && err != io.EOF {
			log.Fatalf("can not read, err is %+v", err)
		} */
		if err == io.EOF {
			break
		}
		Content = append(Content, row)
	}
	return Content
}

//write One line at a time 一次写一行
func CSV_WriteOneLineWithFD(strOneLine []string, fd *os.File) {
	//这样可以追加写
	fd.Seek(0, io.SeekEnd)
	w := csv.NewWriter(fd)
	//设置属性
	w.Comma = ','
	w.UseCRLF = true
	err := w.Write(strOneLine)
	if err != nil {
		log.Print("can not write, err is %+v", err)
		//SafeExit(1)
	}
	//这里必须刷新，才能将数据写入文件。
	w.Flush()
}

//一次写多行
func CSV_WriteMuchLineWithFD(Content [][]string, fd *os.File) {
	fd.Seek(0, io.SeekStart)
	w := csv.NewWriter(fd)
	//设置属性
	w.Comma = ','
	w.UseCRLF = true
	//一次写入多行
	w.WriteAll(Content)
	w.Flush()
}

func StringToBool(s string) bool {
	if s == "true" {
		return true
	} else {
		return false
	}
}

//bool转string
func BoolToString(b bool) string {
	if b {
		return "true"
	} else {
		return "false"
	}
}

//判断文件是否存在
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// easy atoi
func Atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func Atoi32(s string) int32 {
	n, _ := strconv.Atoi(s)
	return int32(n)
}
func Atoi64(s string) int64 {
	n, _ := strconv.Atoi(s)
	return int64(n)
}
func Atou32(s string) uint32 {
	n, _ := strconv.Atoi(s)
	return uint32(n)
}
func Atou64(s string) uint64 {
	n, _ := strconv.Atoi(s)
	return uint64(n)
}

//指针内存深拷贝
func DeepCopy(dst, src interface{}) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(src); err != nil {
		return err
	}
	return gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(dst)
}

//根据缓存创建XML文件
func CreateXMLFileFromCache(path string, v interface{}) error {
	output, err := xml.MarshalIndent(v, "", "    ")
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	file.Write([]byte(xml.Header))
	file.Write(output)
	return nil
}

//获取本地IP
func GetLocalIP() string {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			addrs, _ := netInterfaces[i].Addrs()
			for _, address := range addrs {
				if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return ipnet.IP.String()
					}
				}
			}
		}
	}
	return ""
}

//毫秒时间戳转日期
func TimestampToDate(testid int64) string {
	return time.Unix(int64(testid/1000), 0).Format("2006-01-02 15:04:11")
}

type ProtoNil struct{} //空的proto.Message
func (p ProtoNil) String() string {
	return ""
}
func (p ProtoNil) Reset() {

}
func (p ProtoNil) ProtoMessage() {

}


func PrintSelfFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	return runtime.FuncForPC(pc).Name()
}
func PrintCallerName() string {
	pc, _, _, _ := runtime.Caller(2)
	return runtime.FuncForPC(pc).Name()
}
func PrintCustomCallerName(skip int) string {
	pc, _, _, _ := runtime.Caller(skip)
	return runtime.FuncForPC(pc).Name()
}
