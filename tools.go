package tools

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
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

//======================================================文件操作
/*
@Desc:加载json配置
@Param:文件路径，json结构体指针(地址)
*/
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
/*
@Desc:加载XML配置
@Param:文件路径，XML结构体指针(地址)
*/
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
/*根据缓存创建XML文件*/
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
/*CSV一次读取所有行*/
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
/*CSV一次写一行*/
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
/*CSV一次写多行*/
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

/*判断文件是否存在*/
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
//======================================================随机数
/*随机生成一个int64，不包括max!*/
func RandInt64(min, max int64) int64 {
	rand.Seed(time.Now().UnixNano())
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int63n(max-min) + min
}
/*随机生成一个int，不包括Max*/
func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
/*一次生成多个不同的随机数用数组返回,不包括start!*/
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
//======================================================类型转换
/*网络字节序转换 byte <-> int */
func BytesToInt64BigEndian(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}
func BytesToInt16BigEndian(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x uint16
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}
func BytesToUint32BigEndian(b []byte) uint32 {
	bytesBuffer := bytes.NewBuffer(b)
	var x uint32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return x
}
func BytesToInt32BigEndian(b []byte) int32 {
	bytesBuffer := bytes.NewBuffer(b)
	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return x
}
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
func Int16ToBytesBigEndian(n int) []byte {
	x := uint16(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}
func Int32ToBytesBigEndian(n int32) []byte {

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, n)
	return bytesBuffer.Bytes()
}
func Int64ToBytesBigEndian(i int64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}
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
func Uint32ToBytesBigEndian(n uint32) []byte {
	x := uint32(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}
/*String <-> Bool */
func StringToBool(s string) bool {
	if s == "true" {
		return true
	} else {
		return false
	}
}
func BoolToString(b bool) string {
	if b {
		return "true"
	} else {
		return "false"
	}
}
/*easy atoi*/
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
/*毫秒时间戳转日期*/
func TimestampToDate(testid int64) string {
	return time.Unix(int64(testid/1000), 0).Format("2006-01-02 15:04:11")
}
//======================================================功能函数
/*进度条*/
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
/*返回调用函数名称*/
func CallFuncName(skip int) string {
	pc, path, line, _ := runtime.Caller(skip)
	return "\n[Call:" + runtime.FuncForPC(pc).Name() + "]\n[Path:" + path + "]\n[line:" + strconv.Itoa(line) + "]"
}
/*指针内存深拷贝*/
func DeepCopy(dst, src interface{}) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(src); err != nil {
		return err
	}
	return gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(dst)
}
/*获取本地IP*/
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
type ProtoNil struct{} //空的proto.Message
func (p ProtoNil) String() string {
	return ""
}
func (p ProtoNil) Reset() {

}
func (p ProtoNil) ProtoMessage() {

}

//======================================================常用加密算法
/*Aes加解密*/
type _PaddingType int32
const(
	PaddingType_PKCS7 _PaddingType = 1
	PaddingType_PKCS5 _PaddingType = 2
	PaddingType_Zero _PaddingType = 3
)
func AesCBCEncrypt(key,iv,origData []byte,t _PaddingType) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch t{
	case PaddingType_PKCS7: origData = PKCS7Padding(origData, block.BlockSize())
	case PaddingType_PKCS5:origData = PKCS5Padding(origData, block.BlockSize())
	case PaddingType_Zero:origData = ZeroPadding(origData, block.BlockSize())
	}
	blockMode := cipher.NewCBCEncrypter(block, iv) //iv=key
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}
func AesCBCDecrypt(key,iv,crypted []byte,t _PaddingType) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	switch t{
	case PaddingType_PKCS7: origData = PKCS7UnPadding(origData)
	case PaddingType_PKCS5:origData = PKCS5UnPadding(origData)
	case PaddingType_Zero:origData = ZeroUnPadding(origData)
	}
	return origData, nil
}
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}
func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
//使用PKCS7进行填充，IOS也是7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
/*Rsa加解密、公钥私钥生成*/
/*公钥、私钥生成*/
func GenRsaKey() (prvkey, pubkey []byte) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}
//签名
func RsaSignWithSha256(data []byte, keyBytes []byte) []byte {
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("private key error"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		panic(err)
	}

	signature, err := rsa.SignPKCS1v15(crand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		panic(err)
	}
	return signature
}
//验证
func RsaVerySignWithSha256(data, signData, keyBytes []byte) bool {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("public key error"))
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData)
	if err != nil {
		panic(err)
	}
	return true
}
// 公钥加密
func RsaEncrypt(data, keyBytes []byte) []byte {
	//解密pem格式的公钥
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("public key error"))
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	ciphertext, err := rsa.EncryptPKCS1v15(crand.Reader, pub, data)
	if err != nil {
		panic(err)
	}
	return ciphertext
}
// 私钥解密
func RsaDecrypt(ciphertext, keyBytes []byte) []byte {
	//获取私钥
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("private key error!"))
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 解密
	data, err := rsa.DecryptPKCS1v15(crand.Reader, priv, ciphertext)
	if err != nil {
		panic(err)
	}
	return data
}