// -------------------------------------------------------------------------
//    @FileName         ：    Log.go
//    @Author           ：    Joker
//    @Date             ：    2019-12-28
//    @Module           ：    Log
//    @Desc             :     robot log pack
//   							- DEBUG,INFO,WARN,ERROR,PANIC,FATAL use "go.uber.org/zap"
//   							- TRACE use "github.com/rs/zerolog"
//
//								ps:Trace级别使用zero log(因为zap不支持TRACE级别),Trace会写入单独的一个文件,一般调试时用
// -------------------------------------------------------------------------
package tools

import (
	"fmt"
	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"runtime"
	"time"
)

//map
var levelMap = map[string]zapcore.Level{
	"Debug": zapcore.DebugLevel,
	"Info":  zapcore.InfoLevel,
	"Warn":  zapcore.WarnLevel,
	"Error": zapcore.ErrorLevel,
	"Fatal": zapcore.FatalLevel,
}

type ArdbegLogger struct{
	baseGlobalToFile *zap.Logger
	baseGlobalToConsole *zap.Logger

	seriousGlobalToFile *zap.Logger
	seriousGlobalToConsole *zap.Logger

	traceGlobalToFile zerolog.Logger
	traceGlobalToConsole zerolog.Logger

	logSwitch
}

type ArdbegLog struct {
	logPath string
	logger map[string]*ArdbegLogger
	maxBackups int
	maxSize int
	caller int
}

type logSwitch struct{
	toFile bool
	toConsole bool
}

type elementLog struct{
	Level     string `xml:"Level,attr"`
	ToFile    string `xml:"ToFile,attr"`    //Output to file
	ToConsole string `xml:"ToConsole,attr"` //Output to console
}

type logOpt func(log *ArdbegLog) 
func WithDebugFile(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Debug"];!ok{
			log.logger["Debug"] = new(ArdbegLogger)
		}
		log.logger["Debug"].toFile = true
	}
}
func WithDebugConsole(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Debug"];!ok{
			log.logger["Debug"] = new(ArdbegLogger)
		}
		log.logger["Debug"].toConsole = true
	}
}
func WithInfoFile(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Info"];!ok{
			log.logger["Info"] = new(ArdbegLogger)
		}
		log.logger["Info"].toFile = true
	}
}
func WithInfoConsole(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Info"];!ok{
			log.logger["Info"] = new(ArdbegLogger)
		}
		log.logger["Info"].toConsole = true
	}
}
func WithWarnFile(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Warn"];!ok{
			log.logger["Warn"] = new(ArdbegLogger)
		}
		log.logger["Warn"].toFile = true
	}
}
func WithWarnConsole(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Warn"];!ok{
			log.logger["Warn"] = new(ArdbegLogger)
		}
		log.logger["Warn"].toConsole = true
	}
}
func WithErrorFile(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Error"];!ok{
			log.logger["Error"] = new(ArdbegLogger)
		}
		log.logger["Error"].toFile = true
	}
}
func WithErrorConsole(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Error"];!ok{
			log.logger["Error"] = new(ArdbegLogger)
		}
		log.logger["Error"].toConsole = true
	}
}
func WithTraceFile(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Trace"];!ok{
			log.logger["Trace"] = new(ArdbegLogger)
		}
		log.logger["Trace"].toFile = true
	}
}
func WithTraceConsole(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Trace"];!ok{
			log.logger["Trace"] = new(ArdbegLogger)
		}
		log.logger["Trace"].toConsole = true
	}
}
func WithFatalFile(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Fatal"];!ok{
			log.logger["Fatal"] = new(ArdbegLogger)
		}
		log.logger["Fatal"].toFile = true
	}
}
func WithFatalConsole(b bool) logOpt{
	return func(log *ArdbegLog) {
		if _,ok:=log.logger["Fatal"];!ok{
			log.logger["Fatal"] = new(ArdbegLogger)
		}
		log.logger["Fatal"].toConsole = true
	}
}

func WithMaxBackups(i int) logOpt{
	return func(log *ArdbegLog) {
		log.maxBackups = i
	}
}
func WithMaxSize(i int) logOpt{
	return func(log *ArdbegLog) {
		log.maxSize = i
	}
}
func WithLogPath(path string) logOpt{
	return func(log *ArdbegLog) {
		log.logPath = path
	}
}
func WithCaller(n int) logOpt{
	return func(log *ArdbegLog) {
		log.caller = n
	}
}
func NewLogger(caseName string,opt... logOpt)(*ArdbegLog,error){
	l:=new(ArdbegLog)
	l.maxSize = 512
	l.maxBackups = 10
	l.logger = make(map[string]*ArdbegLogger)
	for _,o:=range opt{
		o(l)
	}
	if l.logPath == ""{
		l.logPath = "./log"
	}
	l.logPath =l.logPath+"/"+time.Now().Format("2006_0102_1504_05")+"_"+caseName
	if err:=os.MkdirAll(l.logPath, os.ModePerm);err!=nil{
		return nil,fmt.Errorf("create dir %v failed ...",l.logPath)
	}
	
	baseLogFile := getFileLogWriter(l.logPath+"/base.log",l.maxSize,l.maxBackups)
	seriousLogFile:=getFileLogWriter(l.logPath+"/serious.log",l.maxSize,l.maxBackups)
	traceLogFile, _:= os.Create(l.logPath+"/trace.log")
	/*zap 日志流*/
	baseSync := []zapcore.WriteSyncer{baseLogFile}
	seriousSync := []zapcore.WriteSyncer{seriousLogFile}
	consoleSync :=[]zapcore.WriteSyncer{os.Stdout}
	/*zap 日志选项*/
	globalOptions := getOptions(zap.AddCaller(), zap.AddCallerSkip(l.caller)) //全局选项
	/*zap 日志解析器*/
	fileEncoder := getEncoderConfig(zapcore.CapitalLevelEncoder) //文件解析器
	consoleEncoder := getEncoderConfig(zapcore.CapitalColorLevelEncoder) //终端解析器

	for k,_:=range l.logger{
		l.logger[k].baseGlobalToFile=newLogger(levelMap[k], fileEncoder, baseSync, globalOptions...)
		l.logger[k].baseGlobalToConsole=newLogger(levelMap[k], consoleEncoder, consoleSync, globalOptions...)

		l.logger[k].seriousGlobalToFile=newLogger(levelMap[k], fileEncoder, seriousSync, globalOptions...)
		l.logger[k].seriousGlobalToConsole=newLogger(levelMap[k], consoleEncoder, consoleSync, globalOptions...)

		l.logger[k].traceGlobalToFile=zerolog.New(traceLogFile).With().CallerWithSkipFrameCount(l.caller+2).Logger().Level(zerolog.TraceLevel).Output(zerolog.ConsoleWriter{Out: traceLogFile, TimeFormat: "2006-01-02 15:04:05.000"})
		l.logger[k].traceGlobalToConsole=zerolog.New(os.Stdout).With().CallerWithSkipFrameCount(l.caller+2).Timestamp().Logger().Level(zerolog.TraceLevel).Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006-01-02 15:04:05.000"})
	}
	return l,nil
}

func (p*ArdbegLog)GetLogPath() string{
	return p.logPath
}

func newLogger(level zapcore.Level, encoderConfig zapcore.EncoderConfig, wSync []zapcore.WriteSyncer, options ...zap.Option) *zap.Logger {
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(level)
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(wSync...),
		atomicLevel,
	)
	return zap.New(core, options...)
}
func getOptions(options ...zap.Option) []zap.Option {
	return options
}
func getEncoderConfig(c zapcore.LevelEncoder) zapcore.EncoderConfig {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    c,                          // 小写编码器
		EncodeTime:     zapcore.ISO8601TimeEncoder, // ISO8601 UTC 时间格式
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder, // 全路径编码器
	}
	return encoderConfig
}
func getFileLogWriter(logName string,MaxSize,MaxBackups int) zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logName,
		MaxSize:    MaxSize,   //512M一个文件
		MaxBackups: MaxBackups,     //最大备份个数
		MaxAge:     365,   //最大保留天数
		Compress:   false, //归档压缩
	}
	return zapcore.AddSync(lumberJackLogger)
}

//Log API for developer
func (p*ArdbegLog)Trace(format string, v ...interface{}) {
	if _,ok:=p.logger["Trace"];!ok{
		return
	}
	if p.logger["Trace"].toConsole{
		p.logger["Trace"].traceGlobalToConsole.Trace().Msg(fmt.Sprintf(format, v...))
	}
	if p.logger["Trace"].toFile{
		p.logger["Trace"].traceGlobalToFile.Trace().Msg(fmt.Sprintf(format, v...))
	}
}

func (p*ArdbegLog)Debug(format string, v ...interface{}) {
	if p == nil {
		return
	}
	if _,ok:=p.logger["Debug"];!ok{
		return
	}
	if p.logger["Debug"].toConsole{
		p.logger["Debug"].baseGlobalToConsole.Debug(fmt.Sprintf(format, v...))
	}
	if p.logger["Debug"].toFile{
		p.logger["Debug"].baseGlobalToFile.Debug(fmt.Sprintf(format, v...))
	}
}
func (p*ArdbegLog)Info(format string, v ...interface{}) {
	if p == nil {
		return
	}
	if _,ok:=p.logger["Info"];!ok{
		return
	}
	if p.logger["Info"].toConsole{
		p.logger["Info"].baseGlobalToConsole.Info(fmt.Sprintf(format, v...))
	}
	if p.logger["Info"].toFile{
		p.logger["Info"].baseGlobalToFile.Info(fmt.Sprintf(format, v...))
	}
}
func (p*ArdbegLog)Error(format string, v ...interface{}) {
	if p == nil {
		return
	}
	if _,ok:=p.logger["Error"];!ok{
		return
	}
	if p.logger["Error"].toConsole{
		p.logger["Error"].seriousGlobalToConsole.Error(fmt.Sprintf(format, v...))
	}
	if p.logger["Error"].toFile{
		p.logger["Error"].seriousGlobalToFile.Error(fmt.Sprintf(format, v...))
	}
}
func (p*ArdbegLog)Warn(format string, v ...interface{}) {
	if p == nil {
		return
	}
	if _,ok:=p.logger["Warn"];!ok{
		return
	}
	if p.logger["Warn"].toConsole{
		p.logger["Warn"].baseGlobalToConsole.Warn(fmt.Sprintf(format, v...))
	}
	if p.logger["Warn"].toFile{
		p.logger["Warn"].baseGlobalToFile.Warn(fmt.Sprintf(format, v...))
	}
}
func (p*ArdbegLog)Fatal(format string, v ...interface{}) {
	if p == nil {
		return
	}
	if _,ok:=p.logger["Fatal"];!ok{
		return
	}
	if p.logger["Fatal"].toConsole{
		p.logger["Fatal"].seriousGlobalToConsole.Fatal(fmt.Sprintf(format, v...))
	}
	if p.logger["Fatal"].toFile{
		p.logger["Fatal"].seriousGlobalToFile.Fatal(fmt.Sprintf(format, v...))
	}
}

//Print now stack
func (p*ArdbegLog) Stack() {
	var buf [4096]byte
	n := runtime.Stack(buf[:], false)
	p.Error("\x1b[31m%s\x1b[0m", fmt.Sprintf("==> %s\n", string(buf[:n])))
}

func ColorRed(format string, v ...interface{}) string {
	return fmt.Sprintf("\x1b[31m%s\x1b[0m",fmt.Sprintf(format, v...))
}
func ColorGreen(format string, v ...interface{}) string {
	return fmt.Sprintf("\x1b[32m%s\x1b[0m",fmt.Sprintf(format, v...))
}
func ColorYellow(format string, v ...interface{}) string{
	return fmt.Sprintf("\x1b[33m%s\x1b[0m",fmt.Sprintf(format, v...))
}
func ColorBlue(format string, v ...interface{}) string{
	return fmt.Sprintf("\x1b[34m%s\x1b[0m",fmt.Sprintf(format, v...))
}
func ColorPurple(format string, v ...interface{}) string{
	return fmt.Sprintf("\x1b[35m%s\x1b[0m",fmt.Sprintf(format, v...))
}
func ColorCyan(format string, v ...interface{}) string{
	return fmt.Sprintf("\x1b[36m%s\x1b[0m",fmt.Sprintf(format, v...))
}
/*
格式：\033[显示方式;前景色;背景色m

说明：
前景色            背景色           颜色
---------------------------------------
30                40              黑色
31                41              红色
32                42              绿色
33                43              黃色
34                44              蓝色
35                45              紫红色
36                46              青蓝色
37                47              白色
显示方式           意义
-------------------------
0                终端默认设置
1                高亮显示
4                使用下划线
5                闪烁
7                反白显示
8                不可见

例子：
\033[1;31;40m
\033[0m

*/