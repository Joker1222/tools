package main

import (
    tools "test/base"
)

func main(){
    e,_:=tools.NewLogger("test",
        tools.WithDebugConsole(true),tools.WithDebugFile(true),
        tools.WithErrorConsole(true),tools.WithErrorFile(true),
        tools.WithWarnConsole(true),tools.WithWarnFile(true),
        tools.WithInfoConsole(true),tools.WithInfoFile(true),
        tools.WithTraceConsole(true),tools.WithTraceFile(true))
    e.Debug("测试通用logger工具")
    e.Trace("测试通用logger工具")
    e.Error("abc")
    e.Warn("bcd")
    e.Fatal("ACD")
    e.Info("ACC")
    e.RDebug("测试通用logger工具")
    e.RTrace("测试通用logger工具")
    e.RError("abc")
    e.RWarn("bcd")
    e.RFatal("ACD")
    e.RInfo("ACC")
    return
}

