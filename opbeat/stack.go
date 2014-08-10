package opbeat

import (
	"path"
	"runtime"
	"strings"
)

func stackFilter(file string, line int, packageName, funcName string) bool {
	return (packageName == "runtime" && funcName == "panic") ||
		(packageName == "runtime" && funcName == "goexit") ||
		(packageName == "github.com/roncohen/opbeat-go/opbeat/opbeat")
}

func makeRelative(file string) string {
	path_segs := strings.Split(file, "/")

	for i, seg := range path_segs {
		if seg == "src" {
			return path.Join(path_segs[i+1:]...)
		}
	}
	return ""
}

func stack(startFrame int) *Stacktrace {
	stack := make([]Frame, 0)
	for i := startFrame; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		packageName, funcName := packageFuncName(pc)

		if stackFilter(file, line, packageName, funcName) {
			continue
		}

		stack = append(stack, Frame{
			AbsFilename: file,
			Filename:    makeRelative(file),
			LineNo:      line,
			Function:    funcName,
		})
	}

	return &Stacktrace{stack}
}

func packageFuncName(pc uintptr) (string, string) {
	f := runtime.FuncForPC(pc)
	if f == nil {
		return "", ""
	}

	packageName := ""
	funcName := f.Name()

	if ind := strings.LastIndex(funcName, "/"); ind > 0 {
		packageName += funcName[:ind+1]
		funcName = funcName[ind+1:]
	}
	if ind := strings.Index(funcName, "."); ind > 0 {
		packageName += funcName[:ind]
		funcName = funcName[ind+1:]
	}

	return packageName, funcName
}
