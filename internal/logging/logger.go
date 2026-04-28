package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type stdLogger struct {
	mu    sync.Mutex
	out   io.Writer
	debug bool
}

func New(out io.Writer, debug bool) Logger {
	if out == nil {
		out = os.Stderr
	}
	return &stdLogger{out: out, debug: debug}
}

func Nop() Logger {
	return nopLogger{}
}

func (l *stdLogger) Debugf(format string, args ...any) {
	if !l.debug {
		return
	}
	l.write("DBG", format, args...)
}

func (l *stdLogger) Infof(format string, args ...any) {
	l.write("INF", format, args...)
}

func (l *stdLogger) Warnf(format string, args ...any) {
	l.write("WRN", format, args...)
}

func (l *stdLogger) Errorf(format string, args ...any) {
	l.write("ERR", format, args...)
}

func (l *stdLogger) write(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "[%s] %s\n", level, fmt.Sprintf(format, args...))
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}
