package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI escape codes
const (
	reset  = "\033[0m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
	red    = "\033[31m"
)

var (
	colorize = true
	mu       sync.Mutex
	out      io.Writer = os.Stderr
)

func init() {
	colorize = detectColorSupport()
}

func detectColorSupport() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	if fileInfo, err := os.Stderr.Stat(); err == nil {
		if (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			return false
		}
	}
	term := os.Getenv("TERM")
	return term != "" && term != "dumb"
}

func c(code, text string) string {
	if !colorize {
		return text
	}
	return code + text + reset
}

func timestamp() string {
	return time.Now().Format("15:04:05.000")
}

func printf(format string, args ...interface{}) {
	mu.Lock()
	fmt.Fprintf(out, format, args...)
	mu.Unlock()
}

// Log handles dynamic log levels
func Log(level, message string) {
	switch strings.ToLower(level) {
	case "info":
		Info("%s", message)
	case "ok":
		OK("%s", message)
	case "warn", "warning":
		Warn("%s", message)
	case "error":
		Error("%s", message)
	case "fatal":
		Fatal("%s", message)
	default:
		Info("[%s] %s", level, message)
	}
}

// Info logs an informational message
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	printf("%s %s %s\n", c(gray, timestamp()), c(cyan, "INFO "), msg)
}

// OK logs a success message
func OK(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	printf("%s %s %s\n", c(gray, timestamp()), c(green, "OK   "), msg)
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	printf("%s %s %s\n", c(gray, timestamp()), c(yellow, "WARN "), msg)
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	printf("%s %s %s\n", c(gray, timestamp()), c(red, "ERROR"), msg)
}

// Fatal logs an error and exits
func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	printf("%s %s %s\n", c(gray, timestamp()), c(red, "FATAL"), msg)
	os.Exit(1)
}

// Banner prints a styled banner
func Banner(text string) {
	printf("\n%s\n%s\n", c(cyan, text), c(gray, strings.Repeat("-", len(text))))
}

// Field prints a key-value field
func Field(key string, value interface{}) {
	printf("  %-15s %v\n", c(gray, key+":"), value)
}

// Dim returns dimmed text
func Dim(text string) string {
	return c(gray, text)
}

// Blank prints a blank line
func Blank() {
	printf("\n")
}
