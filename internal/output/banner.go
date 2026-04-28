package output

import (
	"fmt"
	"os"
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
)

func Colorize(color, text string) string {
	return color + text + Reset
}

func PrintBanner() {
	banner := `
` + Bold + Cyan + `    ____  _ ____    _____           __         
   / __ \(_) __ \  / __(_)___  ____/ /__  _____
  / / / / / / / / / /_/ / __ \/ __  / _ \/ ___/
 / /_/ / / /_/ / / __/ / / / / /_/ /  __/ /    
/_____/_/_____/ /_/ /_/_/ /_/\__,_/\___/_/     
` + Reset + `
` + Dim + `              Advanced Subdomain Discovery Engine` + Reset + `
` + Dim + `              v3.0 — github.com/yel-joul/did_finder` + Reset + `
`

	fmt.Fprintln(os.Stderr, banner)
}

func PrintInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, Cyan+"[INF] "+Reset+format+"\n", args...)
}

func PrintWarning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, Yellow+"[WRN] "+Reset+format+"\n", args...)
}

func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, Red+"[ERR] "+Reset+format+"\n", args...)
}

func PrintSuccess(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, Green+"[+] "+Reset+format+"\n", args...)
}

func PrintFound(subdomain, source string) {
	fmt.Printf(Green+"%s"+Reset+" "+Dim+"[%s]"+Reset+"\n", subdomain, source)
}
