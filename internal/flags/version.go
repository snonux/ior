package flags

import (
	"fmt"
	"io"
	"os"
)

// Version is the current application version.
const Version = "v1.1.0"

const asciiBannerTemplate = ` ██╗    ██╗  ██████╗     ██████╗  ██╗  ██████╗  ████████╗
 ██║   ██╔╝ ██╔═══██╗    ██╔══██╗ ██║ ██╔═══██╗ ╚══██╔══╝
 ██║  ██╔╝  ██║   ██║    ██████╔╝ ██║ ██║   ██║    ██║   
 ██║ ██╔╝   ██║   ██║    ██╔══██╗ ██║ ██║   ██║    ██║   
 ██║██╔╝    ╚██████╔╝    ██║  ██║ ██║ ╚██████╔╝    ██║   
 ╚═╝╚═╝      ╚═════╝     ╚═╝  ╚═╝ ╚═╝  ╚═════╝     ╚═╝   
       ⚡ Next-Generation BPF I/O Syscall Tracer ⚡
                          %s`

// PrintVersion prints the banner with the current version to stdout.
func PrintVersion() {
	PrintVersionTo(os.Stdout)
}

// PrintVersionTo writes the banner with the current version to w. Callers
// whose stdout is machine-readable (e.g. -plain CSV mode) pass os.Stderr so
// the banner never interleaves with data output.
func PrintVersionTo(w io.Writer) {
	_, _ = fmt.Fprintf(w, asciiBannerTemplate+"\n", Version)
}
