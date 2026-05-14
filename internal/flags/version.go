package flags

import "fmt"

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

// PrintVersion prints the banner with the current version.
func PrintVersion() {
	fmt.Printf(asciiBannerTemplate+"\n", Version)
}
