package flags

import "fmt"

// Version is the current application version.
const Version = "v0.0.0"

const asciiBannerTemplate = ` ___   _____    ___ _     _
|_ _| / / _ \  | _ (_)___| |_ 
 | | / / (_) | |   / / _ \  _|
|___/_/ \___/  |_|_\_\___/\__| NG
               %s`

// PrintVersion prints the banner with the current version.
func PrintVersion() {
	fmt.Printf(asciiBannerTemplate+"\n", Version)
}
