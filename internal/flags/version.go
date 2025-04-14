package flags

const version = `v0.0.0`

const asciiBanner = ` ___   _____    ___ _     _   
|_ _| / / _ \  | _ (_)___| |_ 
 | | / / (_) | |   / / _ \  _|
|___/_/ \___/  |_|_\_\___/\__| NG
               ` + version

func PrintVersion() {
	println(asciiBanner)
}
