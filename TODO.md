# TODO

## Functionality 

* Send PID and/or file pattern dynamically to the BPF program (command line flags)
* Capture all *open* and *close* syscalls (e.g. from debugfs?)
    * Could write a Go code to check for available syscalls and then alert?
* ...

## Refactor

* Error wrapping
* vet 
* Move have a ./internal/ioriot.bpf.c and ./internal/ioriot.go as starting points
* Move main.go to ./cmd/ioriot
