all: build run
build:
	./build.sh
clean:
	find . -type f -name ioriotng -delete
	find . -name \*.o -delete
	find . -name vmlinux.h -delete
run:
	sudo ./ioriotng
