all: generate

generate: types tracepoint_list

.PHONY: types
types:
	cat ../c/types.h | raku generate.raku nqctogo | tee types/types.go

.PHONY: tracepoint_list
tracepoint_list:
	echo 'package generated' > tracepoint_list.go
	echo '' >> tracepoint_list.go
	echo 'var TracepointList = []string{' >> tracepoint_list.go
	sed -n -E '/^SEC.*sys_(enter|exit)_/ { s/[")]//g; s/.*sys_(.*)/\t"\1",/; p; }' \
		../c/tracepoints/*.c >> tracepoint_list.go
	echo '}' >> tracepoint_list.go
