PORT := 1339
ARGS :=
LIB := protocol.go session.go map.go server.go takeover.go movement.go

.PHONY: all
build:
	go build -o bin/ ./...

bin/%: %/main.go ${LIB}
	go build -o bin/ "./$*"

.PHONY: rerun
rerun:

.PRECIOUS: %/run
%/run: bin/% rerun
	cd $* && "../bin/$*" -remote=147.75.85.99:${PORT} ${ARGS} 2>&1 | tee run
