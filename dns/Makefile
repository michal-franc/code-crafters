default: run-resolver

build:
	go build -o ./bin/server app/*.go

run: build
	sudo ./bin/server

run-resolver: build
	sudo ./bin/server --resolver 8.8.8.8:53
