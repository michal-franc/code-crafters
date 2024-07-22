default: run-resolver

build:
	go build -o server app/*.go

run: build
	sudo ./server

run-resolver: build
	sudo ./server --resolver 8.8.8.8:53
