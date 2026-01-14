.PHONY: build clean

build:
	env GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm main.go plugin.go http.go

clean:
	rm -f plugin.wasm
