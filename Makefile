.PHONY: build clean docker-build extract-wasm

build:
	env GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm

docker-build:
	docker build -t crowdsec-wasm-bouncer:latest .

extract-wasm:
	docker create --name wasm-extract crowdsec-wasm-bouncer:latest
	docker cp wasm-extract:/plugin.wasm ./plugin.wasm
	docker rm wasm-extract

clean:
	rm -f plugin.wasm
