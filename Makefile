BINARY ?= did_finder
OLLAMA_MODEL ?= llama3.2:1b
GO ?= go

.PHONY: build install test doctor ollama-pull nuclei-install nuclei-update smoke clean

build:
	$(GO) build -o $(BINARY) ./cmd/did_finder

install:
	$(GO) install ./cmd/did_finder

test:
	$(GO) test ./...

doctor:
	./scripts/doctor.sh

ollama-pull:
	ollama pull $(OLLAMA_MODEL)

nuclei-install:
	$(GO) install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

nuclei-update:
	nuclei -update-templates

smoke:
	did_finder -d example.com -timeout 10 -ollama -ollama-model $(OLLAMA_MODEL) -ollama-out output/smoke-ai.md -report output/smoke-report.html

clean:
	rm -f $(BINARY)
