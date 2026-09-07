VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt install uninstall run clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/chn-resolver ./cmd/chn-resolver

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

install: build
	install -Dm755 bin/chn-resolver /usr/local/bin/chn-resolver
	install -Dm644 deploy/chn-resolver.toml /etc/chn-resolver/chn-resolver.toml
	install -Dm644 deploy/chn-resolver.service /etc/systemd/system/chn-resolver.service

uninstall:
	rm -f /usr/local/bin/chn-resolver /etc/systemd/system/chn-resolver.service

run: build
	./bin/chn-resolver -config deploy/chn-resolver.toml

clean:
	rm -rf bin
