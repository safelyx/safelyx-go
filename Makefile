.PHONY: format
format:
	go fmt .

.PHONY: test
test:
	go vet .
	go test -v . -race
	go mod tidy
