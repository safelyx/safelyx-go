.PHONY: format
format:
	go fmt .

.PHONY: test
test:
	go test -v . -race
	go mod tidy
