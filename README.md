# Safelyx API

[![](https://github.com/safelyx/safelyx-go/workflows/Run%20Tests/badge.svg)](https://github.com/safelyx/safelyx-go/actions?workflow=Run+Tests)

> Safelyx API client

Safelyx API client for Go. It has no dependencies.

You can find the API documentation at https://safelyx.com/safe-api.

### Some things to note:

1. It's simply making an HTTP request to the Safelyx API.

2. It provides types for the results and for the parameters.

## Usage

It has a method per API endpoint.

```bash
go install github.com/safelyx/safelyx-go@v0.1.1
```

```go
import (
  "log"
  "fmt"

  "github.com/safelyx/safelyx-go"
)

api := safelyx.NewClient("your-key-code")

checkResult, err := api.CheckLink("https://example.com")
if err != nil {
  log.Fatal(err)
}

fmt.Println(checkResult.Result) // Outputs a safety score between 0 (unsafe) and 10 (safe). -1 if there was an error, -2 if there are no checks remaining.
```

## Development

Requires `go`.

```bash
make format
make test
```

## Publishing

Just push to the `main` branch (with the updated version in the README) and create a tag + release.
