# w3g
W3G exports the missing HTTP header keys that should have been shipped with Go.

## Go
This package can be added as a dependency using Go's package manager.

### Install
Adding the package.

```sh
go get -u github.com/lindsaygelle/w3g
```

## Docker
This code can be run and executed from within a Docker Container. 
Below are the instructions to use the provided Dockerfile as the development and testing environment.

### Building 
Building the Container.

```sh
docker build . -t w3g
```

### Running
Developing and running Go from within the Container.

```sh
docker run -it --rm --name w3g w3g
```

## Usage

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"

    "github.com/lindsaygelle/w3g"
)

const (
	address string = "8080"
)

const (
	contentApplication string = "application/json"
	contentCharset     string = "charset"
	contentEncoding    string = "utf-8"
)

type response struct {
	Message string
}

var (
	contentHeaders = http.Header{
		w3g.ContentType: {(contentApplication + ";") + (contentCharset + "=" + contentEncoding)}}
)

func handle(w http.ResponseWriter, r *http.Request, b *[]byte) {
	for key, values := range contentHeaders {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(http.StatusOK)
	w.Write(*b)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(response{"Hello!"})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(nil)
			return
		}
		handle(w, r, &b)
	})
	http.ListenAndServe(fmt.Sprintf(":%s", address), nil)
}
