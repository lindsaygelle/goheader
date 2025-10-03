# Goheader

Goheader is a small, focused [Go](https://github.com/golang/go) library that makes HTTP headers simple to define, compose and write. Instead of putting string literals all over your code, you use strongly named constructors (`NewContentTypeHeader`, `NewAcceptHeader`, `NewStrictTransportSecurityHeader` and many more) to build headers in a consistent way. A simple Header type is used to define a name, values and whether or not it is applicable. `WriteHeaders` then uses this to apply it to `http.ResponseWriter`.
If you know the header you want, there's a constructor for it. If you need more than one value, add them in. If you want to keep things tidy, collect headers into a slice and write them all at once.

![Goheader](https://repository-images.githubusercontent.com/398801126/5de79de0-f8f1-4c15-83bb-be249a772b01)

[![PkgGoDev](https://pkg.go.dev/badge/github.com/lindsaygelle/goheader)](https://pkg.go.dev/github.com/lindsaygelle/goheader)
[![Go Report Card](https://goreportcard.com/badge/github.com/lindsaygelle/goheader)](https://goreportcard.com/report/github.com/lindsaygelle/goheader)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/lindsaygelle/goheader)](https://github.com/lindsaygelle/goheader/releases)
[![GitHub](https://img.shields.io/github/license/lindsaygelle/goheader)](LICENSE.txt)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v1.4%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

## Features

### Typed constructors for dozens of headers
Use small config structs for clarity and correctness:
Examples:
- `NewAcceptHeader(AcceptConfig)`
- `NewAuthorizationHeader(AuthorizationConfig)`
- `NewContentSecurityPolicyHeader(ContentSecurityPolicyConfig)`
- `NewStrictTransportSecurityHeader(StrictTransportSecurityConfig)`
- `NewSetCookieHeader(SetCookieConfig)`
- `NewReportingEndpointsHeader(ReportingEndpointsConfig)`
- `NewPermissionsPolicyHeader(PermissionsPolicyConfig)`

And many more.

### Correct formatting out of the box
Constructors handle the fiddly bits—q-values, date formatting (Mon, 02 Jan 2006 15:04:05 GMT), CSV joins, params quoting, and directive assembly.
Examples:
- `NewAcceptEncodingHeader(AcceptEncodingConfig{...})` > `"gzip;q=1.0, br;q=0.8"`
- `NewContentRangeHeader(ContentRangeConfig{...})` > `"bytes 0-499/1234"`
- `NewRefreshHeader(RefreshConfig{...})` > `"5; url=https://example.com/new-page"`

### Ergonomic multi-value support
Pass slices for multi-valued headers and get correctly joined output:
Examples
- `NewVaryHeader(VaryConfig{Headers: []string{"Accept-Encoding","User-Agent"}})` > `"Accept-Encoding, User-Agent"`
- `NewLinkHeader(LinkConfig{Links: ...})` > `"<...>; rel=\"next\", <...>; rel=\"prev\""`

### Request & Response clarity
Config names mirror where headers are typically used (request vs response), making intent obvious in code review.

### Simple integration
Works with `net/http`. Collect headers in a slice and `WriteHeaders(w, headers...)`.

## Installation
You can install it in your Go project using `go get`:

```sh
go get github.com/lindsaygelle/goheader
```

```go
import "github.com/lindsaygelle/goheader"
```

## Usage
Import the package into your Go code:

```go
package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/lindsaygelle/goheader"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Build headers via typed configs.
	hContentType := goheader.NewContentTypeHeader(goheader.ContentTypeConfig{
		MediaType: "application/json",
		Params:    map[string]string{"charset": "UTF-8"},
	})

	hAccept := goheader.NewAcceptHeader(goheader.AcceptConfig{
		Values: []goheader.AcceptValue{
			{MediaType: "application/json", Quality: 1.0},
			{MediaType: "text/html", Quality: 0.8, Params: map[string]string{"charset": "utf-8"}},
		},
	})

	exp := time.Now().Add(24 * time.Hour)
	hCookie := goheader.NewSetCookieHeader(goheader.SetCookieConfig{
		Name: "sessionId", Value: "abc123", Expires: &exp,
		Path: "/", Secure: true, HTTPOnly: true, SameSite: "Strict",
	})

	hCSP := goheader.NewContentSecurityPolicyHeader(goheader.ContentSecurityPolicyConfig{
		Directives: []goheader.CSPDirective{
			{Directive: "default-src", Sources: []string{"'self'"}},
			{Directive: "script-src", Sources: []string{"'self'", "https://apis.example.com"}},
		},
	})

	hHSTS := goheader.NewStrictTransportSecurityHeader(goheader.StrictTransportSecurityConfig{
		MaxAge: 31536000, IncludeSubDomains: true, Preload: true,
	})

	// Apply in one call.
	goheader.WriteHeaders(w, hContentType, hAccept, hCookie, hCSP, hHSTS)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}

func main() { _ = http.ListenAndServe(":8080", http.HandlerFunc(handler)) }
```

## Common Recipes
### CORS 
```go
cors := []goheader.Header{
	goheader.NewAccessControlAllowOriginHeader(goheader.AccessControlAllowOriginConfig{
		Origin: "https://example.com",
	}),
	goheader.NewAccessControlAllowMethodsHeader(goheader.AccessControlAllowMethodsConfig{
		Values: []goheader.AccessControlAllowMethodsValue{{Method: "GET"}, {Method: "POST"}, {Method: "OPTIONS"}},
	}),
	goheader.NewAccessControlAllowHeadersHeader(goheader.AccessControlAllowHeadersConfig{
		Values: []goheader.AccessControlAllowHeadersValue{{Header: "Content-Type"}, {Header: "Authorization"}},
	}),
}
goheader.WriteHeaders(w, cors...)
```

### Security
```go
goheader.WriteHeaders(w,
	goheader.NewReferrerPolicyHeader(goheader.ReferrerPolicyConfig{Policy: "strict-origin-when-cross-origin"}),
	goheader.NewXContentTypeOptionsHeader(goheader.XContentTypeOptionsConfig{NoSniff: true}),
	goheader.NewXXSSProtectionHeader(goheader.XXSSProtectionConfig{Enabled: true, Mode: "block"}),
)
```

### Cache Control
```go
maxAge := 3600
goheader.WriteHeaders(w,
	goheader.NewCacheControlHeader(goheader.CacheControlConfig{
		Directives: []goheader.CacheControlDirective{
			{Directive: "max-age", Value: &maxAge},
			{Directive: "no-cache"},
		},
	}),
)
```

### Partials
```go
goheader.WriteHeaders(w,
	goheader.NewContentRangeHeader(goheader.ContentRangeConfig{
		Unit: "bytes", Start: 0, End: 499, Size: 1234,
	}),
)
```

### Extending
```go
custom := goheader.Header{
	Name:       "X-Feature-Flag",
	Values:     []string{"beta-thing"},
}
goheader.WriteHeaders(w, custom)
```

## Docker
A [Dockerfile](./Dockerfile) is provided for individuals that prefer containerized development.

### Building
Building the Docker container:
```sh
docker build . -t goheader
```

### Running
Developing and running Go within the Docker container:
```sh
docker run -it --rm --name goheader goheader
```

## Docker Compose
A [docker-compose](./docker-compose.yml) file has also been included for convenience:
### Running
Running the compose file.
```sh
docker-compose up -d
```

## Contributing
We warmly welcome contributions to Goheader. Whether you have innovative ideas, bug reports, or enhancements in mind, please share them with us by submitting GitHub issues or creating pull requests. For substantial contributions, it's a good practice to start a discussion by creating an issue to ensure alignment with the project's goals and direction. Refer to the [CONTRIBUTING](./CONTRIBUTING.md) file for comprehensive details.

## Branching
For a smooth collaboration experience, we have established branch naming conventions and guidelines. Please consult the [BRANCH_NAMING_CONVENTION](./BRANCH_NAMING_CONVENTION.md) document for comprehensive information and best practices.

## License
Goheader is released under the MIT License, granting you the freedom to use, modify, and distribute the code within this repository in accordance with the terms of the license. For additional information, please review the [LICENSE](./LICENSE) file.

## Security
If you discover a security vulnerability within this project, please consult the [SECURITY](./SECURITY.md) document for information and next steps.

## Code Of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct). For additional information, please review the [CODE_OF_CONDUCT](./CODE_OF_CONDUCT.md) file.

## Acknowledgements
Big thanks to [egonelbre/gophers](https://github.com/egonelbre/gophers) for providing the delightful Gopher artwork used in the social preview. Don't hesitate to pay them a visit!

## References
The information for this package was sourced from the following sites.

[Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
The go-to resource for comprehensive HTTP header information.

[Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields)
A reliable reference providing detailed insights into various HTTP header fields.

[http.dev](https://http.dev/)
A valuable platform offering expert guidance and best practices in HTTP development.

If you spot any discrepancies or have additional insights, don't hesitate to reach out!
