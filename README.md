# Goheader
Goheader is a [Go](https://github.com/golang/go) package designed to simplify the management of HTTP headers in web applications. It offers a comprehensive collection of constants, each representing a standard HTTP header field, facilitating easy reference and usage. The package introduces a Header struct that encapsulates vital information about headers, such as name, values, and applicability, streamlining header manipulation. GoHeader provides a set of convenient functions for creating headers, allowing developers to specify multiple values efficiently. Headers are categorized based on their relevance to HTTP requests and responses, enhancing clarity in their usage context. With support for experimental headers and well-documented usage examples, GoHeader helps developers quickly integrate custom headers into their applications.

![Goheader](https://repository-images.githubusercontent.com/398801126/5de79de0-f8f1-4c15-83bb-be249a772b01)

[![PkgGoDev](https://pkg.go.dev/badge/github.com/lindsaygelle/goheader)](https://pkg.go.dev/github.com/lindsaygelle/goheader)
[![Go Report Card](https://goreportcard.com/badge/github.com/lindsaygelle/goheader)](https://goreportcard.com/report/github.com/lindsaygelle/goheader)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/lindsaygelle/goheader)](https://github.com/lindsaygelle/goheader/releases)
[![GitHub](https://img.shields.io/github/license/lindsaygelle/goheader)](LICENSE.txt)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v1.4%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

## Features

### 🏷️ Comprehensive List
GoHeader provides a comprehensive list of constants for standard HTTP headers, making it easy to reference and use common headers in your applications.

### 📂 Header Definition
Provides a Header struct that encapsulates important information about HTTP headers, including name, values, and applicability properties.

### 📦 Header Constructors
Offers helper functions like NewHeaders, NewAIMHeader, NewAcceptHeader, and many more, allowing developers to create headers with specified values efficiently.

## Installation
You can install it in your Go project using `go get`:

```sh
go get github.com/lindsaygelle/goheader
```

## Usage
Import the package into your Go code:

```Go
import (
	"github.com/lindsaygelle/goheader"
)
```

## Functions
Provided functions for `goheader`.

### NewAIMHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAIMHeader("feed")
	fmt.Println(header)
}
```

### NewAcceptHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptHeader("text/html")
	fmt.Println(header)
}
```

### NewAcceptCHHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptCHHeader("width")
	fmt.Println(header)
}
```

### NewAcceptCHLifetimeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptCHLifetimeHeader("86400")
	fmt.Println(header)
}
```

### NewAcceptCharsetHeader


```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptCharsetHeader("UTF-8")
	fmt.Println(header)
}
```

### NewAcceptDatetimeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptDatetimeHeader("Thu, 31 May 2007 20:35:00 GMT")
	fmt.Println(header)
}
```

### NewAcceptEncodingHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptEncodingHeader("gzip")
	fmt.Println(header)
}
```

### NewAcceptLanguageHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptLanguageHeader("en-AU")
	fmt.Println(header)
}
```

### NewAcceptPatchHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptPatchHeader("application/example", "text/example")
	fmt.Println(header)
}
```

### NewAcceptPostHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptPostHeader("application/example", "text/example")
	fmt.Println(header)
}
```

### NewAcceptRangesHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptRangesHeader("bytes")
	fmt.Println(header)
}
```

### NewAccessControlAllowCredentialsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowCredentialsHeader("true")
	fmt.Println(header)
}
```

### NewAccessControlAllowHeadersHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowHeadersHeader("*")
	fmt.Println(header)
}
```

### NewAccessControlAllowMethodsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowMethodsHeader("POST", "GET")
	fmt.Println(header)
}
```

### NewAccessControlAllowOriginHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowOriginHeader("*")
	fmt.Println(header)
}
```

### NewAccessControlExposeHeadersHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlExposeHeadersHeader("https://github.com")
	fmt.Println(header)
}
```

### NewAccessControlMaxAgeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlMaxAgeHeader("600")
	fmt.Println(header)
}
```

### NewAccessControlRequestHeadersHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlRequestHeadersHeader("Content-Type", "X-User-Addr")
	fmt.Println(header)
}
```

### NewAccessControlRequestMethodHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlRequestMethodHeader("GET")
	fmt.Println(header)
}
```

### NewAgeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAgeHeader("15")
	fmt.Println(header)
}
```

### NewAllowHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAllowHeader("HEAD", "GET")
	fmt.Println(header)
}
```

### NewAltSvcHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAltSvcHeader("h2=\"alt.example.com:443\"", "h2=\":443\"")
	fmt.Println(header)
}
```

### NewAltUsedHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAltUsedHeader("alternate.example.net")
	fmt.Println(header)
}
```

### NewAuthorizationHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAuthorizationHeader("Basic RXhhbXBsZTphaQ==")
	fmt.Println(header)
}
```

### NewCacheControlHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCacheControlHeader("max-age=604800")
	fmt.Println(header)
}
```

### NewClearSiteDataHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewClearSiteDataHeader("*")
	fmt.Println(header)
}
```

### NewConnectionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewConnectionHeader("keep-alive")
	fmt.Println(header)
}
```

### NewContentDPRHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentDPRHeader("1")
	fmt.Println(header)
}
```

### NewContentDispositionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentDispositionHeader("attachment; filename=\"document.doc\"")
	fmt.Println(header)
}
```

### NewContentEncodingHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentEncodingHeader("deflate", "br")
	fmt.Println(header)
}
```

### NewContentLanguageHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentLanguageHeader("en-AU")
	fmt.Println(header)
}
```

### NewContentLengthHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentLengthHeader("128")
	fmt.Println(header)
}
```

### NewContentLocationHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentLocationHeader("https://example.com/documents/foo")
	fmt.Println(header)
}
```

### NewContentMD5Header

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentMD5Header("b89f948e98f3a113dc13fdbd3bdb17ef")
	fmt.Println(header)
}
```

### NewContentRangeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentRangeHeader("1000-2000/*")
	fmt.Println(header)
}
```

### NewContentSecurityPolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentSecurityPolicyHeader("default-src 'self'; font-src fonts.gstatic.com; style-src 'self' fonts.googleapis.com")
	fmt.Println(header)
}
```

### NewContentSecurityPolicyReportOnlyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentSecurityPolicyReportOnlyHeader("default-src https:; report-to /csp-violation-report-endpoint/")
	fmt.Println(header)
}
```

### NewContentTypeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentTypeHeader("text/html; charset=utf-8")
	fmt.Println(header)
}
```

### NewCookieHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCookieHeader("PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1")
	fmt.Println(header)
}
```

### NewCorrelationIDHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCorrelationIDHeader("93dba609-c615-4513-b95b-0d3468ec20d0")
	fmt.Println(header)
}
```

### NewCriticalCHHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCriticalCHHeader("Sec-CH-Prefers-Reduced-Motion")
	fmt.Println(header)
}
```

### NewCrossOriginEmbedderPolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCrossOriginEmbedderPolicyHeader("require-corp")
	fmt.Println(header)
}
```

### NewCrossOriginOpenerPolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCrossOriginOpenerPolicyHeader("same-origin-allow-popups")
	fmt.Println(header)
}
```

### NewCrossOriginResourcePolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCrossOriginResourcePolicyHeader("same-origin")
	fmt.Println(header)
}
```

### NewDNTHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDNTHeader("1")
	fmt.Println(header)
}
```

### NewDPRHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDPRHeader("2.0")
	fmt.Println(header)
}
```

### NewDateHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDateHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}
```

### NewDeltaBaseHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDeltaBaseHeader("12340001")
	fmt.Println(header)
}
```

### NewDeviceMemoryHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDeviceMemoryHeader("2")
	fmt.Println(header)
}
```

### NewDigestHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDigestHeader("sha-512= 3b761a2a9a96e1c430236dc31378a3450ea189ae1449c3c8eac25cfa8b25381661317968a54cf46bfced09ae6b49f8512832182ac2d087b22380fcb760d802a3")
	fmt.Println(header)
}
```

### NewDownlinkHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDownlinkHeader("1.7")
	fmt.Println(header)
}
```

### NewECTHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewECTHeader("2g")
	fmt.Println(header)
}
```

### NewETagHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewETagHeader("33a64df551425fcc55e4d42a148795d9f25f89d4")
	fmt.Println(header)
}
```

### NewEarlyDataHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewEarlyDataHeader("1")
	fmt.Println(header)
}
```

### NewExpectHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewExpectHeader("100-continue")
	fmt.Println(header)
}
```

### NewExpectCTHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewExpectCTHeader("max-age=86400", "enforce", "report-uri=\"https://foo.example.com/report\"")
	fmt.Println(header)
}
```

### NewExpiresHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewExpiresHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}
```

### NewForwardedHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewForwardedHeader("for=192.0.2.43", "for=198.51.100.17")
	fmt.Println(header)
}
```

### NewFromHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewFromHeader("webmaster@example.org")
	fmt.Println(header)
}
```

### NewFrontEndHTTPSHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewFrontEndHTTPSHeader("on")
	fmt.Println(header)
}
```

### NewHTTP2SettingsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewHTTP2SettingsHeader("token64")
	fmt.Println(header)
}
```

### NewHostHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewHostHeader("Host")
	fmt.Println(header)
}
```

### NewIMHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIMHeader("feed")
	fmt.Println(header)
}
```

### NewIfMatchHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfMatchHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}
```

### NewIfModifiedSinceHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfModifiedSinceHeader("Sat, 29 Oct 1994 19:43:31 GMT")
	fmt.Println(header)
}
```

### NewIfNoneMatchHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfNoneMatchHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}
```

### NewIfRangeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfRangeHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}
```

### NewIfUnmodifiedSinceHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfUnmodifiedSinceHeader("Sat, 29 Oct 1994 19:43:31 GMT")
	fmt.Println(header)
}
```

### NewKeepAliveHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewKeepAliveHeader("timeout=5", "max=1000")
	fmt.Println(header)
}
```

### NewLargeAllocationHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLargeAllocationHeader("500")
	fmt.Println(header)
}
```

### NewLastModifiedHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLastModifiedHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}
```

### NewLinkHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLinkHeader("<https://one.example.com>; rel=\"preconnect\"", "<https://two.example.com>; rel=\"preconnect\"", "<https://three.example.com>; rel=\"preconnect\"")
	fmt.Println(header)
}
```

### NewLocationHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLocationHeader("/index.html")
	fmt.Println(header)
}
```

### NewMaxForwardsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewMaxForwardsHeader("10")
	fmt.Println(header)
}
```

### NewNELHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewNELHeader("{ \"report_to\": \"name_of_reporting_group\", \"max_age\": 12345, \"include_subdomains\": false, \"success_fraction\": 0.0, \"failure_fraction\": 1.0 }")
	fmt.Println(header)
}
```

### NewOriginHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewOriginHeader("https://example.com")
	fmt.Println(header)
}
```

### NewP3PHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewP3PHeader("CP=\"https://example.com/P3P\"")
	fmt.Println(header)
}
```

### NewPermissionsPolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPermissionsPolicyHeader("(\"https://example.com\" \"https://a.example.com\" \"https://b.example.com\" \"https://c.example.com\")")
	fmt.Println(header)
}
```

### NewPragmaHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPragmaHeader("no-cache")
	fmt.Println(header)
}
```

### NewPreferHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPreferHeader("respond-async", "wait=5")
	fmt.Println(header)
}
```

### NewPreferenceAppliedHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPreferenceAppliedHeader("return=representation")
	fmt.Println(header)
}
```

### NewProxyAuthenticateHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewProxyAuthenticateHeader("Basic realm=\"Access to the internal site\"")
	fmt.Println(header)
}
```

### NewProxyAuthorizationHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewProxyAuthorizationHeader("Basic YWxhZGRpbjpvcGVuc2VzYW1l")
	fmt.Println(header)
}
```

### NewProxyConnectionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewProxyConnectionHeader("keep-alive")
	fmt.Println(header)
}
```

### NewPublicKeyPinsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPublicKeyPinsHeader("max-age=2592000; pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\";")
	fmt.Println(header)
}
```

### NewRTTHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRTTHeader("123")
	fmt.Println(header)
}
```

### NewRangeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRangeHeader("bytes=200-1000", "2000-6576", "19000-")
	fmt.Println(header)
}
```

### NewRefererHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRefererHeader("https://example.com/")
	fmt.Println(header)
}
```

### NewReferrerPolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewReferrerPolicyHeader("no-referrer", "strict-origin-when-cross-origin")
	fmt.Println(header)
}
```

### NewRefreshHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRefreshHeader("5; url=http://www.w3.org/pub/WWW/People.html")
	fmt.Println(header)
}
```

### NewReportToHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewReportToHeader("{ \"group\": \"csp-endpoint\", \"max_age\": 10886400, \"endpoints\": [ { \"url\": \"https-url-of-site-which-collects-reports\" } ] }")
	fmt.Println(header)
}
```

### NewRetryAfterHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRetryAfterHeader("123")
	fmt.Println(header)
}
```

### NewSaveDataHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSaveDataHeader("on")
	fmt.Println(header)
}
```

### NewSecCHPrefersColorSchemeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHPrefersColorSchemeHeader("dark")
	fmt.Println(header)
}
```

### NewSecCHPrefersReducedMotionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHPrefersReducedMotionHeader("reduce")
	fmt.Println(header)
}
```

### NewSecCHPrefersReducedTransparencyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHPrefersReducedTransparencyHeader("reduce")
	fmt.Println(header)
}
```

### NewSecCHUAHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAHeader("\"Opera\";v=\"81\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"95\"")
	fmt.Println(header)
}
```

### NewSecCHUAArchHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAArchHeader("x86")
	fmt.Println(header)
}
```

### NewSecCHUABitnessHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUABitnessHeader("64")
	fmt.Println(header)
}
```

### NewSecCHUAFullVersionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAFullVersionHeader("96.0.4664.110")
	fmt.Println(header)
}
```

### NewSecCHUAFullVersionListHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAFullVersionListHeader("\" Not A;Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"98.0.4750.0\", \"Google Chrome\";v=\"98.0.4750.0\"")
	fmt.Println(header)
}
```

### NewSecCHUAMobileHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAMobileHeader("?1")
	fmt.Println(header)
}
```

### NewSecCHUAModelHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAModelHeader("Pixel 3 XL")
	fmt.Println(header)
}
```

### NewSecCHUAPlatformHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAPlatformHeader("macOS")
	fmt.Println(header)
}
```

### NewSecCHUAPlatformVersionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAPlatformVersionHeader("10.0.0")
	fmt.Println(header)
}
```

### NewSecFetchDestHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchDestHeader("image")
	fmt.Println(header)
}
```

### NewSecFetchModeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchModeHeader("no-cors")
	fmt.Println(header)
}
```

### NewSecFetchSiteHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchSiteHeader("cross-site")
	fmt.Println(header)
}
```

### NewSecFetchUserHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchUserHeader("?1")
	fmt.Println(header)
}
```

### NewSecGPCHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecGPCHeader("1")
	fmt.Println(header)
}
```

### NewSecPurposeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecPurposeHeader("prefetch")
	fmt.Println(header)
}
```

### NewSecWebSocketAcceptHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecWebSocketAcceptHeader("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	fmt.Println(header)
}
```

### NewServerHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewServerHeader("Apache/2.4.1 (Unix)")
	fmt.Println(header)
}
```

### NewServerTimingHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewServerTimingHeader("missedCache")
	fmt.Println(header)
}
```

### NewServiceWorkerNavigationPreloadHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewServiceWorkerNavigationPreloadHeader("json_fragment1")
	fmt.Println(header)
}
```

### NewSetCookieHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSetCookieHeader("id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GM")
	fmt.Println(header)
}
```

### NewSourceMapHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSourceMapHeader("/static/js/file.js")
	fmt.Println(header)
}
```

### NewStatusHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewStatusHeader("200 OK")
	fmt.Println(header)
}
```

### NewStrictTransportSecurityHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewStrictTransportSecurityHeader("max-age=63072000; includeSubDomains; preload")
	fmt.Println(header)
}
```

### NewTEHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTEHeader("compress, deflate;q=0.7")
	fmt.Println(header)
}
```

### NewTimingAllowOriginHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTimingAllowOriginHeader("https://www.example.com")
	fmt.Println(header)
}
```

### NewTKHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTKHeader("T")
	fmt.Println(header)
}
```

### NewTrailerHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTrailerHeader("Expires")
	fmt.Println(header)
}
```

### NewTransferEncodingHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTransferEncodingHeader("gzip", "chunked")
	fmt.Println(header)
}
```

### NewUpgradeHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewUpgradeHeader("example/1", "example/2")
	fmt.Println(header)
}
```

### NewUpgradeInsecureRequestsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewUpgradeInsecureRequestsHeader("1")
	fmt.Println(header)
}
```

### NewUserAgentHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewUserAgentHeader("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	fmt.Println(header)
}
```

### NewVaryHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewVaryHeader("Accept")
	fmt.Println(header)
}
```

### NewViaHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewViaHeader("HTTP/1.1 proxy.example.re", "1.1 edge_1")
	fmt.Println(header)
}
```

### NewViewportWidthHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewViewportWidthHeader("320")
	fmt.Println(header)
}
```

### NewWWWAuthenticateHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWWWAuthenticateHeader("Basic realm=\"Access to the staging site\", charset=\"UTF-8\"")
	fmt.Println(header)
}
```

### NewWantDigestHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWantDigestHeader("SHA-512;q=0.3, sha-256;q=1, md5;q=0")
	fmt.Println(header)
}
```

### NewWarningHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWarningHeader("112 - \"cache down\" \"Wed, 21 Oct 2015 07:28:00 GMT\"")
	fmt.Println(header)
}
```

### NewWidthHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWidthHeader("1920")
	fmt.Println(header)
}
```

### NewXATTDeviceIDHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXATTDeviceIDHeader("GT-P7320/P7320XXLPG")
	fmt.Println(header)
}
```

### NewXContentDurationHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXContentDurationHeader("42.666")
	fmt.Println(header)
}
```

### NewXContentSecurityPolicyHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXContentSecurityPolicyHeader("default-src 'self'")
	fmt.Println(header)
}
```

### NewXContentTypeOptionsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXContentTypeOptionsHeader("nosniff")
	fmt.Println(header)
}
```

### NewXCorrelationIDHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXCorrelationIDHeader("f058ebd6-02f7-4d3f-942e-904344e8cde5")
	fmt.Println(header)
}
```

### NewXCSRFTokenHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXCSRFTokenHeader("i8XNjC4b8KVok4uw5RftR38Wgp2BFwql")
	fmt.Println(header)
}
```

### NewXDNSPrefetchControlHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXDNSPrefetchControlHeader("off")
	fmt.Println(header)
}
```

### NewXForwardedForHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXForwardedForHeader("203.0.113.195", "2001:db8:85a3:8d3:1319:8a2e:370:7348")
	fmt.Println(header)
}
```

### NewXForwardedHostHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXForwardedHostHeader("id42.example-cdn.com")
	fmt.Println(header)
}
```

### NewXForwardedProtoHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXForwardedProtoHeader("https")
	fmt.Println(header)
}
```

### NewXFrameOptionsHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXFrameOptionsHeader("SAMEORIGIN")
	fmt.Println(header)
}
```

### NewXHTTPMethodOverrideHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXHTTPMethodOverrideHeader("DELETE")
	fmt.Println(header)
}
```

### NewXPoweredByHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXPoweredByHeader("PHP/5.4.0")
	fmt.Println(header)
}
```

### NewXRedirectByHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXRedirectByHeader("WordPress")
	fmt.Println(header)
}
```

### NewXRequestIDHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXRequestIDHeader("f058ebd6-02f7-4d3f-942e-904344e8cde5")
	fmt.Println(header)
}
```

### NewXRequestedWithHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXRequestedWithHeader("XMLHttpRequest")
	fmt.Println(header)
}
```

### NewXUACompatibleHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXUACompatibleHeader("IE=EmulateIE7")
	fmt.Println(header)
}
```

### NewXUIDHHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXUIDHHeader("...")
	fmt.Println(header)
}
```

### NewXWapProfileHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXWapProfileHeader("http://wap.samsungmobile.com/uaprof/SGH-I777.xml")
	fmt.Println(header)
}
```

### NewXWebKitCSPHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXWebKitCSPHeader("default-src 'self'")
	fmt.Println(header)
}
```

### NewXXSSProtectionHeader

```Go
// GitHub goheader example.
package main

// Import the goheader package.
import "github.com/lindsaygelle/goheader"

func main() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXXSSProtectionHeader("1; mode=block")
	fmt.Println(header)
}
```

## Examples

### ResponseWriter
Adding new Headers to an existing http.ResponseWriter.

```Go
// GitHub goheader example.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/lindsaygelle/goheader"
)

func main() {
	// Create a default handler.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Create a new set of goheader.Header instances.
		headers := []goheader.Header{
			goheader.NewContentLanguageHeader("en-AU"),
			goheader.NewContentTypeHeader("application/json"),
			goheader.NewCookieHeader("language=golang")}

		// Add the headers to the http.ResponseWriter.
		goheader.WriteHeaders(w, headers...)
		// Write the HTTP status code.
		w.WriteHeader(http.StatusOK)
		// Write the HTTP response.
		json.NewEncoder(w).Encode(w.Header()) // { "Content-Language": [ "en-AU" ], "Content-Type": [ "application/json" ], "Cookie": [ "language=golang" ] }
	})
	// Set the port for the server.
	serverAddress := fmt.Sprintf(":%d", 8080)
	// Serve content.
	log.Println(http.ListenAndServe(serverAddress, nil))
}
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
