// Package goheader_test provides testing the goheader package.
package goheader_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lindsaygelle/goheader"
)

// ExampleNewAIMHeader is an example function for NewAIMHeader.
func ExampleNewAIMHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptConfig{
		Values: []goheader.AcceptValue{
			{MediaType: "application/json", Quality: 1.0},
			{MediaType: "text/html", Quality: 0.8, Params: map[string]string{"charset": "utf-8"}},
		},
	}
	header := goheader.NewAcceptHeader(cfg)
	fmt.Println(header.Values) // ["application/json;q=1.0, text/html;charset=utf-8;q=0.8"]
}

// ExampleNewAcceptHeader is an example function for NewAcceptHeader.
func ExampleNewAcceptHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptCHConfig{
		Values: []goheader.AcceptCHValue{
			{Token: "DPR"},
			{Token: "Viewport-Width"},
		},
	}
	header := goheader.NewAcceptCHHeader(cfg)
	fmt.Println(header.Values) // ["DPR, Viewport-Width"]
}

// ExampleNewAcceptCHHeader is an example function for NewAcceptCHHeader.
func ExampleNewAcceptCHHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptCHLifetimeConfig{Lifetime: 86400}
	header := goheader.NewAcceptCHLifetimeHeader(cfg)
	fmt.Println(header.Values) // ["86400"]
}

// ExampleNewAcceptCHLifetimeHeader is an example function for NewAcceptCHLifetimeHeader.
func ExampleNewAcceptCHLifetimeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptCHLifetimeHeader("86400")
	fmt.Println(header)
}

// ExampleNewAcceptCharsetHeader is an example function for NewAcceptCharsetHeader.

func ExampleNewAcceptCharsetHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptCharsetConfig{
		Values: []goheader.AcceptCharsetValue{
			{Charset: "utf-8", Quality: 1.0},
			{Charset: "iso-8859-1", Quality: 0.5},
		},
	}
	header := goheader.NewAcceptCharsetHeader(cfg)
	fmt.Println(header.Values) // ["utf-8;q=1.0, iso-8859-1;q=0.5"]
}

// ExampleNewAcceptDatetimeHeader is an example function for NewAcceptDatetimeHeader.
func ExampleNewAcceptDatetimeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptDatetimeConfig{
		Datetime: time.Date(2023, 5, 1, 12, 30, 0, 0, time.UTC),
	}
	header := goheader.NewAcceptDatetimeHeader(cfg)
	fmt.Println(header.Values) // ["Mon, 01 May 2023 12:30:00 GMT"]
}

// ExampleNewAcceptEncodingHeader is an example function for NewAcceptEncodingHeader.
func ExampleNewAcceptEncodingHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptEncodingConfig{
		Values: []goheader.AcceptEncodingValue{
			{Encoding: "gzip", Quality: 1.0},
			{Encoding: "br", Quality: 0.8},
		},
	}
	header := goheader.NewAcceptEncodingHeader(cfg)
	fmt.Println(header.Values) // ["gzip;q=1.0, br;q=0.8"]
}

// ExampleNewAcceptLanguageHeader is an example function for NewAcceptLanguageHeader.
func ExampleNewAcceptLanguageHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptLanguageConfig{
		Values: []goheader.AcceptLanguageValue{
			{Language: "en-US", Quality: 1.0},
			{Language: "fr", Quality: 0.8},
		},
	}
	header := goheader.NewAcceptLanguageHeader(cfg)
	fmt.Println(header.Values) // ["en-US;q=1.0, fr;q=0.8"]
}

// ExampleNewAcceptPatchHeader is an example function for NewAcceptPatchHeader.
func ExampleNewAcceptPatchHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptPatchConfig{
		Values: []goheader.AcceptPatchValue{
			{MediaType: "application/json-patch+json"},
			{MediaType: "application/merge-patch+json"},
		},
	}
	header := goheader.NewAcceptPatchHeader(cfg)
	fmt.Println(header.Values) // ["application/json-patch+json, application/merge-patch+json"]
}

// ExampleNewAcceptPostHeader is an example function for NewAcceptPostHeader.
func ExampleNewAcceptPostHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptPostConfig{
		Values: []goheader.AcceptPostValue{
			{MediaType: "application/json"},
			{MediaType: "application/ld+json"},
		},
	}
	header := goheader.NewAcceptPostHeader(cfg)
	fmt.Println(header.Values) // ["application/json, application/ld+json"]
}

// ExampleNewAcceptRangesHeader is an example function for NewAcceptRangesHeader.
func ExampleNewAcceptRangesHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AcceptRangesConfig{
		Values: []goheader.AcceptRangesValue{
			{Unit: "bytes"},
		},
	}
	header := goheader.NewAcceptRangesHeader(cfg)
	fmt.Println(header.Values) // ["bytes"]
}

// ExampleNewAccessControlAllowCredentialsHeader is an example function for NewAccessControlAllowCredentialsHeader.
func ExampleNewAccessControlAllowCredentialsHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlAllowCredentialsConfig{AllowCredentials: true}
	header := goheader.NewAccessControlAllowCredentialsHeader(cfg)
	fmt.Println(header.Values) // ["true"]
}

// ExampleNewAccessControlAllowHeadersHeader is an example function for NewAccessControlAllowHeadersHeader.
func ExampleNewAccessControlAllowHeadersHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlAllowHeadersConfig{
		Values: []goheader.AccessControlAllowHeadersValue{
			{Header: "Content-Type"},
			{Header: "Authorization"},
		},
	}
	header := goheader.NewAccessControlAllowHeadersHeader(cfg)
	fmt.Println(header.Values) // ["Content-Type, Authorization"]
}

// ExampleNewAccessControlAllowMethodsHeader is an example function for NewAccessControlAllowMethodsHeader.
func ExampleNewAccessControlAllowMethodsHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlAllowMethodsConfig{
		Values: []goheader.AccessControlAllowMethodsValue{
			{Method: "GET"},
			{Method: "POST"},
			{Method: "OPTIONS"},
		},
	}
	header := goheader.NewAccessControlAllowMethodsHeader(cfg)
	fmt.Println(header.Values) // ["GET, POST, OPTIONS"]
}

// ExampleNewAccessControlAllowOriginHeader is an example function for NewAccessControlAllowOriginHeader.
func ExampleNewAccessControlAllowOriginHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlAllowOriginConfig{Origin: "https://example.com"}
	header := goheader.NewAccessControlAllowOriginHeader(cfg)
	fmt.Println(header.Values) // ["https://example.com"]
}

// ExampleNewAccessControlExposeHeadersHeader is an example function for NewAccessControlExposeHeadersHeader.
func ExampleNewAccessControlExposeHeadersHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlExposeHeadersConfig{
		Values: []goheader.AccessControlExposeHeadersValue{
			{Header: "Content-Length"},
			{Header: "X-Custom-Header"},
		},
	}
	header := goheader.NewAccessControlExposeHeadersHeader(cfg)
	fmt.Println(header.Values) // ["Content-Length, X-Custom-Header"]
}

// ExampleNewAccessControlMaxAgeHeader is an example function for NewAccessControlMaxAgeHeader.
func ExampleNewAccessControlMaxAgeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlMaxAgeConfig{Seconds: 600}
	header := goheader.NewAccessControlMaxAgeHeader(cfg)
	fmt.Println(header.Values) // ["600"]
}

// ExampleNewAccessControlRequestHeadersHeader is an example function for NewAccessControlRequestHeadersHeader.
func ExampleNewAccessControlRequestHeadersHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlRequestHeadersConfig{
		Values: []goheader.AccessControlRequestHeadersValue{
			{Header: "Content-Type"},
			{Header: "Authorization"},
		},
	}
	header := goheader.NewAccessControlRequestHeadersHeader(cfg)
	fmt.Println(header.Values) // ["Content-Type, Authorization"]
}

// ExampleNewAccessControlRequestMethodHeader is an example function for NewAccessControlRequestMethodHeader.
func ExampleNewAccessControlRequestMethodHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AccessControlRequestMethodConfig{Method: "POST"}
	header := goheader.NewAccessControlRequestMethodHeader(cfg)
	fmt.Println(header.Values) // ["POST"]
}

// ExampleNewAgeHeader is an example function for NewAgeHeader.
func ExampleNewAgeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AgeConfig{Seconds: 120}
	header := goheader.NewAgeHeader(cfg)
	fmt.Println(header.Values) // ["120"]
}

// ExampleNewAllowHeader is an example function for NewAllowHeader.
func ExampleNewAllowHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AllowConfig{
		Values: []goheader.AllowValue{
			{Method: "GET"},
			{Method: "POST"},
		},
	}
	header := goheader.NewAllowHeader(cfg)
	fmt.Println(header.Values) // ["GET, POST"]
}

// ExampleNewAltSvcHeader is an example function for NewAltSvcHeader.
func ExampleNewAltSvcHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AltSvcConfig{
		Values: []goheader.AltSvcValue{
			{Protocol: "h3", Host: ":443", MaxAge: 86400, Persist: true},
		},
	}
	header := goheader.NewAltSvcHeader(cfg)
	fmt.Println(header.Values) // [h3=":443"; ma=86400; persist=1]
}

// ExampleNewAltUsedHeader is an example function for NewAltUsedHeader.
func ExampleNewAltUsedHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AltUsedConfig{HostPort: "alt.example.com:443"}
	header := goheader.NewAltUsedHeader(cfg)
	fmt.Println(header.Values) // ["alt.example.com:443"]
}

// ExampleNewAuthorizationHeader is an example function for NewAuthorizationHeader.
func ExampleNewAuthorizationHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.AuthorizationConfig{
		Scheme:      "Bearer",
		Credentials: "token123",
	}
	header := goheader.NewAuthorizationHeader(cfg)
	fmt.Println(header.Values) // ["Bearer token123"]
}

// ExampleNewCacheControlHeader is an example function for NewCacheControlHeader.
func ExampleNewCacheControlHeader() {
	// Create a new goheader.Header instance.
	maxAge := 3600
	cfg := goheader.CacheControlConfig{
		Directives: []goheader.CacheControlDirective{
			{Directive: "max-age", Value: &maxAge},
			{Directive: "no-cache"},
		},
	}
	header := goheader.NewCacheControlHeader(cfg)
	fmt.Println(header.Values) // ["max-age=3600, no-cache"]
}

// ExampleNewClearSiteDataHeader is an example function for NewClearSiteDataHeader.
func ExampleNewClearSiteDataHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ClearSiteDataConfig{
		Directives: []goheader.ClearSiteDataDirective{
			{Directive: "cache"},
			{Directive: "cookies"},
			{Directive: "storage"},
		},
	}
	header := goheader.NewClearSiteDataHeader(cfg)
	fmt.Println(header.Values) // ["\"cache\", \"cookies\", \"storage\""]
}

// ExampleNewConnectionHeader is an example function for NewConnectionHeader.
func ExampleNewConnectionHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ConnectionConfig{
		Options: []goheader.ConnectionOption{
			{Option: "keep-alive"},
		},
	}
	header := goheader.NewConnectionHeader(cfg)
	fmt.Println(header.Values) // ["keep-alive"]
}

// ExampleNewContentDPRHeader is an example function for NewContentDPRHeader.
func ExampleNewContentDPRHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentDPRConfig{DPR: 2.0}
	header := goheader.NewContentDPRHeader(cfg)
	fmt.Println(header.Values) // ["2.0"]
}

// ExampleNewContentDispositionHeader is an example function for NewContentDispositionHeader.
func ExampleNewContentDispositionHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentDispositionConfig{
		Type: "attachment",
		Params: map[string]string{
			"filename": "example.txt",
		},
	}
	header := goheader.NewContentDispositionHeader(cfg)
	fmt.Println(header.Values) // ["attachment; filename=\"example.txt\""]
}

// ExampleNewContentEncodingHeader is an example function for NewContentEncodingHeader.
func ExampleNewContentEncodingHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentEncodingConfig{
		Values: []goheader.ContentEncodingValue{
			{Encoding: "gzip"},
			{Encoding: "br"},
		},
	}
	header := goheader.NewContentEncodingHeader(cfg)
	fmt.Println(header.Values) // ["gzip, br"]
}

// ExampleNewContentLanguageHeader is an example function for NewContentLanguageHeader.
func ExampleNewContentLanguageHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentLanguageConfig{
		Values: []goheader.ContentLanguageValue{
			{Language: "en"},
			{Language: "fr"},
		},
	}
	header := goheader.NewContentLanguageHeader(cfg)
	fmt.Println(header.Values) // ["en, fr"]
}

// ExampleNewContentLengthHeader is an example function for NewContentLengthHeader.
func ExampleNewContentLengthHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentLengthConfig{Bytes: 1024}
	header := goheader.NewContentLengthHeader(cfg)
	fmt.Println(header.Values) // ["1024"]
}

// ExampleNewContentLocationHeader is an example function for NewContentLocationHeader.
func ExampleNewContentLocationHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentLocationConfig{URL: "https://example.com/data.json"}
	header := goheader.NewContentLocationHeader(cfg)
	fmt.Println(header.Values) // ["https://example.com/data.json"]
}

// ExampleNewContentMD5Header is an example function for NewContentMD5Header.
func ExampleNewContentMD5Header() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentMD5Config{Checksum: "Q2hlY2sgSW50ZWdyaXR5IQ=="}
	header := goheader.NewContentMD5Header(cfg)
	fmt.Println(header.Values) // ["Q2hlY2sgSW50ZWdyaXR5IQ=="]
}

// ExampleNewContentRangeHeader is an example function for NewContentRangeHeader.
func ExampleNewContentRangeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentRangeConfig{Unit: "bytes", Start: 0, End: 499, Size: 1234}
	header := goheader.NewContentRangeHeader(cfg)
	fmt.Println(header.Values) // ["bytes 0-499/1234"]
}

// ExampleNewContentSecurityPolicyHeader is an example function for NewContentSecurityPolicyHeader.
func ExampleNewContentSecurityPolicyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentSecurityPolicyConfig{
		Directives: []goheader.CSPDirective{
			{Directive: "default-src", Sources: []string{"'self'"}},
			{Directive: "script-src", Sources: []string{"'self'", "https://apis.example.com"}},
		},
	}
	header := goheader.NewContentSecurityPolicyHeader(cfg)
	fmt.Println(header.Values) // ["default-src 'self'; script-src 'self' https://apis.example.com"]
}

// ExampleNewContentSecurityPolicyReportOnlyHeader is an example function for NewContentSecurityPolicyReportOnlyHeader.
func ExampleNewContentSecurityPolicyReportOnlyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentSecurityPolicyReportOnlyConfig{
		Directives: []goheader.CSPDirective{
			{Directive: "default-src", Sources: []string{"'self'"}},
			{Directive: "script-src", Sources: []string{"'self'", "https://apis.example.com"}},
		},
	}
	header := goheader.NewContentSecurityPolicyReportOnlyHeader(cfg)
	fmt.Println(header.Values) // ["default-src 'self'; script-src 'self' https://apis.example.com"]
}

// ExampleNewContentTypeHeader is an example function for NewContentTypeHeader.
func ExampleNewContentTypeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ContentTypeConfig{
		MediaType: "application/json",
		Params:    map[string]string{"charset": "UTF-8"},
	}
	header := goheader.NewContentTypeHeader(cfg)
	fmt.Println(header.Values) // ["application/json; charset=UTF-8"]
}

// ExampleNewCookieHeader is an example function for NewCookieHeader.
func ExampleNewCookieHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.CookieConfig{
		Cookies: []goheader.CookieValue{
			{Name: "sessionId", Value: "abc123"},
			{Name: "theme", Value: "dark"},
		},
	}
	header := goheader.NewCookieHeader(cfg)
	fmt.Println(header.Values) // ["sessionId=abc123; theme=dark"]
}

// ExampleNewCorrelationIDHeader is an example function for NewCorrelationIDHeader.
func ExampleNewCorrelationIDHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.CorrelationIDConfig{ID: "123e4567-e89b-12d3-a456-426614174000"}
	header := goheader.NewCorrelationIDHeader(cfg)
	fmt.Println(header.Values) // ["123e4567-e89b-12d3-a456-426614174000"]
}

// ExampleNewCriticalCHHeader is an example function for NewCriticalCHHeader.
func ExampleNewCriticalCHHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.CriticalCHConfig{Hints: []string{"DPR", "Width", "Viewport-Width"}}
	header := goheader.NewCriticalCHHeader(cfg)
	fmt.Println(header.Values) // ["DPR, Width, Viewport-Width"]
}

// ExampleNewCrossOriginEmbedderPolicyHeader is an example function for NewCrossOriginEmbedderPolicyHeader.
func ExampleNewCrossOriginEmbedderPolicyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.CrossOriginEmbedderPolicyConfig{Policy: "require-corp"}
	header := goheader.NewCrossOriginEmbedderPolicyHeader(cfg)
	fmt.Println(header.Values) // ["require-corp"]
}

// ExampleNewCrossOriginOpenerPolicyHeader is an example function for NewCrossOriginOpenerPolicyHeader.
func ExampleNewCrossOriginOpenerPolicyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.CrossOriginOpenerPolicyConfig{Policy: "same-origin"}
	header := goheader.NewCrossOriginOpenerPolicyHeader(cfg)
	fmt.Println(header.Values) // ["same-origin"]
}

// ExampleNewCrossOriginResourcePolicyHeader is an example function for NewCrossOriginResourcePolicyHeader.
func ExampleNewCrossOriginResourcePolicyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.CrossOriginResourcePolicyConfig{Policy: "same-origin"}
	header := goheader.NewCrossOriginResourcePolicyHeader(cfg)
	fmt.Println(header.Values) // ["same-origin"]
}

// ExampleNewDNTHeader is an example function for NewDNTHeader.
func ExampleNewDNTHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DNTConfig{Value: "1"}
	header := goheader.NewDNTHeader(cfg)
	fmt.Println(header.Values) // ["1"]
}

// ExampleNewDPRHeader is an example function for NewDPRHeader.
func ExampleNewDPRHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DPRConfig{Value: 2.0}
	header := goheader.NewDPRHeader(cfg)
	fmt.Println(header.Values) // ["2.0"])
}

// ExampleNewDateHeader is an example function for NewDateHeader.
func ExampleNewDateHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DateConfig{Time: time.Now()}
	header := goheader.NewDateHeader(cfg)
	fmt.Println(header.Values) // ["Mon, 02 Jan 2006 15:04:05 GMT"]
}

// ExampleNewDeltaBaseHeader is an example function for NewDeltaBaseHeader.
func ExampleNewDeltaBaseHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DeltaBaseConfig{ETag: "\"abc123etag\""}
	header := goheader.NewDeltaBaseHeader(cfg)
	fmt.Println(header.Values) // ["\"abc123etag\""]
}

// ExampleNewDeviceMemoryHeader is an example function for NewDeviceMemoryHeader.
func ExampleNewDeviceMemoryHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DeviceMemoryConfig{GB: 4}
	header := goheader.NewDeviceMemoryHeader(cfg)
	fmt.Println(header.Values) // ["4"]
}

// ExampleNewDigestHeader is an example function for NewDigestHeader.
func ExampleNewDigestHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DigestConfig{
		Values: []goheader.DigestValue{
			{Algorithm: "SHA-256", Hash: "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
		},
	}
	header := goheader.NewDigestHeader(cfg)
	fmt.Println(header.Values) // ["SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="]
}

// ExampleNewDownlinkHeader is an example function for NewDownlinkHeader.
func ExampleNewDownlinkHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.DownlinkConfig{Mbps: 10.2}
	header := goheader.NewDownlinkHeader(cfg)
	fmt.Println(header.Values) // ["10.2"]
}

// ExampleNewECTHeader is an example function for NewECTHeader.
func ExampleNewECTHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ECTConfig{Type: "4g"}
	header := goheader.NewECTHeader(cfg)
	fmt.Println(header.Values) // ["4g"]
}

// ExampleNewETagHeader is an example function for NewETagHeader.
func ExampleNewETagHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ETagConfig{Value: "\"abc123\""}
	header := goheader.NewETagHeader(cfg)
	fmt.Println(header.Values) // ["\"abc123\""]
}

// ExampleNewEarlyDataHeader is an example function for NewEarlyDataHeader.
func ExampleNewEarlyDataHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.EarlyDataConfig{Value: "1"}
	header := goheader.NewEarlyDataHeader(cfg)
	fmt.Println(header.Values) // ["1"]
}

// ExampleNewExpectHeader is an example function for NewExpectHeader.
func ExampleNewExpectHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ExpectConfig{Directives: []string{"100-continue"}}
	header := goheader.NewExpectHeader(cfg)
	fmt.Println(header.Values) // ["100-continue"]
}

// ExampleNewExpectCTHeader is an example function for NewExpectCTHeader.
func ExampleNewExpectCTHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ExpectCTConfig{MaxAge: 86400, Enforce: true, ReportURI: "https://example.com/report"}
	header := goheader.NewExpectCTHeader(cfg)
	fmt.Println(header.Values) // ["max-age=86400, enforce, report-uri=\"https://example.com/report\""]
}

// ExampleNewExpiresHeader is an example function for NewExpiresHeader.
func ExampleNewExpiresHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ExpiresConfig{Time: time.Now().Add(24 * time.Hour)}
	header := goheader.NewExpiresHeader(cfg)
	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
}

// ExampleNewForwardedHeader is an example function for NewForwardedHeader.
func ExampleNewForwardedHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ForwardedConfig{
		For:   "192.0.2.43",
		By:    "203.0.113.43",
		Proto: "https",
		Host:  "example.com",
	}
	header := goheader.NewForwardedHeader(cfg)
	fmt.Println(header.Values) // ["for=192.0.2.43; by=203.0.113.43; proto=https; host=example.com"]
}

// ExampleNewFromHeader is an example function for NewFromHeader.
func ExampleNewFromHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.FromConfig{Email: "user@example.com"}
	header := goheader.NewFromHeader(cfg)
	fmt.Println(header.Values) // ["user@example.com"]
}

// ExampleNewFrontEndHTTPSHeader is an example function for NewFrontEndHTTPSHeader.
func ExampleNewFrontEndHTTPSHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.FrontEndHTTPSConfig{Enabled: true}
	header := goheader.NewFrontEndHttpsHeader(cfg)
	fmt.Println(header.Values) // ["on"]
}

// ExampleNewHTTP2SettingsHeader is an example function for NewHTTP2SettingsHeader.
func ExampleNewHTTP2SettingsHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.HTTP2SettingsConfig{Settings: "AAMAAABkAAQAAP__"}
	header := goheader.NewHTTP2SettingsHeader(cfg)
	fmt.Println(header.Values) // ["AAMAAABkAAQAAP__"]
}

// ExampleNewHostHeader is an example function for NewHostHeader.
func ExampleNewHostHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.HostConfig{Host: "example.com:8080"}
	header := goheader.NewHostHeader(cfg)
	fmt.Println(header.Values) // ["example.com:8080"]
}

// ExampleNewIMHeader is an example function for NewIMHeader.
func ExampleNewIMHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.IMConfig{Values: []string{"vcdiff", "gzip"}}
	header := goheader.NewIMHeader(cfg)
	fmt.Println(header.Values) // ["vcdiff, gzip"]
}

// ExampleNewIfMatchHeader is an example function for NewIfMatchHeader.
func ExampleNewIfMatchHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.IfMatchConfig{ETags: []string{"\"abc123\"", "\"xyz456\""}}
	header := goheader.NewIfMatchHeader(cfg)
	fmt.Println(header.Values) // ["\"abc123\", \"xyz456\""]
}

// ExampleNewIfModifiedSinceHeader is an example function for NewIfModifiedSinceHeader.
func ExampleNewIfModifiedSinceHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.IfModifiedSinceConfig{Time: time.Now().Add(-24 * time.Hour)}
	header := goheader.NewIfModifiedSinceHeader(cfg)
	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
}

// ExampleNewIfNoneMatchHeader is an example function for NewIfNoneMatchHeader.
func ExampleNewIfNoneMatchHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.IfNoneMatchConfig{ETags: []string{"\"abc123\"", "\"xyz456\""}}
	header := goheader.NewIfNoneMatchHeader(cfg)
	fmt.Println(header.Values) // ["\"abc123\", \"xyz456\""]
}

// ExampleNewIfRangeHeader is an example function for NewIfRangeHeader.
func ExampleNewIfRangeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.IfRangeConfig{ETag: "\"abc123\""}
	header := goheader.NewIfRangeHeader(cfg)
	fmt.Println(header.Values) // ["\"abc123\""]
}

// ExampleNewIfUnmodifiedSinceHeader is an example function for NewIfUnmodifiedSinceHeader.
func ExampleNewIfUnmodifiedSinceHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.IfUnmodifiedSinceConfig{Time: time.Now().Add(-24 * time.Hour)}
	header := goheader.NewIfUnmodifiedSinceHeader(cfg)
	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
}

// ExampleNewKeepAliveHeader is an example function for NewKeepAliveHeader.
func ExampleNewKeepAliveHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.KeepAliveConfig{Timeout: 5, Max: 1000}
	header := goheader.NewKeepAliveHeader(cfg)
	fmt.Println(header.Values) // ["timeout=5, max=1000"]
}

// ExampleNewLargeAllocationHeader is an example function for NewLargeAllocationHeader.
func ExampleNewLargeAllocationHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.LargeAllocationConfig{Size: 5000}
	header := goheader.NewLargeAllocationHeader(cfg)
	fmt.Println(header.Values) // ["5000"]
}

// ExampleNewLastModifiedHeader is an example function for NewLastModifiedHeader.
func ExampleNewLastModifiedHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.LastModifiedConfig{Time: time.Now().Add(-48 * time.Hour)}
	header := goheader.NewLastModifiedHeader(cfg)
	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
}

// ExampleNewLinkHeader is an example function for NewLinkHeader.
func ExampleNewLinkHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.LinkConfig{
		Links: []goheader.LinkEntry{
			{URL: "https://example.com/page2", Attributes: map[string]string{"rel": "next"}},
			{URL: "https://example.com/page1", Attributes: map[string]string{"rel": "prev"}},
		},
	}
	header := goheader.NewLinkHeader(cfg)
	fmt.Println(header.Values) // ["<https://example.com/page2>; rel=\"next\", <https://example.com/page1>; rel=\"prev\""]
}

// ExampleNewLocationHeader is an example function for NewLocationHeader.
func ExampleNewLocationHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.LocationConfig{URL: "https://example.com/newpage"}
	header := goheader.NewLocationHeader(cfg)
	fmt.Println(header.Values) // ["https://example.com/newpage"]
}

// ExampleNewMaxForwardsHeader is an example function for NewMaxForwardsHeader.
func ExampleNewMaxForwardsHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.MaxForwardsConfig{Count: 5}
	header := goheader.NewMaxForwardsHeader(cfg)
	fmt.Println(header.Values) // ["5"]
}

// ExampleNewNELHeader is an example function for NewNELHeader.
func ExampleNewNELHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.NELConfig{Policy: `{"report_to": "endpoint-1", "max_age": 2592000, "include_subdomains": true}`}
	header := goheader.NewNELHeader(cfg)
	fmt.Println(header.Values) // [`{"report_to": "endpoint-1", "max_age": 2592000, "include_subdomains": true}`]
}

// ExampleNewOriginHeader is an example function for NewOriginHeader.
func ExampleNewOriginHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.OriginConfig{URL: "https://example.com"}
	header := goheader.NewOriginHeader(cfg)
	fmt.Println(header.Values) // ["https://example.com"]
}

// ExampleNewP3PHeader is an example function for NewP3PHeader.
func ExampleNewP3PHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.P3PConfig{Policy: `CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"`}
	header := goheader.NewP3PHeader(cfg)
	fmt.Println(header.Values) // [`CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"`]
}

// ExampleNewPermissionsPolicyHeader is an example function for NewPermissionsPolicyHeader.
func ExampleNewPermissionsPolicyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.PermissionsPolicyConfig{
		Directives: map[string][]string{
			"geolocation": {"self"},
			"microphone":  {},
		},
	}
	header := goheader.NewPermissionsPolicyHeader(cfg)
	fmt.Println(header.Values) // ["geolocation=(self), microphone=()"]
}

// ExampleNewPragmaHeader is an example function for NewPragmaHeader.
func ExampleNewPragmaHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.PragmaConfig{Directives: []string{"no-cache"}}
	header := goheader.NewPragmaHeader(cfg)
	fmt.Println(header.Values) // ["no-cache"]
}

// ExampleNewPreferHeader is an example function for NewPreferHeader.
func ExampleNewPreferHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.PreferConfig{Directives: []string{"return=minimal", "wait=10"}}
	header := goheader.NewPreferHeader(cfg)
	fmt.Println(header.Values) // ["return=minimal, wait=10"]
}

// ExampleNewPreferenceAppliedHeader is an example function for NewPreferenceAppliedHeader.
func ExampleNewPreferenceAppliedHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.PreferenceAppliedConfig{Directives: []string{"return=minimal"}}
	header := goheader.NewPreferenceAppliedHeader(cfg)
	fmt.Println(header.Values) // ["return=minimal"]
}

// ExampleNewPriorityConfigHeader is an example function for NewPriorityHeader.
func ExampleNewPriorityConfigHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.PriorityConfig{Urgency: 3, Incremental: true}
	header := goheader.NewPriorityHeader(cfg)
	fmt.Println(header.Values) // ["u=3, i"]
}

// ExampleNewProxyAuthenticateHeader is an example function for NewProxyAuthenticateHeader.
func ExampleNewProxyAuthenticateHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ProxyAuthenticateConfig{Schemes: []string{"Basic realm=\"Access to internal site\""}}
	header := goheader.NewProxyAuthenticateHeader(cfg)
	fmt.Println(header.Values) // ["Basic realm=\"Access to internal site\""]
}

// ExampleNewProxyAuthenticationInfoConfig is an example function for NewProxyAuthenticationInfoConfig
func ExampleNewProxyAuthenticationInfoConfig() {
	// Create a new goheader.Header instance.
	cfg := goheader.ProxyAuthenticationInfoConfig{Params: map[string]string{"nextnonce": "abc123", "qop": "auth"}}
	header := goheader.NewProxyAuthenticationInfoHeader(cfg)
	fmt.Println(header.Values) // ["nextnonce=\"abc123\", qop=\"auth\""]
}

// ExampleNewProxyAuthorizationHeader is an example function for NewProxyAuthorizationHeader.
func ExampleNewProxyAuthorizationHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ProxyAuthorizationConfig{Credentials: "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}
	header := goheader.NewProxyAuthorizationHeader(cfg)
	fmt.Println(header.Values) // ["Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]
}

// ExampleNewProxyConnectionHeader is an example function for NewProxyConnectionHeader.
func ExampleNewProxyConnectionHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ProxyConnectionConfig{Directives: []string{"keep-alive"}}
	header := goheader.NewProxyConnectionHeader(cfg)
	fmt.Println(header.Values) // ["keep-alive"]
}

// ExampleNewPublicKeyPinsHeader is an example function for NewPublicKeyPinsHeader.
func ExampleNewPublicKeyPinsHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.PublicKeyPinsConfig{
		Pins:              []string{"base64+primary==", "base64+backup=="},
		MaxAge:            5184000,
		IncludeSubDomains: true,
		ReportURI:         "https://example.com/hpkp-report",
	}
	header := goheader.NewPublicKeyPinsHeader(cfg)
	fmt.Println(header.Values)
	// ["pin-sha256=\"base64+primary==\"; pin-sha256=\"base64+backup==\"; max-age=5184000; includeSubDomains; report-uri=\"https://example.com/hpkp-report\""]
}

// ExampleNewPublicKeyPinsHeaderReportOnly is an example function for NewPublicKeyPinsReportOnlyHeader.

func ExampleNewPublicKeyPinsHeaderReportOnly() {
	// Create a new goheader.Header instance.
	cfg := goheader.PublicKeyPinsReportOnlyConfig{
		Pins:              []string{"base64+primary==", "base64+backup=="},
		MaxAge:            5184000,
		IncludeSubDomains: true,
		ReportURI:         "https://example.com/hpkp-report",
	}
	header := goheader.NewPublicKeyPinsReportOnlyHeader(cfg)
	fmt.Println(header.Values)
	// ["pin-sha256=\"base64+primary==\"; pin-sha256=\"base64+backup==\"; max-age=5184000; includeSubDomains; report-uri=\"https://example.com/hpkp-report\""]
}

// ExampleNewRTTHeader is an example function for NewRTTHeader.
func ExampleNewRTTHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.RTTConfig{Milliseconds: 150}
	header := goheader.NewRTTHeader(cfg)
	fmt.Println(header.Values) // ["150"]
}

// ExampleNewRangeHeader is an example function for NewRangeHeader.
func ExampleNewRangeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.RangeConfig{
		Unit:   "bytes",
		Ranges: [][2]int64{{200, 1000}, {1500, -1}},
	}
	header := goheader.NewRangeHeader(cfg)
	fmt.Println(header.Values) // ["bytes=200-1000,1500-"]
}

// ExampleNewRefererHeader is an example function for NewRefererHeader.
func ExampleNewRefererHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.RefererConfig{URL: "https://example.com/page"}
	header := goheader.NewRefererHeader(cfg)
	fmt.Println(header.Values) // ["https://example.com/page"]
}

// ExampleNewReferrerPolicyHeader is an example function for NewReferrerPolicyHeader.
func ExampleNewReferrerPolicyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ReferrerPolicyConfig{Policy: "strict-origin-when-cross-origin"}
	header := goheader.NewReferrerPolicyHeader(cfg)
	fmt.Println(header.Values) // ["strict-origin-when-cross-origin"]
}

// ExampleNewRefreshHeader is an example function for NewRefreshHeader.
func ExampleNewRefreshHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.RefreshConfig{DelaySeconds: 5, RedirectURL: "https://example.com/new-page"}
	header := goheader.NewRefreshHeader(cfg)
	fmt.Println(header.Values) // ["5; url=https://example.com/new-page"]
}

// NewReplayNonceHeader is an example function for NewReplayNonceHeader.
func ExampleNewReplayNonceHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ReplayNonceConfig{Nonce: "abc123XYZ"}
	header := goheader.NewReplayNonceHeader(cfg)
	fmt.Println(header.Values) // ["abc123XYZ"]
}

// ExampleNewReportingEndpointsHeader is an example function for NewReportingEndpointsHeader.
func ExampleNewReportingEndpointsHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ReportingEndpointsConfig{
		Endpoints: map[string]string{
			"default": "https://example.com/reports",
			"csp":     "https://example.com/csp-reports",
		},
	}
	header := goheader.NewReportingEndpointsHeader(cfg)
	fmt.Println(header.Values)
	// ["default=\"https://example.com/reports\", csp=\"https://example.com/csp-reports\""]
}

// ExampleNewReportToHeader is an example function for NewReportToHeader.
func ExampleNewReportToHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.ReportToConfig{
		Group:             "csp-endpoint",
		MaxAge:            10886400,
		Endpoints:         []string{"https://example.com/csp-reports"},
		IncludeSubdomains: true,
	}
	header := goheader.NewReportToHeader(cfg)
	fmt.Println(header.Values)
	// ['{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://example.com/csp-reports"}],"include_subdomains":true}']
}

// ExampleNewRetryAfterHeader is an example function for NewRetryAfterHeader.
func ExampleNewRetryAfterHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.RetryAfterConfig{Seconds: 120}
	header := goheader.NewRetryAfterHeader(cfg)
	fmt.Println(header.Values) // ["120"]

	cfg2 := goheader.RetryAfterConfig{Date: "Wed, 21 Oct 2015 07:28:00 GMT"}
	header2 := goheader.NewRetryAfterHeader(cfg2)
	fmt.Println(header2.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
}

// ExampleNewSaveDataHeader is an example function for NewSaveDataHeader.
func ExampleNewSaveDataHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SaveDataConfig{Enabled: true}
	header := goheader.NewSaveDataHeader(cfg)
	fmt.Println(header.Values) // ["on"]
}

// ExampleNewSecCHPrefersColorSchemeHeader is an example function for NewSecCHPrefersColorSchemeHeader.
func ExampleNewSecCHPrefersColorSchemeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHPrefersColorSchemeConfig{Preference: "dark"}
	header := goheader.NewSecCHPrefersColorSchemeHeader(cfg)
	fmt.Println(header.Values) // ["dark"]
}

// ExampleNewSecCHPrefersReducedMotionHeader is an example function for NewSecCHPrefersReducedMotionHeader.
func ExampleNewSecCHPrefersReducedMotionHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHPrefersReducedMotionConfig{Preference: "reduce"}
	header := goheader.NewSecCHPrefersReducedMotionHeader(cfg)
	fmt.Println(header.Values) // ["reduce"]
}

// ExampleNewSecCHPrefersReducedTransparencyHeader is an example function for NewSecCHPrefersReducedTransparencyHeader.
func ExampleNewSecCHPrefersReducedTransparencyHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHPrefersReducedTransparencyConfig{Preference: "reduce"}
	header := goheader.NewSecCHPrefersReducedTransparencyHeader(cfg)
	fmt.Println(header.Values) // ["reduce"]
}

// ExampleNewSecCHUAHeader is an example function for NewSecCHUAHeader.
func ExampleNewSecCHUAHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAConfig{Brands: map[string]string{
		"Chromium":      "112",
		"Google Chrome": "112",
	}}
	header := goheader.NewSecCHUAHeader(cfg)
	fmt.Println(header.Values)
	// ["\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\""
}

// ExampleNewSecCHUAArchHeader is an example function for NewSecCHUAArchHeader.
func ExampleNewSecCHUAArchHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAArchConfig{Architecture: "x86"}
	header := goheader.NewSecCHUAArchHeader(cfg)
	fmt.Println(header.Values) // ["\"x86\""]
}

// ExampleNewSecCHUABitnessHeader is an example function for NewSecCHUABitnessHeader.
func ExampleNewSecCHUABitnessHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUABitnessConfig{Bitness: "64"}
	header := goheader.NewSecCHUABitnessHeader(cfg)
	fmt.Println(header.Values) // ["\"64\""]
}

// ExampleNewSecCHUAFullVersionHeader is an example function for NewSecCHUAFullVersionHeader.
func ExampleNewSecCHUAFullVersionHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAFullVersionConfig{
		Brands: map[string]string{"Chromium": "112.0.5615.137"},
	}
	header := goheader.NewSecCHUAFullVersionHeader(cfg)
	fmt.Println(header.Values) // ["\"Chromium\";v=\"112.0.5615.137\""]
}

// ExampleNewSecCHUAFullVersionListHeader is an example function for NewSecCHUAFullVersionListHeader.
func ExampleNewSecCHUAFullVersionListHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAFullVersionListConfig{
		Brands: map[string]string{
			"Chromium":      "112.0.5615.137",
			"Google Chrome": "112.0.5615.137",
		},
	}
	header := goheader.NewSecCHUAFullVersionListHeader(cfg)
	fmt.Println(header.Values)
	// ["\"Chromium\";v=\"112.0.5615.137\", \"Google Chrome\";v=\"112.0.5615.137\""]
}

// ExampleNewSecCHUAMobileHeader is an example function for NewSecCHUAMobileHeader.
func ExampleNewSecCHUAMobileHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAMobileConfig{IsMobile: true}
	header := goheader.NewSecCHUAMobileHeader(cfg)
	fmt.Println(header.Values) // ["?1"]
}

// ExampleNewSecCHUAModelHeader is an example function for NewSecCHUAModelHeader.
func ExampleNewSecCHUAModelHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAModelConfig{Model: "Pixel 6"}
	header := goheader.NewSecCHUAModelHeader(cfg)
	fmt.Println(header.Values) // ["\"Pixel 6\""]
}

// ExampleNewSecCHUAPlatformHeader is an example function for NewSecCHUAPlatformHeader.
func ExampleNewSecCHUAPlatformHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAPlatformConfig{Platform: "Windows"}
	header := goheader.NewSecCHUAPlatformHeader(cfg)
	fmt.Println(header.Values) // ["\"Windows\""]
}

// ExampleNewSecCHUAPlatformVersionHeader is an example function for NewSecCHUAPlatformVersionHeader.
func ExampleNewSecCHUAPlatformVersionHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAPlatformVersionConfig{Version: "15.4"}
	header := goheader.NewSecCHUAPlatformVersionHeader(cfg)
	fmt.Println(header.Values) // ["\"15.4\""]
}

// ExampleNewSecCHUAPlatformVersionHeader is an example function for NewSecCHUAWoW64Header.
func ExampleNewSecCHUAWoW64Header() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecCHUAWoW64Config{WoW64: true}
	header := goheader.NewSecCHUAWoW64Header(cfg)
	fmt.Println(header.Values) // ["?1"]
}

// ExampleNewSecFetchDestHeader is an example function for NewSecFetchDestHeader.
func ExampleNewSecFetchDestHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecFetchDestConfig{Destination: "script"}
	header := goheader.NewSecFetchDestHeader(cfg)
	fmt.Println(header.Values) // ["script"]
}

// ExampleNewSecFetchModeHeader is an example function for NewSecFetchModeHeader.
func ExampleNewSecFetchModeHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecFetchModeConfig{Mode: "cors"}
	header := goheader.NewSecFetchModeHeader(cfg)
	fmt.Println(header.Values) // ["cors"]
}

// ExampleNewSecFetchSiteHeader is an example function for NewSecFetchSiteHeader.
func ExampleNewSecFetchSiteHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecFetchSiteConfig{Site: "same-origin"}
	header := goheader.NewSecFetchSiteHeader(cfg)
	fmt.Println(header.Values) // ["same-origin"]
}

// ExampleNewSecFetchUserHeader is an example function for NewSecFetchUserHeader.
func ExampleNewSecFetchUserHeader() {
	// Create a new goheader.Header instance.
	cfg := goheader.SecFetchUserConfig{Activated: true}
	header := goheader.NewSecFetchUserHeader(cfg)
	fmt.Println(header.Values) // ["?1"]
}

// ExampleNewSecGPCHeader is an example function for NewSecGPCHeader.
func ExampleNewSecGPCHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecGPCHeader("1")
	fmt.Println(header)
}

// ExampleNewSecPurposeHeader is an example function for NewSecPurposeHeader.
func ExampleNewSecPurposeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecPurposeHeader("prefetch")
	fmt.Println(header)
}

// ExampleNewSecWebSocketAcceptHeader is an example function for NewSecWebSocketAcceptHeader.
func ExampleNewSecWebSocketAcceptHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecWebSocketAcceptHeader("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	fmt.Println(header)
}

// ExampleNewServerHeader is an example function for NewServerHeader.
func ExampleNewServerHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewServerHeader("Apache/2.4.1 (Unix)")
	fmt.Println(header)
}

// ExampleNewServerTimingHeader is an example function for NewServerTimingHeader.
func ExampleNewServerTimingHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewServerTimingHeader("missedCache")
	fmt.Println(header)
}

// ExampleNewServiceWorkerNavigationPreloadHeader is an example function for NewServiceWorkerNavigationPreloadHeader.
func ExampleNewServiceWorkerNavigationPreloadHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewServiceWorkerNavigationPreloadHeader("json_fragment1")
	fmt.Println(header)
}

// ExampleNewSetCookieHeader is an example function for NewSetCookieHeader.
func ExampleNewSetCookieHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSetCookieHeader("id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GM")
	fmt.Println(header)
}

// ExampleNewSourceMapHeader is an example function for NewSourceMapHeader.
func ExampleNewSourceMapHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSourceMapHeader("/static/js/file.js")
	fmt.Println(header)
}

// ExampleNewStatusHeader is an example function for NewStatusHeader.
func ExampleNewStatusHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewStatusHeader("200 OK")
	fmt.Println(header)
}

// ExampleNewStrictTransportSecurityHeader is an example function for NewStrictTransportSecurityHeader.
func ExampleNewStrictTransportSecurityHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewStrictTransportSecurityHeader("max-age=63072000; includeSubDomains; preload")
	fmt.Println(header)
}

// ExampleNewTEHeader is an example function for NewTEHeader.
func ExampleNewTEHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewTEHeader("compress, deflate;q=0.7")
	fmt.Println(header)
}

// ExampleNewTimingAllowOriginHeader is an example function for NewTimingAllowOriginHeader.
func ExampleNewTimingAllowOriginHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewTimingAllowOriginHeader("https://www.example.com")
	fmt.Println(header)
}

// ExampleNewTKHeader is an example function for NewTKHeader.
func ExampleNewTKHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewTKHeader("T")
	fmt.Println(header)
}

// ExampleNewTrailerHeader is an example function for NewTrailerHeader.
func ExampleNewTrailerHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewTrailerHeader("Expires")
	fmt.Println(header)
}

// ExampleNewTransferEncodingHeader is an example function for NewTransferEncodingHeader.
func ExampleNewTransferEncodingHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewTransferEncodingHeader("gzip", "chunked")
	fmt.Println(header)
}

// ExampleNewUpgradeHeader is an example function for NewUpgradeHeader.
func ExampleNewUpgradeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewUpgradeHeader("example/1", "example/2")
	fmt.Println(header)
}

// ExampleNewUpgradeInsecureRequestsHeader is an example function for NewUpgradeInsecureRequestsHeader.
func ExampleNewUpgradeInsecureRequestsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewUpgradeInsecureRequestsHeader("1")
	fmt.Println(header)
}

// ExampleNewUserAgentHeader is an example function for NewUserAgentHeader.
func ExampleNewUserAgentHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewUserAgentHeader("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	fmt.Println(header)
}

// ExampleNewVaryHeader is an example function for NewVaryHeader.
func ExampleNewVaryHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewVaryHeader("Accept")
	fmt.Println(header)
}

// ExampleNewViaHeader is an example function for NewViaHeader.
func ExampleNewViaHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewViaHeader("HTTP/1.1 proxy.example.re", "1.1 edge_1")
	fmt.Println(header)
}

// ExampleNewViewportWidthHeader is an example function for NewViewportWidthHeader.
func ExampleNewViewportWidthHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewViewportWidthHeader("320")
	fmt.Println(header)
}

// ExampleNewWWWAuthenticateHeader is an example function for NewWWWAuthenticateHeader.
func ExampleNewWWWAuthenticateHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewWWWAuthenticateHeader("Basic realm=\"Access to the staging site\", charset=\"UTF-8\"")
	fmt.Println(header)
}

// ExampleNewWantDigestHeader is an example function for NewWantDigestHeader.
func ExampleNewWantDigestHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewWantDigestHeader("SHA-512;q=0.3, sha-256;q=1, md5;q=0")
	fmt.Println(header)
}

// ExampleNewWarningHeader is an example function for NewWarningHeader.
func ExampleNewWarningHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewWarningHeader("112 - \"cache down\" \"Wed, 21 Oct 2015 07:28:00 GMT\"")
	fmt.Println(header)
}

// ExampleNewWidthHeader is an example function for NewWidthHeader.
func ExampleNewWidthHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewWidthHeader("1920")
	fmt.Println(header)
}

// ExampleNewXATTDeviceIDHeader is an example function for NewXATTDeviceIDHeader.
func ExampleNewXATTDeviceIDHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXATTDeviceIDHeader("GT-P7320/P7320XXLPG")
	fmt.Println(header)
}

// ExampleNewXContentDurationHeader is an example function for NewXContentDurationHeader.
func ExampleNewXContentDurationHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXContentDurationHeader("42.666")
	fmt.Println(header)
}

// ExampleNewXContentSecurityPolicyHeader is an example function for NewXContentSecurityPolicyHeader.
func ExampleNewXContentSecurityPolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXContentSecurityPolicyHeader("default-src 'self'")
	fmt.Println(header)
}

// ExampleNewXContentTypeOptionsHeader is an example function for NewXContentTypeOptionsHeader.
func ExampleNewXContentTypeOptionsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXContentTypeOptionsHeader("nosniff")
	fmt.Println(header)
}

// ExampleNewXCorrelationIDHeader is an example function for NewXCorrelationIDHeader.
func ExampleNewXCorrelationIDHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXCorrelationIDHeader("f058ebd6-02f7-4d3f-942e-904344e8cde5")
	fmt.Println(header)
}

// ExampleNewXCSRFTokenHeader is an example function for NewXCSRFTokenHeader.
func ExampleNewXCSRFTokenHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXCSRFTokenHeader("i8XNjC4b8KVok4uw5RftR38Wgp2BFwql")
	fmt.Println(header)
}

// ExampleNewXDNSPrefetchControlHeader is an example function for NewXDNSPrefetchControlHeader.
func ExampleNewXDNSPrefetchControlHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXDNSPrefetchControlHeader("off")
	fmt.Println(header)
}

// ExampleNewXForwardedForHeader is an example function for NewXForwardedForHeader.
func ExampleNewXForwardedForHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXForwardedForHeader("203.0.113.195", "2001:db8:85a3:8d3:1319:8a2e:370:7348")
	fmt.Println(header)
}

// ExampleNewXForwardedHostHeader is an example function for NewXForwardedHostHeader.
func ExampleNewXForwardedHostHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXForwardedHostHeader("id42.example-cdn.com")
	fmt.Println(header)
}

// ExampleNewXForwardedProtoHeader is an example function for NewXForwardedProtoHeader.
func ExampleNewXForwardedProtoHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXForwardedProtoHeader("https")
	fmt.Println(header)
}

// ExampleNewXFrameOptionsHeader is an example function for NewXFrameOptionsHeader.
func ExampleNewXFrameOptionsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXFrameOptionsHeader("SAMEORIGIN")
	fmt.Println(header)
}

// ExampleNewXHTTPMethodOverrideHeader is an example function for NewXHTTPMethodOverrideHeader.
func ExampleNewXHTTPMethodOverrideHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXHTTPMethodOverrideHeader("DELETE")
	fmt.Println(header)
}

// ExampleNewXPoweredByHeader is an example function for NewXPoweredByHeader.
func ExampleNewXPoweredByHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXPoweredByHeader("PHP/5.4.0")
	fmt.Println(header)
}

// ExampleNewXRedirectByHeader is an example function for NewXRedirectByHeader.
func ExampleNewXRedirectByHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXRedirectByHeader("WordPress")
	fmt.Println(header)
}

// ExampleNewXRequestIDHeader is an example function for NewXRequestIDHeader.
func ExampleNewXRequestIDHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXRequestIDHeader("f058ebd6-02f7-4d3f-942e-904344e8cde5")
	fmt.Println(header)
}

// ExampleNewXRequestedWithHeader is an example function for NewXRequestedWithHeader.
func ExampleNewXRequestedWithHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXRequestedWithHeader("XMLHttpRequest")
	fmt.Println(header)
}

// ExampleNewXUACompatibleHeader is an example function for NewXUACompatibleHeader.
func ExampleNewXUACompatibleHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXUACompatibleHeader("IE=EmulateIE7")
	fmt.Println(header)
}

// ExampleNewXUIDHHeader is an example function for NewXUIDHHeader.
func ExampleNewXUIDHHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXUIDHHeader("...")
	fmt.Println(header)
}

// ExampleNewXWapProfileHeader is an example function for NewXWapProfileHeader.
func ExampleNewXWapProfileHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXWapProfileHeader("http://wap.samsungmobile.com/uaprof/SGH-I777.xml")
	fmt.Println(header)
}

// ExampleNewXWebKitCSPHeader is an example function for NewXWebKitCSPHeader.
func ExampleNewXWebKitCSPHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXWebKitCSPHeader("default-src 'self'")
	fmt.Println(header)
}

// ExampleNewXXSSProtectionHeader is an example function for NewXXSSProtectionHeader.
func ExampleNewXXSSProtectionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewXXSSProtectionHeader("1; mode=block")
	fmt.Println(header)
}

// ExampleWriteHeaders is an example function for WriteHeaders.
func ExampleWriteHeaders() {
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
		json.NewEncoder(w).Encode(w.Header())
	})
	// Set the port for the server.
	serverAddress := fmt.Sprintf(":%d", 8080)
	// Serve content.
	log.Println(http.ListenAndServe(serverAddress, nil))
}
