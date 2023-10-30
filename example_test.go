package goheader_test

import (
	"fmt"

	"github.com/lindsaygelle/goheader"
)

// ExampleNewAIMHeader creates an example for function NewAIMHeader.
func ExampleNewAIMHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAIMHeader("feed")
	fmt.Println(header)
}

// ExampleNewAcceptHeader creates an example for function NewAcceptHeader.
func ExampleNewAcceptHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptHeader("text/html")
	fmt.Println(header)
}

// ExampleNewAcceptCHHeader creates an example for function NewAcceptCHHeader.
func ExampleNewAcceptCHHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptCHHeader("width")
	fmt.Println(header)
}

// ExampleNewAcceptCHLifetimeHeader creates an example for function NewAcceptCHLifetimeHeader.
func ExampleNewAcceptCHLifetimeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptCHLifetimeHeader("86400")
	fmt.Println(header)
}

// ExampleNewAcceptCharsetHeader creates an example for function NewAcceptCharsetHeader.

func ExampleNewAcceptCharsetHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptCharsetHeader("UTF-8")
	fmt.Println(header)
}

// ExampleNewAcceptDatetimeHeader creates an example for function NewAcceptDatetimeHeader.
func ExampleNewAcceptDatetimeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptDatetimeHeader("Thu, 31 May 2007 20:35:00 GMT")
	fmt.Println(header)
}

// ExampleNewAcceptEncodingHeader creates an example for function NewAcceptEncodingHeader.
func ExampleNewAcceptEncodingHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptEncodingHeader("gzip")
	fmt.Println(header)
}

// ExampleNewAcceptLanguageHeader creates an example for function NewAcceptLanguageHeader.
func ExampleNewAcceptLanguageHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptLanguageHeader("en-AU")
	fmt.Println(header)
}

// ExampleNewAcceptPatchHeader creates an example for function NewAcceptPatchHeader.
func ExampleNewAcceptPatchHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptPatchHeader("application/example", "text/example")
	fmt.Println(header)
}

// ExampleNewAcceptPostHeader creates an example for function NewAcceptPostHeader.
func ExampleNewAcceptPostHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptPostHeader("application/example", "text/example")
	fmt.Println(header)
}

// ExampleNewAcceptRangesHeader creates an example for function NewAcceptRangesHeader.
func ExampleNewAcceptRangesHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAcceptRangesHeader("bytes")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowCredentialsHeader creates an example for function NewAccessControlAllowCredentialsHeader.
func ExampleNewAccessControlAllowCredentialsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowCredentialsHeader("true")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowHeadersHeader creates an example for function NewAccessControlAllowHeadersHeader.
func ExampleNewAccessControlAllowHeadersHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowHeadersHeader("*")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowMethodsHeader creates an example for function NewAccessControlAllowMethodsHeader.
func ExampleNewAccessControlAllowMethodsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowMethodsHeader("POST", "GET")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowOriginHeader creates an example for function NewAccessControlAllowOriginHeader.
func ExampleNewAccessControlAllowOriginHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlAllowOriginHeader("*")
	fmt.Println(header)
}

// ExampleNewAccessControlExposeHeadersHeader creates an example for function NewAccessControlExposeHeadersHeader.
func ExampleNewAccessControlExposeHeadersHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlExposeHeadersHeader("https://github.com")
	fmt.Println(header)
}

// ExampleNewAccessControlMaxAgeHeader creates an example for function NewAccessControlMaxAgeHeader.
func ExampleNewAccessControlMaxAgeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlMaxAgeHeader("600")
	fmt.Println(header)
}

// ExampleNewAccessControlRequestHeadersHeader creates an example for function NewAccessControlRequestHeadersHeader.
func ExampleNewAccessControlRequestHeadersHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlRequestHeadersHeader("Content-Type", "X-User-Addr")
	fmt.Println(header)
}

// ExampleNewAccessControlRequestMethodHeader creates an example for function NewAccessControlRequestMethodHeader.
func ExampleNewAccessControlRequestMethodHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAccessControlRequestMethodHeader("GET")
	fmt.Println(header)
}

// ExampleNewAgeHeader creates an example for function NewAgeHeader.
func ExampleNewAgeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAgeHeader("15")
	fmt.Println(header)
}

// ExampleNewAllowHeader creates an example for function NewAllowHeader.
func ExampleNewAllowHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAllowHeader("HEAD", "GET")
	fmt.Println(header)
}

// ExampleNewAltSvcHeader creates an example for function NewAltSvcHeader.
func ExampleNewAltSvcHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAltSvcHeader("h2=\"alt.example.com:443\"", "h2=\":443\"")
	fmt.Println(header)
}

// ExampleNewAltUsedHeader creates an example for function NewAltUsedHeader.
func ExampleNewAltUsedHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAltUsedHeader("alternate.example.net")
	fmt.Println(header)
}

// ExampleNewAuthorizationHeader creates an example for function NewAuthorizationHeader.
func ExampleNewAuthorizationHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewAuthorizationHeader("Basic RXhhbXBsZTphaQ==")
	fmt.Println(header)
}

// ExampleNewCacheControlHeader creates an example for function NewCacheControlHeader.
func ExampleNewCacheControlHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCacheControlHeader("max-age=604800")
	fmt.Println(header)
}

// ExampleNewClearSiteDataHeader creates an example for function NewClearSiteDataHeader.
func ExampleNewClearSiteDataHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewClearSiteDataHeader("*")
	fmt.Println(header)
}

// ExampleNewConnectionHeader creates an example for function NewConnectionHeader.
func ExampleNewConnectionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewConnectionHeader("keep-alive")
	fmt.Println(header)
}

// ExampleNewContentDPRHeader creates an example for function NewContentDPRHeader.
func ExampleNewContentDPRHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentDPRHeader("1")
	fmt.Println(header)
}

// ExampleNewContentDispositionHeader creates an example for function NewContentDispositionHeader.
func ExampleNewContentDispositionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentDispositionHeader("attachment; filename=\"document.doc\"")
	fmt.Println(header)
}

// ExampleNewContentEncodingHeader creates an example for function NewContentEncodingHeader.
func ExampleNewContentEncodingHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentEncodingHeader("deflate", "br")
	fmt.Println(header)
}

// ExampleNewContentLanguageHeader creates an example for function NewContentLanguageHeader.
func ExampleNewContentLanguageHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentLanguageHeader("en-AU")
	fmt.Println(header)
}

// ExampleNewContentLengthHeader creates an example for function NewContentLengthHeader.
func ExampleNewContentLengthHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentLengthHeader("128")
	fmt.Println(header)
}

// ExampleNewContentLocationHeader creates an example for function NewContentLocationHeader.
func ExampleNewContentLocationHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentLocationHeader("https://example.com/documents/foo")
	fmt.Println(header)
}

// ExampleNewContentMD5Header creates an example for function NewContentMD5Header.
func ExampleNewContentMD5Header() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentMD5Header("b89f948e98f3a113dc13fdbd3bdb17ef")
	fmt.Println(header)
}

// ExampleNewContentRangeHeader creates an example for function NewContentRangeHeader.
func ExampleNewContentRangeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentRangeHeader("1000-2000/*")
	fmt.Println(header)
}

// ExampleNewContentSecurityPolicyHeader creates an example for function NewContentSecurityPolicyHeader.
func ExampleNewContentSecurityPolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentSecurityPolicyHeader("default-src 'self'; font-src fonts.gstatic.com; style-src 'self' fonts.googleapis.com")
	fmt.Println(header)
}

// ExampleNewContentSecurityPolicyReportOnlyHeader creates an example for function NewContentSecurityPolicyReportOnlyHeader.
func ExampleNewContentSecurityPolicyReportOnlyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentSecurityPolicyReportOnlyHeader("default-src https:; report-to /csp-violation-report-endpoint/")
	fmt.Println(header)
}

// ExampleNewContentTypeHeader creates an example for function NewContentTypeHeader.
func ExampleNewContentTypeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewContentTypeHeader("text/html; charset=utf-8")
	fmt.Println(header)
}

// ExampleNewCookieHeader creates an example for function NewCookieHeader.
func ExampleNewCookieHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCookieHeader("PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1")
	fmt.Println(header)
}

// ExampleNewCorrelationIDHeader creates an example for function NewCorrelationIDHeader.
func ExampleNewCorrelationIDHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCorrelationIDHeader("93dba609-c615-4513-b95b-0d3468ec20d0")
	fmt.Println(header)
}

// ExampleNewCriticalCHHeader creates an example for function NewCriticalCHHeader.
func ExampleNewCriticalCHHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCriticalCHHeader("Sec-CH-Prefers-Reduced-Motion")
	fmt.Println(header)
}

// ExampleNewCrossOriginEmbedderPolicyHeader creates an example for function NewCrossOriginEmbedderPolicyHeader.
func ExampleNewCrossOriginEmbedderPolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCrossOriginEmbedderPolicyHeader("require-corp")
	fmt.Println(header)
}

// ExampleNewCrossOriginOpenerPolicyHeader creates an example for function NewCrossOriginOpenerPolicyHeader.
func ExampleNewCrossOriginOpenerPolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCrossOriginOpenerPolicyHeader("same-origin-allow-popups")
	fmt.Println(header)
}

// ExampleNewCrossOriginResourcePolicyHeader creates an example for function NewCrossOriginResourcePolicyHeader.
func ExampleNewCrossOriginResourcePolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewCrossOriginResourcePolicyHeader("same-origin")
	fmt.Println(header)
}

// ExampleNewDNTHeader creates an example for function NewDNTHeader.
func ExampleNewDNTHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDNTHeader("1")
	fmt.Println(header)
}

// ExampleNewDPRHeader creates an example for function NewDPRHeader.
func ExampleNewDPRHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDPRHeader("2.0")
	fmt.Println(header)
}

// ExampleNewDateHeader creates an example for function NewDateHeader.
func ExampleNewDateHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDateHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}

// ExampleNewDeltaBaseHeader creates an example for function NewDeltaBaseHeader.
func ExampleNewDeltaBaseHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDeltaBaseHeader("12340001")
	fmt.Println(header)
}

// ExampleNewDeviceMemoryHeader creates an example for function NewDeviceMemoryHeader.
func ExampleNewDeviceMemoryHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDeviceMemoryHeader("2")
	fmt.Println(header)
}

// ExampleNewDigestHeader creates an example for function NewDigestHeader.
func ExampleNewDigestHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDigestHeader("sha-512= 3b761a2a9a96e1c430236dc31378a3450ea189ae1449c3c8eac25cfa8b25381661317968a54cf46bfced09ae6b49f8512832182ac2d087b22380fcb760d802a3")
	fmt.Println(header)
}

// ExampleNewDownlinkHeader creates an example for function NewDownlinkHeader.
func ExampleNewDownlinkHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewDownlinkHeader("1.7")
	fmt.Println(header)
}

// ExampleNewECTHeader creates an example for function NewECTHeader.
func ExampleNewECTHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewECTHeader("2g")
	fmt.Println(header)
}

// ExampleNewETagHeader creates an example for function NewETagHeader.
func ExampleNewETagHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewETagHeader("33a64df551425fcc55e4d42a148795d9f25f89d4")
	fmt.Println(header)
}

// ExampleNewEarlyDataHeader creates an example for function NewEarlyDataHeader.
func ExampleNewEarlyDataHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewEarlyDataHeader("1")
	fmt.Println(header)
}

// ExampleNewExpectHeader creates an example for function NewExpectHeader.
func ExampleNewExpectHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewExpectHeader("100-continue")
	fmt.Println(header)
}

// ExampleNewExpectCTHeader creates an example for function NewExpectCTHeader.
func ExampleNewExpectCTHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewExpectCTHeader("max-age=86400", "enforce", "report-uri=\"https://foo.example.com/report\"")
	fmt.Println(header)
}

// ExampleNewExpiresHeader creates an example for function NewExpiresHeader.
func ExampleNewExpiresHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewExpiresHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}

// ExampleNewForwardedHeader creates an example for function NewForwardedHeader.
func ExampleNewForwardedHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewForwardedHeader("for=192.0.2.43", "for=198.51.100.17")
	fmt.Println(header)
}

// ExampleNewFromHeader creates an example for function NewFromHeader.
func ExampleNewFromHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewFromHeader("webmaster@example.org")
	fmt.Println(header)
}

// ExampleNewFrontEndHTTPSHeader creates an example for function NewFrontEndHTTPSHeader.
func ExampleNewFrontEndHTTPSHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewFrontEndHTTPSHeader("on")
	fmt.Println(header)
}

// ExampleNewHTTP2SettingsHeader creates an example for function NewHTTP2SettingsHeader.
func ExampleNewHTTP2SettingsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewHTTP2SettingsHeader("token64")
	fmt.Println(header)
}

// ExampleNewHostHeader creates an example for function NewHostHeader.
func ExampleNewHostHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewHostHeader("Host")
	fmt.Println(header)
}

// ExampleNewIMHeader creates an example for function NewIMHeader.
func ExampleNewIMHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIMHeader("feed")
	fmt.Println(header)
}

// ExampleNewIfMatchHeader creates an example for function NewIfMatchHeader.
func ExampleNewIfMatchHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfMatchHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}

// ExampleNewIfModifiedSinceHeader creates an example for function NewIfModifiedSinceHeader.
func ExampleNewIfModifiedSinceHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfModifiedSinceHeader("Sat, 29 Oct 1994 19:43:31 GMT")
	fmt.Println(header)
}

// ExampleNewIfNoneMatchHeader creates an example for function NewIfNoneMatchHeader.
func ExampleNewIfNoneMatchHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfNoneMatchHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}

// ExampleNewIfRangeHeader creates an example for function NewIfRangeHeader.
func ExampleNewIfRangeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfRangeHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}

// ExampleNewIfUnmodifiedSinceHeader creates an example for function NewIfUnmodifiedSinceHeader.
func ExampleNewIfUnmodifiedSinceHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewIfUnmodifiedSinceHeader("Sat, 29 Oct 1994 19:43:31 GMT")
	fmt.Println(header)
}

// ExampleNewKeepAliveHeader creates an example for function NewKeepAliveHeader.
func ExampleNewKeepAliveHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewKeepAliveHeader("timeout=5", "max=1000")
	fmt.Println(header)
}

// ExampleNewLargeAllocationHeader creates an example for function NewLargeAllocationHeader.
func ExampleNewLargeAllocationHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLargeAllocationHeader("500")
	fmt.Println(header)
}

// ExampleNewLastModifiedHeader creates an example for function NewLastModifiedHeader.
func ExampleNewLastModifiedHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLastModifiedHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}

// ExampleNewLinkHeader creates an example for function NewLinkHeader.
func ExampleNewLinkHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLinkHeader("<https://one.example.com>; rel=\"preconnect\"", "<https://two.example.com>; rel=\"preconnect\"", "<https://three.example.com>; rel=\"preconnect\"")
	fmt.Println(header)
}

// ExampleNewLocationHeader creates an example for function NewLocationHeader.
func ExampleNewLocationHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewLocationHeader("/index.html")
	fmt.Println(header)
}

// ExampleNewMaxForwardsHeader creates an example for function NewMaxForwardsHeader.
func ExampleNewMaxForwardsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewMaxForwardsHeader("10")
	fmt.Println(header)
}

// ExampleNewNELHeader creates an example for function NewNELHeader.
func ExampleNewNELHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewNELHeader("{ \"report_to\": \"name_of_reporting_group\", \"max_age\": 12345, \"include_subdomains\": false, \"success_fraction\": 0.0, \"failure_fraction\": 1.0 }")
	fmt.Println(header)
}

// ExampleNewOriginHeader creates an example for function NewOriginHeader.
func ExampleNewOriginHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewOriginHeader("https://example.com")
	fmt.Println(header)
}

// ExampleNewP3PHeader creates an example for function NewP3PHeader.
func ExampleNewP3PHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewP3PHeader("CP=\"https://example.com/P3P\"")
	fmt.Println(header)
}

// ExampleNewPermissionsPolicyHeader creates an example for function NewPermissionsPolicyHeader.
func ExampleNewPermissionsPolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPermissionsPolicyHeader("(\"https://example.com\" \"https://a.example.com\" \"https://b.example.com\" \"https://c.example.com\")")
	fmt.Println(header)
}

// ExampleNewPragmaHeader creates an example for function NewPragmaHeader.
func ExampleNewPragmaHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPragmaHeader("no-cache")
	fmt.Println(header)
}

// ExampleNewPreferHeader creates an example for function NewPreferHeader.
func ExampleNewPreferHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPreferHeader("respond-async", "wait=5")
	fmt.Println(header)
}

// ExampleNewPreferenceAppliedHeader creates an example for function NewPreferenceAppliedHeader.
func ExampleNewPreferenceAppliedHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPreferenceAppliedHeader("return=representation")
	fmt.Println(header)
}

// ExampleNewProxyAuthenticateHeader creates an example for function NewProxyAuthenticateHeader.
func ExampleNewProxyAuthenticateHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewProxyAuthenticateHeader("Basic realm=\"Access to the internal site\"")
	fmt.Println(header)
}

// ExampleNewProxyAuthorizationHeader creates an example for function NewProxyAuthorizationHeader.
func ExampleNewProxyAuthorizationHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewProxyAuthorizationHeader("Basic YWxhZGRpbjpvcGVuc2VzYW1l")
	fmt.Println(header)
}

// ExampleNewProxyConnectionHeader creates an example for function NewProxyConnectionHeader.
func ExampleNewProxyConnectionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewProxyConnectionHeader("keep-alive")
	fmt.Println(header)
}

// ExampleNewPublicKeyPinsHeader creates an example for function NewPublicKeyPinsHeader.
func ExampleNewPublicKeyPinsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewPublicKeyPinsHeader("max-age=2592000; pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\";")
	fmt.Println(header)
}

// ExampleNewRTTHeader creates an example for function NewRTTHeader.
func ExampleNewRTTHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRTTHeader("123")
	fmt.Println(header)
}

// ExampleNewRangeHeader creates an example for function NewRangeHeader.
func ExampleNewRangeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRangeHeader("bytes=200-1000", "2000-6576", "19000-")
	fmt.Println(header)
}

// ExampleNewRefererHeader creates an example for function NewRefererHeader.
func ExampleNewRefererHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRefererHeader("https://example.com/")
	fmt.Println(header)
}

// ExampleNewReferrerPolicyHeader creates an example for function NewReferrerPolicyHeader.
func ExampleNewReferrerPolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewReferrerPolicyHeader("no-referrer", "strict-origin-when-cross-origin")
	fmt.Println(header)
}

// ExampleNewRefreshHeader creates an example for function NewRefreshHeader.
func ExampleNewRefreshHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRefreshHeader("5; url=http://www.w3.org/pub/WWW/People.html")
	fmt.Println(header)
}

// ExampleNewReportToHeader creates an example for function NewReportToHeader.
func ExampleNewReportToHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewReportToHeader("{ \"group\": \"csp-endpoint\", \"max_age\": 10886400, \"endpoints\": [ { \"url\": \"https-url-of-site-which-collects-reports\" } ] }")
	fmt.Println(header)
}

// ExampleNewRetryAfterHeader creates an example for function NewRetryAfterHeader.
func ExampleNewRetryAfterHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewRetryAfterHeader("123")
	fmt.Println(header)
}

// ExampleNewSaveDataHeader creates an example for function NewSaveDataHeader.
func ExampleNewSaveDataHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSaveDataHeader("on")
	fmt.Println(header)
}

// ExampleNewSecCHPrefersColorSchemeHeader creates an example for function NewSecCHPrefersColorSchemeHeader.
func ExampleNewSecCHPrefersColorSchemeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHPrefersColorSchemeHeader("dark")
	fmt.Println(header)
}

// ExampleNewSecCHPrefersReducedMotionHeader creates an example for function NewSecCHPrefersReducedMotionHeader.
func ExampleNewSecCHPrefersReducedMotionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHPrefersReducedMotionHeader("reduce")
	fmt.Println(header)
}

// ExampleNewSecCHPrefersReducedTransparencyHeader creates an example for function NewSecCHPrefersReducedTransparencyHeader.
func ExampleNewSecCHPrefersReducedTransparencyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHPrefersReducedTransparencyHeader("reduce")
	fmt.Println(header)
}

// ExampleNewSecCHUAHeader creates an example for function NewSecCHUAHeader.
func ExampleNewSecCHUAHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAHeader("\"Opera\";v=\"81\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"95\"")
	fmt.Println(header)
}

// ExampleNewSecCHUAArchHeader creates an example for function NewSecCHUAArchHeader.
func ExampleNewSecCHUAArchHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAArchHeader("x86")
	fmt.Println(header)
}

// ExampleNewSecCHUABitnessHeader creates an example for function NewSecCHUABitnessHeader.
func ExampleNewSecCHUABitnessHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUABitnessHeader("64")
	fmt.Println(header)
}

// ExampleNewSecCHUAFullVersionHeader creates an example for function NewSecCHUAFullVersionHeader.
func ExampleNewSecCHUAFullVersionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAFullVersionHeader("96.0.4664.110")
	fmt.Println(header)
}

// ExampleNewSecCHUAFullVersionListHeader creates an example for function NewSecCHUAFullVersionListHeader.
func ExampleNewSecCHUAFullVersionListHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAFullVersionListHeader("\" Not A;Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"98.0.4750.0\", \"Google Chrome\";v=\"98.0.4750.0\"")
	fmt.Println(header)
}

// ExampleNewSecCHUAMobileHeader creates an example for function NewSecCHUAMobileHeader.
func ExampleNewSecCHUAMobileHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAMobileHeader("?1")
	fmt.Println(header)
}

// ExampleNewSecCHUAModelHeader creates an example for function NewSecCHUAModelHeader.
func ExampleNewSecCHUAModelHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAModelHeader("Pixel 3 XL")
	fmt.Println(header)
}

// ExampleNewSecCHUAPlatformHeader creates an example for function NewSecCHUAPlatformHeader.
func ExampleNewSecCHUAPlatformHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAPlatformHeader("macOS")
	fmt.Println(header)
}

// ExampleNewSecCHUAPlatformVersionHeader creates an example for function NewSecCHUAPlatformVersionHeader.
func ExampleNewSecCHUAPlatformVersionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecCHUAPlatformVersionHeader("10.0.0")
	fmt.Println(header)
}

// ExampleNewSecFetchDestHeader creates an example for function NewSecFetchDestHeader.
func ExampleNewSecFetchDestHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchDestHeader("image")
	fmt.Println(header)
}

// ExampleNewSecFetchModeHeader creates an example for function NewSecFetchModeHeader.
func ExampleNewSecFetchModeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchModeHeader("no-cors")
	fmt.Println(header)
}

// ExampleNewSecFetchSiteHeader creates an example for function NewSecFetchSiteHeader.
func ExampleNewSecFetchSiteHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchSiteHeader("cross-site")
	fmt.Println(header)
}

// ExampleNewSecFetchUserHeader creates an example for function NewSecFetchUserHeader.
func ExampleNewSecFetchUserHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecFetchUserHeader("?1")
	fmt.Println(header)
}

// ExampleNewSecGPCHeader creates an example for function NewSecGPCHeader.
func ExampleNewSecGPCHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecGPCHeader("1")
	fmt.Println(header)
}

// ExampleNewSecPurposeHeader creates an example for function NewSecPurposeHeader.
func ExampleNewSecPurposeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecPurposeHeader("prefetch")
	fmt.Println(header)
}

// ExampleNewSecWebSocketAcceptHeader creates an example for function NewSecWebSocketAcceptHeader.
func ExampleNewSecWebSocketAcceptHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSecWebSocketAcceptHeader("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	fmt.Println(header)
}

// ExampleNewServerHeader creates an example for function NewServerHeader.
func ExampleNewServerHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewServerHeader("Apache/2.4.1 (Unix)")
	fmt.Println(header)
}

// ExampleNewServerTimingHeader creates an example for function NewServerTimingHeader.
func ExampleNewServerTimingHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewServerTimingHeader("missedCache")
	fmt.Println(header)
}

// ExampleNewServiceWorkerNavigationPreloadHeader creates an example for function NewServiceWorkerNavigationPreloadHeader.
func ExampleNewServiceWorkerNavigationPreloadHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewServiceWorkerNavigationPreloadHeader("json_fragment1")
	fmt.Println(header)
}

// ExampleNewSetCookieHeader creates an example for function NewSetCookieHeader.
func ExampleNewSetCookieHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSetCookieHeader("id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GM")
	fmt.Println(header)
}

// ExampleNewSourceMapHeader creates an example for function NewSourceMapHeader.
func ExampleNewSourceMapHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewSourceMapHeader("/static/js/file.js")
	fmt.Println(header)
}

// ExampleNewStatusHeader creates an example for function NewStatusHeader.
func ExampleNewStatusHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewStatusHeader("200 OK")
	fmt.Println(header)
}

// ExampleNewStrictTransportSecurityHeader creates an example for function NewStrictTransportSecurityHeader.
func ExampleNewStrictTransportSecurityHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewStrictTransportSecurityHeader("max-age=63072000; includeSubDomains; preload")
	fmt.Println(header)
}

// ExampleNewTEHeader creates an example for function NewTEHeader.
func ExampleNewTEHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTEHeader("compress, deflate;q=0.7")
	fmt.Println(header)
}

// ExampleNewTimingAllowOriginHeader creates an example for function NewTimingAllowOriginHeader.
func ExampleNewTimingAllowOriginHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTimingAllowOriginHeader("https://www.example.com")
	fmt.Println(header)
}

// ExampleNewTKHeader creates an example for function NewTKHeader.
func ExampleNewTKHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTKHeader("T")
	fmt.Println(header)
}

// ExampleNewTrailerHeader creates an example for function NewTrailerHeader.
func ExampleNewTrailerHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTrailerHeader("Expires")
	fmt.Println(header)
}

// ExampleNewTransferEncodingHeader creates an example for function NewTransferEncodingHeader.
func ExampleNewTransferEncodingHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewTransferEncodingHeader("gzip", "chunked")
	fmt.Println(header)
}

// ExampleNewUpgradeHeader creates an example for function NewUpgradeHeader.
func ExampleNewUpgradeHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewUpgradeHeader("example/1", "example/2")
	fmt.Println(header)
}

// ExampleNewUpgradeInsecureRequestsHeader creates an example for function NewUpgradeInsecureRequestsHeader.
func ExampleNewUpgradeInsecureRequestsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewUpgradeInsecureRequestsHeader("1")
	fmt.Println(header)
}

// ExampleNewUserAgentHeader creates an example for function NewUserAgentHeader.
func ExampleNewUserAgentHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewUserAgentHeader("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	fmt.Println(header)
}

// ExampleNewVaryHeader creates an example for function NewVaryHeader.
func ExampleNewVaryHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewVaryHeader("Accept")
	fmt.Println(header)
}

// ExampleNewViaHeader creates an example for function NewViaHeader.
func ExampleNewViaHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewViaHeader("HTTP/1.1 proxy.example.re", "1.1 edge_1")
	fmt.Println(header)
}

// ExampleNewViewportWidthHeader creates an example for function NewViewportWidthHeader.
func ExampleNewViewportWidthHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewViewportWidthHeader("320")
	fmt.Println(header)
}

// ExampleNewWWWAuthenticateHeader creates an example for function NewWWWAuthenticateHeader.
func ExampleNewWWWAuthenticateHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWWWAuthenticateHeader("Basic realm=\"Access to the staging site\", charset=\"UTF-8\"")
	fmt.Println(header)
}

// ExampleNewWantDigestHeader creates an example for function NewWantDigestHeader.
func ExampleNewWantDigestHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWantDigestHeader("SHA-512;q=0.3, sha-256;q=1, md5;q=0")
	fmt.Println(header)
}

// ExampleNewWarningHeader creates an example for function NewWarningHeader.
func ExampleNewWarningHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWarningHeader("112 - \"cache down\" \"Wed, 21 Oct 2015 07:28:00 GMT\"")
	fmt.Println(header)
}

// ExampleNewWidthHeader creates an example for function NewWidthHeader.
func ExampleNewWidthHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewWidthHeader("1920")
	fmt.Println(header)
}

// ExampleNewXATTDeviceIDHeader creates an example for function NewXATTDeviceIDHeader.
func ExampleNewXATTDeviceIDHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXATTDeviceIDHeader("GT-P7320/P7320XXLPG")
	fmt.Println(header)
}

// ExampleNewXContentDurationHeader creates an example for function NewXContentDurationHeader.
func ExampleNewXContentDurationHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXContentDurationHeader("42.666")
	fmt.Println(header)
}

// ExampleNewXContentSecurityPolicyHeader creates an example for function NewXContentSecurityPolicyHeader.
func ExampleNewXContentSecurityPolicyHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXContentSecurityPolicyHeader("default-src 'self'")
	fmt.Println(header)
}

// ExampleNewXContentTypeOptionsHeader creates an example for function NewXContentTypeOptionsHeader.
func ExampleNewXContentTypeOptionsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXContentTypeOptionsHeader("nosniff")
	fmt.Println(header)
}

// ExampleNewXCorrelationIDHeader creates an example for function NewXCorrelationIDHeader.
func ExampleNewXCorrelationIDHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXCorrelationIDHeader("f058ebd6-02f7-4d3f-942e-904344e8cde5")
	fmt.Println(header)
}

// ExampleNewXCSRFTokenHeader creates an example for function NewXCSRFTokenHeader.
func ExampleNewXCSRFTokenHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXCSRFTokenHeader("i8XNjC4b8KVok4uw5RftR38Wgp2BFwql")
	fmt.Println(header)
}

// ExampleNewXDNSPrefetchControlHeader creates an example for function NewXDNSPrefetchControlHeader.
func ExampleNewXDNSPrefetchControlHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXDNSPrefetchControlHeader("off")
	fmt.Println(header)
}

// ExampleNewXForwardedForHeader creates an example for function NewXForwardedForHeader.
func ExampleNewXForwardedForHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXForwardedForHeader("203.0.113.195", "2001:db8:85a3:8d3:1319:8a2e:370:7348")
	fmt.Println(header)
}

// ExampleNewXForwardedHostHeader creates an example for function NewXForwardedHostHeader.
func ExampleNewXForwardedHostHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXForwardedHostHeader("id42.example-cdn.com")
	fmt.Println(header)
}

// ExampleNewXForwardedProtoHeader creates an example for function NewXForwardedProtoHeader.
func ExampleNewXForwardedProtoHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXForwardedProtoHeader("https")
	fmt.Println(header)
}

// ExampleNewXFrameOptionsHeader creates an example for function NewXFrameOptionsHeader.
func ExampleNewXFrameOptionsHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXFrameOptionsHeader("SAMEORIGIN")
	fmt.Println(header)
}

// ExampleNewXHTTPMethodOverrideHeader creates an example for function NewXHTTPMethodOverrideHeader.
func ExampleNewXHTTPMethodOverrideHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXHTTPMethodOverrideHeader("DELETE")
	fmt.Println(header)
}

// ExampleNewXPoweredByHeader creates an example for function NewXPoweredByHeader.
func ExampleNewXPoweredByHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXPoweredByHeader("PHP/5.4.0")
	fmt.Println(header)
}

// ExampleNewXRedirectByHeader creates an example for function NewXRedirectByHeader.
func ExampleNewXRedirectByHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXRedirectByHeader("WordPress")
	fmt.Println(header)
}

// ExampleNewXRequestIDHeader creates an example for function NewXRequestIDHeader.
func ExampleNewXRequestIDHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXRequestIDHeader("f058ebd6-02f7-4d3f-942e-904344e8cde5")
	fmt.Println(header)
}

// ExampleNewXRequestedWithHeader creates an example for function NewXRequestedWithHeader.
func ExampleNewXRequestedWithHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXRequestedWithHeader("XMLHttpRequest")
	fmt.Println(header)
}

// ExampleNewXUACompatibleHeader creates an example for function NewXUACompatibleHeader.
func ExampleNewXUACompatibleHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXUACompatibleHeader("IE=EmulateIE7")
	fmt.Println(header)
}

// ExampleNewXUIDHHeader creates an example for function NewXUIDHHeader.
func ExampleNewXUIDHHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXUIDHHeader("...")
	fmt.Println(header)
}

// ExampleNewXWapProfileHeader creates an example for function NewXWapProfileHeader.
func ExampleNewXWapProfileHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXWapProfileHeader("http://wap.samsungmobile.com/uaprof/SGH-I777.xml")
	fmt.Println(header)
}

// ExampleNewXWebKitCSPHeader creates an example for function NewXWebKitCSPHeader.
func ExampleNewXWebKitCSPHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXWebKitCSPHeader("default-src 'self'")
	fmt.Println(header)
}

// ExampleNewXXSSProtectionHeader creates an example for function NewXXSSProtectionHeader.
func ExampleNewXXSSProtectionHeader() {
	// Create a new HTTP header for use in HTTP client.
	header := goheader.NewXXSSProtectionHeader("1; mode=block")
	fmt.Println(header)
}
