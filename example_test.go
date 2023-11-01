// Package goheader_test provides testing the goheader package.
package goheader_test

import (
	"fmt"

	"github.com/lindsaygelle/goheader"
)

// ExampleNewAIMHeader is an example function for NewAIMHeader.
func ExampleNewAIMHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAIMHeader("feed")
	fmt.Println(header)
}

// ExampleNewAcceptHeader is an example function for NewAcceptHeader.
func ExampleNewAcceptHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptHeader("text/html")
	fmt.Println(header)
}

// ExampleNewAcceptCHHeader is an example function for NewAcceptCHHeader.
func ExampleNewAcceptCHHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptCHHeader("width")
	fmt.Println(header)
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
	header := goheader.NewAcceptCharsetHeader("UTF-8")
	fmt.Println(header)
}

// ExampleNewAcceptDatetimeHeader is an example function for NewAcceptDatetimeHeader.
func ExampleNewAcceptDatetimeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptDatetimeHeader("Thu, 31 May 2007 20:35:00 GMT")
	fmt.Println(header)
}

// ExampleNewAcceptEncodingHeader is an example function for NewAcceptEncodingHeader.
func ExampleNewAcceptEncodingHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptEncodingHeader("gzip")
	fmt.Println(header)
}

// ExampleNewAcceptLanguageHeader is an example function for NewAcceptLanguageHeader.
func ExampleNewAcceptLanguageHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptLanguageHeader("en-AU")
	fmt.Println(header)
}

// ExampleNewAcceptPatchHeader is an example function for NewAcceptPatchHeader.
func ExampleNewAcceptPatchHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptPatchHeader("application/example", "text/example")
	fmt.Println(header)
}

// ExampleNewAcceptPostHeader is an example function for NewAcceptPostHeader.
func ExampleNewAcceptPostHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptPostHeader("application/example", "text/example")
	fmt.Println(header)
}

// ExampleNewAcceptRangesHeader is an example function for NewAcceptRangesHeader.
func ExampleNewAcceptRangesHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAcceptRangesHeader("bytes")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowCredentialsHeader is an example function for NewAccessControlAllowCredentialsHeader.
func ExampleNewAccessControlAllowCredentialsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlAllowCredentialsHeader("true")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowHeadersHeader is an example function for NewAccessControlAllowHeadersHeader.
func ExampleNewAccessControlAllowHeadersHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlAllowHeadersHeader("*")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowMethodsHeader is an example function for NewAccessControlAllowMethodsHeader.
func ExampleNewAccessControlAllowMethodsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlAllowMethodsHeader("POST", "GET")
	fmt.Println(header)
}

// ExampleNewAccessControlAllowOriginHeader is an example function for NewAccessControlAllowOriginHeader.
func ExampleNewAccessControlAllowOriginHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlAllowOriginHeader("*")
	fmt.Println(header)
}

// ExampleNewAccessControlExposeHeadersHeader is an example function for NewAccessControlExposeHeadersHeader.
func ExampleNewAccessControlExposeHeadersHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlExposeHeadersHeader("https://github.com")
	fmt.Println(header)
}

// ExampleNewAccessControlMaxAgeHeader is an example function for NewAccessControlMaxAgeHeader.
func ExampleNewAccessControlMaxAgeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlMaxAgeHeader("600")
	fmt.Println(header)
}

// ExampleNewAccessControlRequestHeadersHeader is an example function for NewAccessControlRequestHeadersHeader.
func ExampleNewAccessControlRequestHeadersHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlRequestHeadersHeader("Content-Type", "X-User-Addr")
	fmt.Println(header)
}

// ExampleNewAccessControlRequestMethodHeader is an example function for NewAccessControlRequestMethodHeader.
func ExampleNewAccessControlRequestMethodHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAccessControlRequestMethodHeader("GET")
	fmt.Println(header)
}

// ExampleNewAgeHeader is an example function for NewAgeHeader.
func ExampleNewAgeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAgeHeader("15")
	fmt.Println(header)
}

// ExampleNewAllowHeader is an example function for NewAllowHeader.
func ExampleNewAllowHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAllowHeader("HEAD", "GET")
	fmt.Println(header)
}

// ExampleNewAltSvcHeader is an example function for NewAltSvcHeader.
func ExampleNewAltSvcHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAltSvcHeader("h2=\"alt.example.com:443\"", "h2=\":443\"")
	fmt.Println(header)
}

// ExampleNewAltUsedHeader is an example function for NewAltUsedHeader.
func ExampleNewAltUsedHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAltUsedHeader("alternate.example.net")
	fmt.Println(header)
}

// ExampleNewAuthorizationHeader is an example function for NewAuthorizationHeader.
func ExampleNewAuthorizationHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewAuthorizationHeader("Basic RXhhbXBsZTphaQ==")
	fmt.Println(header)
}

// ExampleNewCacheControlHeader is an example function for NewCacheControlHeader.
func ExampleNewCacheControlHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCacheControlHeader("max-age=604800")
	fmt.Println(header)
}

// ExampleNewClearSiteDataHeader is an example function for NewClearSiteDataHeader.
func ExampleNewClearSiteDataHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewClearSiteDataHeader("*")
	fmt.Println(header)
}

// ExampleNewConnectionHeader is an example function for NewConnectionHeader.
func ExampleNewConnectionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewConnectionHeader("keep-alive")
	fmt.Println(header)
}

// ExampleNewContentDPRHeader is an example function for NewContentDPRHeader.
func ExampleNewContentDPRHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentDPRHeader("1")
	fmt.Println(header)
}

// ExampleNewContentDispositionHeader is an example function for NewContentDispositionHeader.
func ExampleNewContentDispositionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentDispositionHeader("attachment; filename=\"document.doc\"")
	fmt.Println(header)
}

// ExampleNewContentEncodingHeader is an example function for NewContentEncodingHeader.
func ExampleNewContentEncodingHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentEncodingHeader("deflate", "br")
	fmt.Println(header)
}

// ExampleNewContentLanguageHeader is an example function for NewContentLanguageHeader.
func ExampleNewContentLanguageHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentLanguageHeader("en-AU")
	fmt.Println(header)
}

// ExampleNewContentLengthHeader is an example function for NewContentLengthHeader.
func ExampleNewContentLengthHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentLengthHeader("128")
	fmt.Println(header)
}

// ExampleNewContentLocationHeader is an example function for NewContentLocationHeader.
func ExampleNewContentLocationHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentLocationHeader("https://example.com/documents/foo")
	fmt.Println(header)
}

// ExampleNewContentMD5Header is an example function for NewContentMD5Header.
func ExampleNewContentMD5Header() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentMD5Header("b89f948e98f3a113dc13fdbd3bdb17ef")
	fmt.Println(header)
}

// ExampleNewContentRangeHeader is an example function for NewContentRangeHeader.
func ExampleNewContentRangeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentRangeHeader("1000-2000/*")
	fmt.Println(header)
}

// ExampleNewContentSecurityPolicyHeader is an example function for NewContentSecurityPolicyHeader.
func ExampleNewContentSecurityPolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentSecurityPolicyHeader("default-src 'self'; font-src fonts.gstatic.com; style-src 'self' fonts.googleapis.com")
	fmt.Println(header)
}

// ExampleNewContentSecurityPolicyReportOnlyHeader is an example function for NewContentSecurityPolicyReportOnlyHeader.
func ExampleNewContentSecurityPolicyReportOnlyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentSecurityPolicyReportOnlyHeader("default-src https:; report-to /csp-violation-report-endpoint/")
	fmt.Println(header)
}

// ExampleNewContentTypeHeader is an example function for NewContentTypeHeader.
func ExampleNewContentTypeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewContentTypeHeader("text/html; charset=utf-8")
	fmt.Println(header)
}

// ExampleNewCookieHeader is an example function for NewCookieHeader.
func ExampleNewCookieHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCookieHeader("PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1")
	fmt.Println(header)
}

// ExampleNewCorrelationIDHeader is an example function for NewCorrelationIDHeader.
func ExampleNewCorrelationIDHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCorrelationIDHeader("93dba609-c615-4513-b95b-0d3468ec20d0")
	fmt.Println(header)
}

// ExampleNewCriticalCHHeader is an example function for NewCriticalCHHeader.
func ExampleNewCriticalCHHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCriticalCHHeader("Sec-CH-Prefers-Reduced-Motion")
	fmt.Println(header)
}

// ExampleNewCrossOriginEmbedderPolicyHeader is an example function for NewCrossOriginEmbedderPolicyHeader.
func ExampleNewCrossOriginEmbedderPolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCrossOriginEmbedderPolicyHeader("require-corp")
	fmt.Println(header)
}

// ExampleNewCrossOriginOpenerPolicyHeader is an example function for NewCrossOriginOpenerPolicyHeader.
func ExampleNewCrossOriginOpenerPolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCrossOriginOpenerPolicyHeader("same-origin-allow-popups")
	fmt.Println(header)
}

// ExampleNewCrossOriginResourcePolicyHeader is an example function for NewCrossOriginResourcePolicyHeader.
func ExampleNewCrossOriginResourcePolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewCrossOriginResourcePolicyHeader("same-origin")
	fmt.Println(header)
}

// ExampleNewDNTHeader is an example function for NewDNTHeader.
func ExampleNewDNTHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDNTHeader("1")
	fmt.Println(header)
}

// ExampleNewDPRHeader is an example function for NewDPRHeader.
func ExampleNewDPRHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDPRHeader("2.0")
	fmt.Println(header)
}

// ExampleNewDateHeader is an example function for NewDateHeader.
func ExampleNewDateHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDateHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}

// ExampleNewDeltaBaseHeader is an example function for NewDeltaBaseHeader.
func ExampleNewDeltaBaseHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDeltaBaseHeader("12340001")
	fmt.Println(header)
}

// ExampleNewDeviceMemoryHeader is an example function for NewDeviceMemoryHeader.
func ExampleNewDeviceMemoryHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDeviceMemoryHeader("2")
	fmt.Println(header)
}

// ExampleNewDigestHeader is an example function for NewDigestHeader.
func ExampleNewDigestHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDigestHeader("sha-512= 3b761a2a9a96e1c430236dc31378a3450ea189ae1449c3c8eac25cfa8b25381661317968a54cf46bfced09ae6b49f8512832182ac2d087b22380fcb760d802a3")
	fmt.Println(header)
}

// ExampleNewDownlinkHeader is an example function for NewDownlinkHeader.
func ExampleNewDownlinkHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewDownlinkHeader("1.7")
	fmt.Println(header)
}

// ExampleNewECTHeader is an example function for NewECTHeader.
func ExampleNewECTHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewECTHeader("2g")
	fmt.Println(header)
}

// ExampleNewETagHeader is an example function for NewETagHeader.
func ExampleNewETagHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewETagHeader("33a64df551425fcc55e4d42a148795d9f25f89d4")
	fmt.Println(header)
}

// ExampleNewEarlyDataHeader is an example function for NewEarlyDataHeader.
func ExampleNewEarlyDataHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewEarlyDataHeader("1")
	fmt.Println(header)
}

// ExampleNewExpectHeader is an example function for NewExpectHeader.
func ExampleNewExpectHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewExpectHeader("100-continue")
	fmt.Println(header)
}

// ExampleNewExpectCTHeader is an example function for NewExpectCTHeader.
func ExampleNewExpectCTHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewExpectCTHeader("max-age=86400", "enforce", "report-uri=\"https://foo.example.com/report\"")
	fmt.Println(header)
}

// ExampleNewExpiresHeader is an example function for NewExpiresHeader.
func ExampleNewExpiresHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewExpiresHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}

// ExampleNewForwardedHeader is an example function for NewForwardedHeader.
func ExampleNewForwardedHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewForwardedHeader("for=192.0.2.43", "for=198.51.100.17")
	fmt.Println(header)
}

// ExampleNewFromHeader is an example function for NewFromHeader.
func ExampleNewFromHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewFromHeader("webmaster@example.org")
	fmt.Println(header)
}

// ExampleNewFrontEndHTTPSHeader is an example function for NewFrontEndHTTPSHeader.
func ExampleNewFrontEndHTTPSHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewFrontEndHTTPSHeader("on")
	fmt.Println(header)
}

// ExampleNewHTTP2SettingsHeader is an example function for NewHTTP2SettingsHeader.
func ExampleNewHTTP2SettingsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewHTTP2SettingsHeader("token64")
	fmt.Println(header)
}

// ExampleNewHostHeader is an example function for NewHostHeader.
func ExampleNewHostHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewHostHeader("Host")
	fmt.Println(header)
}

// ExampleNewIMHeader is an example function for NewIMHeader.
func ExampleNewIMHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewIMHeader("feed")
	fmt.Println(header)
}

// ExampleNewIfMatchHeader is an example function for NewIfMatchHeader.
func ExampleNewIfMatchHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewIfMatchHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}

// ExampleNewIfModifiedSinceHeader is an example function for NewIfModifiedSinceHeader.
func ExampleNewIfModifiedSinceHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewIfModifiedSinceHeader("Sat, 29 Oct 1994 19:43:31 GMT")
	fmt.Println(header)
}

// ExampleNewIfNoneMatchHeader is an example function for NewIfNoneMatchHeader.
func ExampleNewIfNoneMatchHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewIfNoneMatchHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}

// ExampleNewIfRangeHeader is an example function for NewIfRangeHeader.
func ExampleNewIfRangeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewIfRangeHeader("737060cd8c284d8af7ad3082f209582d")
	fmt.Println(header)
}

// ExampleNewIfUnmodifiedSinceHeader is an example function for NewIfUnmodifiedSinceHeader.
func ExampleNewIfUnmodifiedSinceHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewIfUnmodifiedSinceHeader("Sat, 29 Oct 1994 19:43:31 GMT")
	fmt.Println(header)
}

// ExampleNewKeepAliveHeader is an example function for NewKeepAliveHeader.
func ExampleNewKeepAliveHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewKeepAliveHeader("timeout=5", "max=1000")
	fmt.Println(header)
}

// ExampleNewLargeAllocationHeader is an example function for NewLargeAllocationHeader.
func ExampleNewLargeAllocationHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewLargeAllocationHeader("500")
	fmt.Println(header)
}

// ExampleNewLastModifiedHeader is an example function for NewLastModifiedHeader.
func ExampleNewLastModifiedHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewLastModifiedHeader("Wed, 21 Oct 2015 07:28:00 GMT")
	fmt.Println(header)
}

// ExampleNewLinkHeader is an example function for NewLinkHeader.
func ExampleNewLinkHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewLinkHeader("<https://one.example.com>; rel=\"preconnect\"", "<https://two.example.com>; rel=\"preconnect\"", "<https://three.example.com>; rel=\"preconnect\"")
	fmt.Println(header)
}

// ExampleNewLocationHeader is an example function for NewLocationHeader.
func ExampleNewLocationHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewLocationHeader("/index.html")
	fmt.Println(header)
}

// ExampleNewMaxForwardsHeader is an example function for NewMaxForwardsHeader.
func ExampleNewMaxForwardsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewMaxForwardsHeader("10")
	fmt.Println(header)
}

// ExampleNewNELHeader is an example function for NewNELHeader.
func ExampleNewNELHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewNELHeader("{ \"report_to\": \"name_of_reporting_group\", \"max_age\": 12345, \"include_subdomains\": false, \"success_fraction\": 0.0, \"failure_fraction\": 1.0 }")
	fmt.Println(header)
}

// ExampleNewOriginHeader is an example function for NewOriginHeader.
func ExampleNewOriginHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewOriginHeader("https://example.com")
	fmt.Println(header)
}

// ExampleNewP3PHeader is an example function for NewP3PHeader.
func ExampleNewP3PHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewP3PHeader("CP=\"https://example.com/P3P\"")
	fmt.Println(header)
}

// ExampleNewPermissionsPolicyHeader is an example function for NewPermissionsPolicyHeader.
func ExampleNewPermissionsPolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewPermissionsPolicyHeader("(\"https://example.com\" \"https://a.example.com\" \"https://b.example.com\" \"https://c.example.com\")")
	fmt.Println(header)
}

// ExampleNewPragmaHeader is an example function for NewPragmaHeader.
func ExampleNewPragmaHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewPragmaHeader("no-cache")
	fmt.Println(header)
}

// ExampleNewPreferHeader is an example function for NewPreferHeader.
func ExampleNewPreferHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewPreferHeader("respond-async", "wait=5")
	fmt.Println(header)
}

// ExampleNewPreferenceAppliedHeader is an example function for NewPreferenceAppliedHeader.
func ExampleNewPreferenceAppliedHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewPreferenceAppliedHeader("return=representation")
	fmt.Println(header)
}

// ExampleNewProxyAuthenticateHeader is an example function for NewProxyAuthenticateHeader.
func ExampleNewProxyAuthenticateHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewProxyAuthenticateHeader("Basic realm=\"Access to the internal site\"")
	fmt.Println(header)
}

// ExampleNewProxyAuthorizationHeader is an example function for NewProxyAuthorizationHeader.
func ExampleNewProxyAuthorizationHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewProxyAuthorizationHeader("Basic YWxhZGRpbjpvcGVuc2VzYW1l")
	fmt.Println(header)
}

// ExampleNewProxyConnectionHeader is an example function for NewProxyConnectionHeader.
func ExampleNewProxyConnectionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewProxyConnectionHeader("keep-alive")
	fmt.Println(header)
}

// ExampleNewPublicKeyPinsHeader is an example function for NewPublicKeyPinsHeader.
func ExampleNewPublicKeyPinsHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewPublicKeyPinsHeader("max-age=2592000; pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\";")
	fmt.Println(header)
}

// ExampleNewRTTHeader is an example function for NewRTTHeader.
func ExampleNewRTTHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewRTTHeader("123")
	fmt.Println(header)
}

// ExampleNewRangeHeader is an example function for NewRangeHeader.
func ExampleNewRangeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewRangeHeader("bytes=200-1000", "2000-6576", "19000-")
	fmt.Println(header)
}

// ExampleNewRefererHeader is an example function for NewRefererHeader.
func ExampleNewRefererHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewRefererHeader("https://example.com/")
	fmt.Println(header)
}

// ExampleNewReferrerPolicyHeader is an example function for NewReferrerPolicyHeader.
func ExampleNewReferrerPolicyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewReferrerPolicyHeader("no-referrer", "strict-origin-when-cross-origin")
	fmt.Println(header)
}

// ExampleNewRefreshHeader is an example function for NewRefreshHeader.
func ExampleNewRefreshHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewRefreshHeader("5; url=http://www.w3.org/pub/WWW/People.html")
	fmt.Println(header)
}

// ExampleNewReportToHeader is an example function for NewReportToHeader.
func ExampleNewReportToHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewReportToHeader("{ \"group\": \"csp-endpoint\", \"max_age\": 10886400, \"endpoints\": [ { \"url\": \"https-url-of-site-which-collects-reports\" } ] }")
	fmt.Println(header)
}

// ExampleNewRetryAfterHeader is an example function for NewRetryAfterHeader.
func ExampleNewRetryAfterHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewRetryAfterHeader("123")
	fmt.Println(header)
}

// ExampleNewSaveDataHeader is an example function for NewSaveDataHeader.
func ExampleNewSaveDataHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSaveDataHeader("on")
	fmt.Println(header)
}

// ExampleNewSecCHPrefersColorSchemeHeader is an example function for NewSecCHPrefersColorSchemeHeader.
func ExampleNewSecCHPrefersColorSchemeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHPrefersColorSchemeHeader("dark")
	fmt.Println(header)
}

// ExampleNewSecCHPrefersReducedMotionHeader is an example function for NewSecCHPrefersReducedMotionHeader.
func ExampleNewSecCHPrefersReducedMotionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHPrefersReducedMotionHeader("reduce")
	fmt.Println(header)
}

// ExampleNewSecCHPrefersReducedTransparencyHeader is an example function for NewSecCHPrefersReducedTransparencyHeader.
func ExampleNewSecCHPrefersReducedTransparencyHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHPrefersReducedTransparencyHeader("reduce")
	fmt.Println(header)
}

// ExampleNewSecCHUAHeader is an example function for NewSecCHUAHeader.
func ExampleNewSecCHUAHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAHeader("\"Opera\";v=\"81\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"95\"")
	fmt.Println(header)
}

// ExampleNewSecCHUAArchHeader is an example function for NewSecCHUAArchHeader.
func ExampleNewSecCHUAArchHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAArchHeader("x86")
	fmt.Println(header)
}

// ExampleNewSecCHUABitnessHeader is an example function for NewSecCHUABitnessHeader.
func ExampleNewSecCHUABitnessHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUABitnessHeader("64")
	fmt.Println(header)
}

// ExampleNewSecCHUAFullVersionHeader is an example function for NewSecCHUAFullVersionHeader.
func ExampleNewSecCHUAFullVersionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAFullVersionHeader("96.0.4664.110")
	fmt.Println(header)
}

// ExampleNewSecCHUAFullVersionListHeader is an example function for NewSecCHUAFullVersionListHeader.
func ExampleNewSecCHUAFullVersionListHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAFullVersionListHeader("\" Not A;Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"98.0.4750.0\", \"Google Chrome\";v=\"98.0.4750.0\"")
	fmt.Println(header)
}

// ExampleNewSecCHUAMobileHeader is an example function for NewSecCHUAMobileHeader.
func ExampleNewSecCHUAMobileHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAMobileHeader("?1")
	fmt.Println(header)
}

// ExampleNewSecCHUAModelHeader is an example function for NewSecCHUAModelHeader.
func ExampleNewSecCHUAModelHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAModelHeader("Pixel 3 XL")
	fmt.Println(header)
}

// ExampleNewSecCHUAPlatformHeader is an example function for NewSecCHUAPlatformHeader.
func ExampleNewSecCHUAPlatformHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAPlatformHeader("macOS")
	fmt.Println(header)
}

// ExampleNewSecCHUAPlatformVersionHeader is an example function for NewSecCHUAPlatformVersionHeader.
func ExampleNewSecCHUAPlatformVersionHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecCHUAPlatformVersionHeader("10.0.0")
	fmt.Println(header)
}

// ExampleNewSecFetchDestHeader is an example function for NewSecFetchDestHeader.
func ExampleNewSecFetchDestHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecFetchDestHeader("image")
	fmt.Println(header)
}

// ExampleNewSecFetchModeHeader is an example function for NewSecFetchModeHeader.
func ExampleNewSecFetchModeHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecFetchModeHeader("no-cors")
	fmt.Println(header)
}

// ExampleNewSecFetchSiteHeader is an example function for NewSecFetchSiteHeader.
func ExampleNewSecFetchSiteHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecFetchSiteHeader("cross-site")
	fmt.Println(header)
}

// ExampleNewSecFetchUserHeader is an example function for NewSecFetchUserHeader.
func ExampleNewSecFetchUserHeader() {
	// Create a new goheader.Header instance.
	header := goheader.NewSecFetchUserHeader("?1")
	fmt.Println(header)
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		goheader.WriteHeaders(
			w,
			goheader.NewContentLanguageHeader("en-AU"),
			goheader.NewContentTypeHeader("application/json"),
			goheader.NewCookieHeader("Hello=World"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(w.Headers())
	})

	serverAddress := fmt.Sprintf(":%d", 8080)
	log.Println(http.ListenAndServe(serverAddress, nil))
}