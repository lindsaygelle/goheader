package goheader_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/lindsaygelle/goheader"
)

// mockResponseWriter is a mock implementation of http.ResponseWriter for testing.
type mockResponseWriter struct {
	headers http.Header
}

// Header returns the headers set in the mock ResponseWriter.
func (m *mockResponseWriter) Header() http.Header {
	return m.headers
}

// Write method of mockResponseWriter, not implemented for this test.
func (m *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

// WriteHeader method of mockResponseWriter, not implemented for this test.
func (m *mockResponseWriter) WriteHeader(int) {}

// TestHeaderConstants tests the goheader HTTP header name constants.
func TestHeaderConstants(t *testing.T) {
	tests := []struct {
		Value          string
		ValueExepected string
	}{
		{goheader.AIM, "A-IM"},
		{goheader.Accept, "Accept"},
		{goheader.AcceptCH, "Accept-CH"},
		{goheader.AcceptCHLifetime, "Accept-CH-Lifetime"},
		{goheader.AcceptCharset, "Accept-Charset"},
		{goheader.AcceptDatetime, "Accept-Datetime"},
		{goheader.AcceptEncoding, "Accept-Encoding"},
		{goheader.AcceptLanguage, "Accept-Language"},
		{goheader.AcceptPatch, "Accept-Patch"},
		{goheader.AcceptPost, "Accept-Post"},
		{goheader.AcceptRanges, "Accept-Ranges"},
		{goheader.AccessControlAllowCredentials, "Access-Control-Allow-Credentials"},
		{goheader.AccessControlAllowHeaders, "Access-Control-Allow-Headers"},
		{goheader.AccessControlAllowMethods, "Access-Control-Allow-Methods"},
		{goheader.AccessControlAllowOrigin, "Access-Control-Allow-Origin"},
		{goheader.AccessControlExposeHeaders, "Access-Control-Expose-Headers"},
		{goheader.AccessControlMaxAge, "Access-Control-Max-Age"},
		{goheader.AccessControlRequestHeaders, "Access-Control-Request-Headers"},
		{goheader.AccessControlRequestMethod, "Access-Control-Request-Method"},
		{goheader.Age, "Age"},
		{goheader.Allow, "Allow"},
		{goheader.AltSvc, "Alt-Svc"},
		{goheader.AltUsed, "Alt-Used"},
		{goheader.Authorization, "Authorization"},
		{goheader.CacheControl, "Cache-Control"},
		{goheader.ClearSiteData, "Clear-Site-Data"},
		{goheader.Connection, "Connection"},
		{goheader.ContentDPR, "Content-DPR"},
		{goheader.ContentDisposition, "Content-Disposition"},
		{goheader.ContentEncoding, "Content-Encoding"},
		{goheader.ContentLanguage, "Content-Language"},
		{goheader.ContentLength, "Content-Length"},
		{goheader.ContentLocation, "Content-Location"},
		{goheader.ContentMD5, "Content-MD5"},
		{goheader.ContentRange, "Content-Range"},
		{goheader.ContentSecurityPolicy, "Content-Security-Policy"},
		{goheader.ContentSecurityPolicyReportOnly, "Content-Security-Policy-Report-Only"},
		{goheader.ContentType, "Content-Type"},
		{goheader.Cookie, "Cookie"},
		{goheader.CorrelationID, "Correlation-ID"},
		{goheader.CriticalCH, "Critical-CH"},
		{goheader.CrossOriginEmbedderPolicy, "Cross-Origin-Embedder-Policy"},
		{goheader.CrossOriginOpenerPolicy, "Cross-Origin-Opener-Policy"},
		{goheader.CrossOriginResourcePolicy, "Cross-Origin-Resource-Policy"},
		{goheader.DNT, "DNT"},
		{goheader.DPR, "DPR"},
		{goheader.Date, "Date"},
		{goheader.DeltaBase, "Delta-Base"},
		{goheader.DeviceMemory, "Device-Memory"},
		{goheader.Digest, "Digest"},
		{goheader.Downlink, "Downlink"},
		{goheader.ECT, "ECT"},
		{goheader.ETag, "ETag"},
		{goheader.EarlyData, "Early-Data"},
		{goheader.Expect, "Expect"},
		{goheader.ExpectCT, "Expect-CT"},
		{goheader.Expires, "Expires"},
		{goheader.Forwarded, "Forwarded"},
		{goheader.From, "From"},
		{goheader.FrontEndHTTPS, "Front-End-Https"},
		{goheader.HTTP2Settings, "HTTP2-Settings"},
		{goheader.Host, "Host"},
		{goheader.IM, "IM"},
		{goheader.IfMatch, "If-Match"},
		{goheader.IfModifiedSince, "If-Modified-Since"},
		{goheader.IfNoneMatch, "If-None-Match"},
		{goheader.IfRange, "If-Range"},
		{goheader.IfUnmodifiedSince, "If-Unmodified-Since"},
		{goheader.KeepAlive, "Keep-Alive"},
		{goheader.LargeAllocation, "Large-Allocation"},
		{goheader.LastModified, "Last-Modified"},
		{goheader.Link, "Link"},
		{goheader.Location, "Location"},
		{goheader.MaxForwards, "Max-Forwards"},
		{goheader.NEL, "NEL"},
		{goheader.Origin, "Origin"},
		{goheader.P3P, "P3P"},
		{goheader.PermissionsPolicy, "Permissions-Policy"},
		{goheader.Pragma, "Pragma"},
		{goheader.Prefer, "Prefer"},
		{goheader.PreferenceApplied, "Preference-Applied"},
		{goheader.ProxyAuthenticate, "Proxy-Authenticate"},
		{goheader.ProxyAuthorization, "Proxy-Authorization"},
		{goheader.ProxyConnection, "Proxy-Connection"},
		{goheader.PublicKeyPins, "Public-Key-Pins"},
		{goheader.RTT, "RTT"},
		{goheader.Range, "Range"},
		{goheader.Referer, "Referer"},
		{goheader.ReferrerPolicy, "Referrer-Policy"},
		{goheader.Refresh, "Refresh"},
		{goheader.ReportTo, "Report-To"},
		{goheader.RetryAfter, "Retry-After"},
		{goheader.SaveData, "Save-Data"},
		{goheader.SecCHPrefersColorScheme, "Sec-CH-Prefers-Color-Scheme"},
		{goheader.SecCHPrefersReducedMotion, "Sec-CH-Prefers-Reduced-Motion"},
		{goheader.SecCHPrefersReducedTransparency, "Sec-CH-Prefers-Reduced-Transparency"},
		{goheader.SecCHUA, "Sec-CH-UA"},
		{goheader.SecCHUAArch, "Sec-CH-UA-Arch"},
		{goheader.SecCHUABitness, "Sec-CH-UA-Bitness"},
		{goheader.SecCHUAFullVersion, "Sec-CH-UA-Full-Version"},
		{goheader.SecCHUAFullVersionList, "Sec-CH-UA-Full-Version-List"},
		{goheader.SecCHUAMobile, "Sec-CH-UA-Mobile"},
		{goheader.SecCHUAModel, "Sec-CH-UA-Model"},
		{goheader.SecCHUAPlatform, "Sec-CH-UA-Platform"},
		{goheader.SecCHUAPlatformVersion, "Sec-CH-UA-Platform-Version"},
		{goheader.SecFetchDest, "Sec-Fetch-Dest"},
		{goheader.SecFetchMode, "Sec-Fetch-Mode"},
		{goheader.SecFetchSite, "Sec-Fetch-Site"},
		{goheader.SecFetchUser, "Sec-Fetch-User"},
		{goheader.SecGPC, "Sec-GPC"},
		{goheader.SecPurpose, "Sec-Purpose"},
		{goheader.SecWebSocketAccept, "Sec-WebSocket-Accept"},
		{goheader.Server, "Server"},
		{goheader.ServerTiming, "Server-Timing"},
		{goheader.ServiceWorkerNavigationPreload, "Service-Worker-Navigation-Preload"},
		{goheader.SetCookie, "Set-Cookie"},
		{goheader.SourceMap, "SourceMap"},
		{goheader.Status, "Status"},
		{goheader.StrictTransportSecurity, "Strict-Transport-Security"},
		{goheader.SupportsLoadingMode, "Supports-Loading-Mode"},
		{goheader.TE, "TE"},
		{goheader.TimingAllowOrigin, "Timing-Allow-Origin"},
		{goheader.TK, "Tk"},
		{goheader.Trailer, "Trailer"},
		{goheader.TransferEncoding, "Transfer-Encoding"},
		{goheader.Upgrade, "Upgrade"},
		{goheader.UpgradeInsecureRequests, "Upgrade-Insecure-Requests"},
		{goheader.UserAgent, "User-Agent"},
		{goheader.Vary, "Vary"},
		{goheader.Via, "Via"},
		{goheader.ViewportWidth, "Viewport-Width"},
		{goheader.WWWAuthenticate, "WWW-Authenticate"},
		{goheader.WantDigest, "Want-Digest"},
		{goheader.Warning, "Warning"},
		{goheader.Width, "Width"},
		{goheader.XATTDeviceID, "X-ATT-DeviceId"},
		{goheader.XContentDuration, "X-Content-Duration"},
		{goheader.XContentSecurityPolicy, "X-Content-Security-Policy"},
		{goheader.XContentTypeOptions, "X-Content-Type-Options"},
		{goheader.XCorrelationID, "X-Correlation-ID"},
		{goheader.XCSRFToken, "X-Csrf-Token"},
		{goheader.XDNSPrefetchControl, "X-DNS-Prefetch-Control"},
		{goheader.XForwardedFor, "X-Forwarded-For"},
		{goheader.XForwardedHost, "X-Forwarded-Host"},
		{goheader.XForwardedProto, "X-Forwarded-Proto"},
		{goheader.XFrameOptions, "X-Frame-Options"},
		{goheader.XHTTPMethodOverride, "X-Http-Method-Override"},
		{goheader.XPoweredBy, "X-Powered-By"},
		{goheader.XRedirectBy, "X-Redirect-By"},
		{goheader.XRequestID, "X-Request-ID"},
		{goheader.XRequestedWith, "X-Requested-With"},
		{goheader.XUACompatible, "X-UA-Compatible"},
		{goheader.XUIDH, "X-UIDH"},
		{goheader.XWapProfile, "X-Wap-Profile"},
		{goheader.XWebKitCSP, "X-WebKit-CSP"},
		{goheader.XXSSProtection, "X-XSS-Protection"}}
	for _, test := range tests {
		t.Run(test.ValueExepected, func(t *testing.T) {
			if test.Value != test.ValueExepected {
				t.Errorf("Expected %s header to be %s, but got %s", strings.ReplaceAll(test.ValueExepected, "-", ""), test.ValueExepected, test.Value)
			}
		})
	}
}

// TestHeaderFunctions tests the goheader Header constructor functions.
func TestHeaderFunctions(t *testing.T) {
	tests := []struct {
		ValueName         string
		ValueNameFunction func(values ...string) goheader.Header
	}{
		{goheader.AIM, goheader.NewAIMHeader},
		{goheader.Accept, goheader.NewAcceptHeader},
		{goheader.AcceptCH, goheader.NewAcceptCHHeader},
		{goheader.AcceptCHLifetime, goheader.NewAcceptCHLifetimeHeader},
		{goheader.AcceptCharset, goheader.NewAcceptCharsetHeader},
		{goheader.AcceptDatetime, goheader.NewAcceptDatetimeHeader},
		{goheader.AcceptEncoding, goheader.NewAcceptEncodingHeader},
		{goheader.AcceptLanguage, goheader.NewAcceptLanguageHeader},
		{goheader.AcceptPatch, goheader.NewAcceptPatchHeader},
		{goheader.AcceptPost, goheader.NewAcceptPostHeader},
		{goheader.AcceptRanges, goheader.NewAcceptRangesHeader},
		{goheader.AccessControlAllowCredentials, goheader.NewAccessControlAllowCredentialsHeader},
		{goheader.AccessControlAllowHeaders, goheader.NewAccessControlAllowHeadersHeader},
		{goheader.AccessControlAllowMethods, goheader.NewAccessControlAllowMethodsHeader},
		{goheader.AccessControlAllowOrigin, goheader.NewAccessControlAllowOriginHeader},
		{goheader.AccessControlExposeHeaders, goheader.NewAccessControlExposeHeadersHeader},
		{goheader.AccessControlMaxAge, goheader.NewAccessControlMaxAgeHeader},
		{goheader.AccessControlRequestHeaders, goheader.NewAccessControlRequestHeadersHeader},
		{goheader.AccessControlRequestMethod, goheader.NewAccessControlRequestMethodHeader},
		{goheader.Age, goheader.NewAgeHeader},
		{goheader.Allow, goheader.NewAllowHeader},
		{goheader.AltSvc, goheader.NewAltSvcHeader},
		{goheader.AltUsed, goheader.NewAltUsedHeader},
		{goheader.Authorization, goheader.NewAuthorizationHeader},
		{goheader.CacheControl, goheader.NewCacheControlHeader},
		{goheader.ClearSiteData, goheader.NewClearSiteDataHeader},
		{goheader.Connection, goheader.NewConnectionHeader},
		{goheader.ContentDPR, goheader.NewContentDPRHeader},
		{goheader.ContentDisposition, goheader.NewContentDispositionHeader},
		{goheader.ContentEncoding, goheader.NewContentEncodingHeader},
		{goheader.ContentLanguage, goheader.NewContentLanguageHeader},
		{goheader.ContentLength, goheader.NewContentLengthHeader},
		{goheader.ContentLocation, goheader.NewContentLocationHeader},
		{goheader.ContentMD5, goheader.NewContentMD5Header},
		{goheader.ContentRange, goheader.NewContentRangeHeader},
		{goheader.ContentSecurityPolicy, goheader.NewContentSecurityPolicyHeader},
		{goheader.ContentSecurityPolicyReportOnly, goheader.NewContentSecurityPolicyReportOnlyHeader},
		{goheader.ContentType, goheader.NewContentTypeHeader},
		{goheader.Cookie, goheader.NewCookieHeader},
		{goheader.CorrelationID, goheader.NewCorrelationIDHeader},
		{goheader.CriticalCH, goheader.NewCriticalCHHeader},
		{goheader.CrossOriginEmbedderPolicy, goheader.NewCrossOriginEmbedderPolicyHeader},
		{goheader.CrossOriginOpenerPolicy, goheader.NewCrossOriginOpenerPolicyHeader},
		{goheader.CrossOriginResourcePolicy, goheader.NewCrossOriginResourcePolicyHeader},
		{goheader.DNT, goheader.NewDNTHeader},
		{goheader.DPR, goheader.NewDPRHeader},
		{goheader.Date, goheader.NewDateHeader},
		{goheader.DeltaBase, goheader.NewDeltaBaseHeader},
		{goheader.DeviceMemory, goheader.NewDeviceMemoryHeader},
		{goheader.Digest, goheader.NewDigestHeader},
		{goheader.Downlink, goheader.NewDownlinkHeader},
		{goheader.ECT, goheader.NewECTHeader},
		{goheader.ETag, goheader.NewETagHeader},
		{goheader.EarlyData, goheader.NewEarlyDataHeader},
		{goheader.Expect, goheader.NewExpectHeader},
		{goheader.ExpectCT, goheader.NewExpectCTHeader},
		{goheader.Expires, goheader.NewExpiresHeader},
		{goheader.Forwarded, goheader.NewForwardedHeader},
		{goheader.From, goheader.NewFromHeader},
		{goheader.FrontEndHTTPS, goheader.NewFrontEndHTTPSHeader},
		{goheader.HTTP2Settings, goheader.NewHTTP2SettingsHeader},
		{goheader.Host, goheader.NewHostHeader},
		{goheader.IM, goheader.NewIMHeader},
		{goheader.IfMatch, goheader.NewIfMatchHeader},
		{goheader.IfModifiedSince, goheader.NewIfModifiedSinceHeader},
		{goheader.IfNoneMatch, goheader.NewIfNoneMatchHeader},
		{goheader.IfRange, goheader.NewIfRangeHeader},
		{goheader.IfUnmodifiedSince, goheader.NewIfUnmodifiedSinceHeader},
		{goheader.KeepAlive, goheader.NewKeepAliveHeader},
		{goheader.LargeAllocation, goheader.NewLargeAllocationHeader},
		{goheader.LastModified, goheader.NewLastModifiedHeader},
		{goheader.Link, goheader.NewLinkHeader},
		{goheader.Location, goheader.NewLocationHeader},
		{goheader.MaxForwards, goheader.NewMaxForwardsHeader},
		{goheader.NEL, goheader.NewNELHeader},
		{goheader.Origin, goheader.NewOriginHeader},
		{goheader.P3P, goheader.NewP3PHeader},
		{goheader.PermissionsPolicy, goheader.NewPermissionsPolicyHeader},
		{goheader.Pragma, goheader.NewPragmaHeader},
		{goheader.Prefer, goheader.NewPreferHeader},
		{goheader.PreferenceApplied, goheader.NewPreferenceAppliedHeader},
		{goheader.ProxyAuthenticate, goheader.NewProxyAuthenticateHeader},
		{goheader.ProxyAuthorization, goheader.NewProxyAuthorizationHeader},
		{goheader.ProxyConnection, goheader.NewProxyConnectionHeader},
		{goheader.PublicKeyPins, goheader.NewPublicKeyPinsHeader},
		{goheader.RTT, goheader.NewRTTHeader},
		{goheader.Range, goheader.NewRangeHeader},
		{goheader.Referer, goheader.NewRefererHeader},
		{goheader.ReferrerPolicy, goheader.NewReferrerPolicyHeader},
		{goheader.Refresh, goheader.NewRefreshHeader},
		{goheader.ReportTo, goheader.NewReportToHeader},
		{goheader.RetryAfter, goheader.NewRetryAfterHeader},
		{goheader.SaveData, goheader.NewSaveDataHeader},
		{goheader.SecCHPrefersColorScheme, goheader.NewSecCHPrefersColorSchemeHeader},
		{goheader.SecCHPrefersReducedMotion, goheader.NewSecCHPrefersReducedMotionHeader},
		{goheader.SecCHPrefersReducedTransparency, goheader.NewSecCHPrefersReducedTransparencyHeader},
		{goheader.SecCHUA, goheader.NewSecCHUAHeader},
		{goheader.SecCHUAArch, goheader.NewSecCHUAArchHeader},
		{goheader.SecCHUABitness, goheader.NewSecCHUABitnessHeader},
		{goheader.SecCHUAFullVersion, goheader.NewSecCHUAFullVersionHeader},
		{goheader.SecCHUAFullVersionList, goheader.NewSecCHUAFullVersionListHeader},
		{goheader.SecCHUAMobile, goheader.NewSecCHUAMobileHeader},
		{goheader.SecCHUAModel, goheader.NewSecCHUAModelHeader},
		{goheader.SecCHUAPlatform, goheader.NewSecCHUAPlatformHeader},
		{goheader.SecCHUAPlatformVersion, goheader.NewSecCHUAPlatformVersionHeader},
		{goheader.SecFetchDest, goheader.NewSecFetchDestHeader},
		{goheader.SecFetchMode, goheader.NewSecFetchModeHeader},
		{goheader.SecFetchSite, goheader.NewSecFetchSiteHeader},
		{goheader.SecFetchUser, goheader.NewSecFetchUserHeader},
		{goheader.SecGPC, goheader.NewSecGPCHeader},
		{goheader.SecPurpose, goheader.NewSecPurposeHeader},
		{goheader.SecWebSocketAccept, goheader.NewSecWebSocketAcceptHeader},
		{goheader.Server, goheader.NewServerHeader},
		{goheader.ServerTiming, goheader.NewServerTimingHeader},
		{goheader.ServiceWorkerNavigationPreload, goheader.NewServiceWorkerNavigationPreloadHeader},
		{goheader.SetCookie, goheader.NewSetCookieHeader},
		{goheader.SourceMap, goheader.NewSourceMapHeader},
		{goheader.Status, goheader.NewStatusHeader},
		{goheader.StrictTransportSecurity, goheader.NewStrictTransportSecurityHeader},
		{goheader.SupportsLoadingMode, goheader.NewSupportsLoadingModeHeader},
		{goheader.TE, goheader.NewTEHeader},
		{goheader.TimingAllowOrigin, goheader.NewTimingAllowOriginHeader},
		{goheader.TK, goheader.NewTKHeader},
		{goheader.Trailer, goheader.NewTrailerHeader},
		{goheader.TransferEncoding, goheader.NewTransferEncodingHeader},
		{goheader.Upgrade, goheader.NewUpgradeHeader},
		{goheader.UpgradeInsecureRequests, goheader.NewUpgradeInsecureRequestsHeader},
		{goheader.UserAgent, goheader.NewUserAgentHeader},
		{goheader.Vary, goheader.NewVaryHeader},
		{goheader.Via, goheader.NewViaHeader},
		{goheader.ViewportWidth, goheader.NewViewportWidthHeader},
		{goheader.WWWAuthenticate, goheader.NewWWWAuthenticateHeader},
		{goheader.WantDigest, goheader.NewWantDigestHeader},
		{goheader.Warning, goheader.NewWarningHeader},
		{goheader.Width, goheader.NewWidthHeader},
		{goheader.XATTDeviceID, goheader.NewXATTDeviceIDHeader},
		{goheader.XContentDuration, goheader.NewXContentDurationHeader},
		{goheader.XContentSecurityPolicy, goheader.NewXContentSecurityPolicyHeader},
		{goheader.XContentTypeOptions, goheader.NewXContentTypeOptionsHeader},
		{goheader.XCorrelationID, goheader.NewXCorrelationIDHeader},
		{goheader.XCSRFToken, goheader.NewXCSRFTokenHeader},
		{goheader.XDNSPrefetchControl, goheader.NewXDNSPrefetchControlHeader},
		{goheader.XForwardedFor, goheader.NewXForwardedForHeader},
		{goheader.XForwardedHost, goheader.NewXForwardedHostHeader},
		{goheader.XForwardedProto, goheader.NewXForwardedProtoHeader},
		{goheader.XFrameOptions, goheader.NewXFrameOptionsHeader},
		{goheader.XHTTPMethodOverride, goheader.NewXHTTPMethodOverrideHeader},
		{goheader.XPoweredBy, goheader.NewXPoweredByHeader},
		{goheader.XRedirectBy, goheader.NewXRedirectByHeader},
		{goheader.XRequestID, goheader.NewXRequestIDHeader},
		{goheader.XRequestedWith, goheader.NewXRequestedWithHeader},
		{goheader.XUACompatible, goheader.NewXUACompatibleHeader},
		{goheader.XUIDH, goheader.NewXUIDHHeader},
		{goheader.XWapProfile, goheader.NewXWapProfileHeader},
		{goheader.XWebKitCSP, goheader.NewXWebKitCSPHeader},
		{goheader.XXSSProtection, goheader.NewXXSSProtectionHeader},
	}
	for _, test := range tests {
		t.Run(test.ValueName, func(t *testing.T) {
			headerValues := []string{"A", "B", "C"}
			header := test.ValueNameFunction(headerValues...)
			if header.Name != test.ValueName {
				t.Errorf("Expected Header.Name to be %s, but got %s", test.ValueName, header.Name)
			}
			if !reflect.DeepEqual(headerValues, header.Values) {
				t.Errorf("Expected Header.Value to be %s, but got %s", headerValues, header.Values)
			}
		})
	}
}

// TestWriteHeaders tests the WriteHeaders function.
func TestWriteHeaders(t *testing.T) {

	// Create a mock http.Header instance.
	mockHeader := http.Header{}

	// Create a mock http.ResponseWriter instance.
	mockWriter := &mockResponseWriter{headers: mockHeader}

	// Headers to be written.
	headers := []goheader.Header{
		{
			Name:   "Content-Type",
			Values: []string{"application/json"}},
		{
			Name:   "Cache-Control",
			Values: []string{"no-cache"}}}

	// Call the WriteHeaders function.
	goheader.WriteHeaders(mockWriter, headers...)

	// Verify that the headers have been set correctly in the mock ResponseWriter.
	expectedHeaders := map[string][]string{
		"Content-Type":  {"application/json"},
		"Cache-Control": {"no-cache"},
	}

	for name, expectedValues := range expectedHeaders {
		actualValues, ok := mockHeader[name]
		if !ok {
			t.Errorf("Expected header '%s' to be set, but it was not found.", name)
		} else if !reflect.DeepEqual(actualValues, expectedValues) {
			t.Errorf("Expected values %v for header '%s', but got %v", expectedValues, name, actualValues)
		}
	}
}
