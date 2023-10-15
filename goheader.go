package goheader

import (
	"net/http"

	"github.com/lindsaygelle/goheader/name"
)

// Header represents an HTTP header with its name, request and response indicators, and values.
type Header struct {
	Name     name.Name // Name of the header.
	Request  bool      // Indicates if the header is applicable for HTTP requests.
	Response bool      // Indicates if the header is applicable for HTTP responses.
	Values   []string  // Values associated with the header.
}

// NewHeaders creates an http.Header from a collection of Header instances.
// It takes Header instances as parameters and returns an http.Header containing the specified headers.
func NewHeaders(headers ...Header) http.Header {
	httpHeaders := http.Header{}
	for _, header := range headers {
		httpHeaders[string(header.Name)] = header.Values
	}
	return httpHeaders
}

// NewAIMHeader creates a A-IM HTTP Header.
func NewAIMHeader(values ...string) Header {
	header := Header{
		Name:    name.AIM,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptHeader creates a Accept HTTP Header.
func NewAcceptHeader(values ...string) Header {
	header := Header{
		Name:    name.Accept,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptCHHeader creates a Accept-CH HTTP Header.
func NewAcceptCHHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptCH,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptCHLifetimeHeader creates a Accept-CH-Lifetime HTTP Header.
func NewAcceptCHLifetimeHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptCHLifetime,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptCharsetHeader creates a Accept-Charset HTTP Header.
func NewAcceptCharsetHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptCharset,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptDatetimeHeader creates a Accept-Datetime HTTP Header.
func NewAcceptDatetimeHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptDatetime,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptEncodingHeader creates a Accept-Encoding HTTP Header.
func NewAcceptEncodingHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptEncoding,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptLanguageHeader creates a Accept-Language HTTP Header.
func NewAcceptLanguageHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptLanguage,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptPatchHeader creates a Accept-Patch HTTP Header.
func NewAcceptPatchHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptPatch,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptPostHeader creates a Accept-Post HTTP Header.
func NewAcceptPostHeader(values ...string) Header {
	header := Header{
		Name:    name.AcceptPost,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAcceptRangesHeader creates a Accept-Ranges HTTP Header.
func NewAcceptRangesHeader(values ...string) Header {
	header := Header{
		Name:   name.AcceptRanges,
		Values: values}
	return header
}

// NewAccessControlAllowCredentialsHeader creates a Access-Control-Allow-Credentials HTTP Header.
func NewAccessControlAllowCredentialsHeader(values ...string) Header {
	header := Header{
		Name:   name.AccessControlAllowCredentials,
		Values: values}
	return header
}

// NewAccessControlAllowHeadersHeader creates a Access-Control-Allow-Headers HTTP Header.
func NewAccessControlAllowHeadersHeader(values ...string) Header {
	header := Header{
		Name:   name.AccessControlAllowHeaders,
		Values: values}
	return header
}

// NewAccessControlAllowMethodsHeader creates a Access-Control-Allow-Methods HTTP Header.
func NewAccessControlAllowMethodsHeader(values ...string) Header {
	header := Header{
		Name:   name.AccessControlAllowMethods,
		Values: values}
	return header
}

// NewAccessControlAllowOriginHeader creates a Access-Control-Allow-Origin HTTP Header.
func NewAccessControlAllowOriginHeader(values ...string) Header {
	header := Header{
		Name:   name.AccessControlAllowOrigin,
		Values: values}
	return header
}

// NewAccessControlExposeHeadersHeader creates a Access-Control-Expose-Headers HTTP Header.
func NewAccessControlExposeHeadersHeader(values ...string) Header {
	header := Header{
		Name:   name.AccessControlExposeHeaders,
		Values: values}
	return header
}

// NewAccessControlMaxAgeHeader creates a Access-Control-Max-Age HTTP Header.
func NewAccessControlMaxAgeHeader(values ...string) Header {
	header := Header{
		Name:   name.AccessControlMaxAge,
		Values: values}
	return header
}

// NewAccessControlRequestHeadersHeader creates a Access-Control-Request-Headers HTTP Header.
func NewAccessControlRequestHeadersHeader(values ...string) Header {
	header := Header{
		Name:    name.AccessControlRequestHeaders,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAccessControlRequestMethodHeader creates a Access-Control-Request-Method HTTP Header.
func NewAccessControlRequestMethodHeader(values ...string) Header {
	header := Header{
		Name:    name.AccessControlRequestMethod,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewAgeHeader creates a Age HTTP Header.
func NewAgeHeader(values ...string) Header {
	header := Header{
		Name:   name.Age,
		Values: values}
	return header
}

// NewAllowHeader creates a Allow HTTP Header.
func NewAllowHeader(values ...string) Header {
	header := Header{
		Name:   name.Allow,
		Values: values}
	return header
}

// NewAltSvcHeader creates a Alt-Svc HTTP Header.
func NewAltSvcHeader(values ...string) Header {
	header := Header{
		Name:   name.AltSvc,
		Values: values}
	return header
}

// NewAltUsedHeader creates a Alt-Used HTTP Header.
func NewAltUsedHeader(values ...string) Header {
	header := Header{
		Name:   name.AltUsed,
		Values: values}
	return header
}

// NewAuthorizationHeader creates a Authorization HTTP Header.
func NewAuthorizationHeader(values ...string) Header {
	header := Header{
		Name:    name.Authorization,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewCacheControlHeader creates a Cache-Control HTTP Header.
func NewCacheControlHeader(values ...string) Header {
	header := Header{
		Name:   name.CacheControl,
		Values: values}
	return header
}

// NewClearSiteDataHeader creates a Clear-Site-Data HTTP Header.
func NewClearSiteDataHeader(values ...string) Header {
	header := Header{
		Name:    name.ClearSiteData,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewConnectionHeader creates a Connection HTTP Header.
func NewConnectionHeader(values ...string) Header {
	header := Header{
		Name:    name.Connection,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentDPRHeader creates a Content-DPR HTTP Header.
func NewContentDPRHeader(values ...string) Header {
	header := Header{
		Name:    name.ContentDPR,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentDispositionHeader creates a Content-Disposition HTTP Header.
func NewContentDispositionHeader(values ...string) Header {
	header := Header{
		Name:   name.ContentDisposition,
		Values: values}
	return header
}

// NewContentEncodingHeader creates a Content-Encoding HTTP Header.
func NewContentEncodingHeader(values ...string) Header {
	header := Header{
		Name:    name.ContentEncoding,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentLanguageHeader creates a Content-Language HTTP Header.
func NewContentLanguageHeader(values ...string) Header {
	header := Header{
		Name:    name.ContentLanguage,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentLengthHeader creates a Content-Length HTTP Header.
func NewContentLengthHeader(values ...string) Header {
	header := Header{
		Name:    name.ContentLength,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentLocationHeader creates a Content-Location HTTP Header.
func NewContentLocationHeader(values ...string) Header {
	header := Header{
		Name:   name.ContentLocation,
		Values: values}
	return header
}

// NewContentMD5Header creates a Content-MD5 HTTP Header.
func NewContentMD5Header(values ...string) Header {
	header := Header{
		Name:    name.ContentMD5,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentRangeHeader creates a Content-Range HTTP Header.
func NewContentRangeHeader(values ...string) Header {
	header := Header{
		Name:    name.ContentRange,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewContentSecurityPolicyHeader creates a Content-Security-Policy HTTP Header.
func NewContentSecurityPolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.ContentSecurityPolicy,
		Values: values}
	return header
}

// NewContentSecurityPolicyReportOnlyHeader creates a Content-Security-Policy-Report-Only HTTP Header.
func NewContentSecurityPolicyReportOnlyHeader(values ...string) Header {
	header := Header{
		Name:   name.ContentSecurityPolicyReportOnly,
		Values: values}
	return header
}

// NewContentTypeHeader creates a Content-Type HTTP Header.
func NewContentTypeHeader(values ...string) Header {
	header := Header{
		Name:    name.ContentType,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewCookieHeader creates a Cookie HTTP Header.
func NewCookieHeader(values ...string) Header {
	header := Header{
		Name:    name.Cookie,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewCorrelationIDHeader creates a Correlation-ID HTTP Header.
func NewCorrelationIDHeader(values ...string) Header {
	header := Header{
		Name:    name.CorrelationID,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewCriticalCHHeader creates a Critical-CH HTTP Header.
func NewCriticalCHHeader(values ...string) Header {
	header := Header{
		Name:   name.CriticalCH,
		Values: values}
	return header
}

// NewCrossOriginEmbedderPolicyHeader creates a Cross-Origin-Embedder-Policy HTTP Header.
func NewCrossOriginEmbedderPolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.CrossOriginEmbedderPolicy,
		Values: values}
	return header
}

// NewCrossOriginOpenerPolicyHeader creates a Cross-Origin-Opener-Policy HTTP Header.
func NewCrossOriginOpenerPolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.CrossOriginOpenerPolicy,
		Values: values}
	return header
}

// NewCrossOriginResourcePolicyHeader creates a Cross-Origin-Resource-Policy HTTP Header.
func NewCrossOriginResourcePolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.CrossOriginResourcePolicy,
		Values: values}
	return header
}

// NewDNTHeader creates a DNT HTTP Header.
func NewDNTHeader(values ...string) Header {
	header := Header{
		Name:    name.DNT,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewDPRHeader creates a DPR HTTP Header.
func NewDPRHeader(values ...string) Header {
	header := Header{
		Name:    name.DPR,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewDateHeader creates a Date HTTP Header.
func NewDateHeader(values ...string) Header {
	header := Header{
		Name:   name.Date,
		Values: values}
	return header
}

// NewDeltaBaseHeader creates a Delta-Base HTTP Header.
func NewDeltaBaseHeader(values ...string) Header {
	header := Header{
		Name:   name.DeltaBase,
		Values: values}
	return header
}

// NewDeviceMemoryHeader creates a Device-Memory HTTP Header.
func NewDeviceMemoryHeader(values ...string) Header {
	header := Header{
		Name:   name.DeviceMemory,
		Values: values}
	return header
}

// NewDigestHeader creates a Digest HTTP Header.
func NewDigestHeader(values ...string) Header {
	header := Header{
		Name:    name.Digest,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewDownlinkHeader creates a Downlink HTTP Header.
func NewDownlinkHeader(values ...string) Header {
	header := Header{
		Name:    name.Downlink,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewECTHeader creates a ECT HTTP Header.
func NewECTHeader(values ...string) Header {
	header := Header{
		Name:    name.ECT,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewETagHeader creates a ETag HTTP Header.
func NewETagHeader(values ...string) Header {
	header := Header{
		Name:   name.ETag,
		Values: values}
	return header
}

// NewEarlyDataHeader creates a Early-Data HTTP Header.
func NewEarlyDataHeader(values ...string) Header {
	header := Header{
		Name:   name.EarlyData,
		Values: values}
	return header
}

// NewExpectHeader creates a Expect HTTP Header.
func NewExpectHeader(values ...string) Header {
	header := Header{
		Name:    name.Expect,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewExpectCTHeader creates a Expect-CT HTTP Header.
func NewExpectCTHeader(values ...string) Header {
	header := Header{
		Name:    name.ExpectCT,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewExpiresHeader creates a Expires HTTP Header.
func NewExpiresHeader(values ...string) Header {
	header := Header{
		Name:   name.Expires,
		Values: values}
	return header
}

// NewForwardedHeader creates a Forwarded HTTP Header.
func NewForwardedHeader(values ...string) Header {
	header := Header{
		Name:   name.Forwarded,
		Values: values}
	return header
}

// NewFromHeader creates a From HTTP Header.
func NewFromHeader(values ...string) Header {
	header := Header{
		Name:    name.From,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewFrontEndHTTPSHeader creates a Front-End-HTTPS HTTP Header.
func NewFrontEndHTTPSHeader(values ...string) Header {
	header := Header{
		Name:   name.FrontEndHTTPS,
		Values: values}
	return header
}

// NewHTTP2SettingsHeader creates a HTTP2-Settings HTTP Header.
func NewHTTP2SettingsHeader(values ...string) Header {
	header := Header{
		Name:   name.HTTP2Settings,
		Values: values}
	return header
}

// NewHostHeader creates a Host HTTP Header.
func NewHostHeader(values ...string) Header {
	header := Header{
		Name:   name.Host,
		Values: values}
	return header
}

// NewIMHeader creates a IM HTTP Header.
func NewIMHeader(values ...string) Header {
	header := Header{
		Name:   name.IM,
		Values: values}
	return header
}

// NewIfMatchHeader creates a If-Match HTTP Header.
func NewIfMatchHeader(values ...string) Header {
	header := Header{
		Name:    name.IfMatch,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewIfModifiedSinceHeader creates a If-Modified-Since HTTP Header.
func NewIfModifiedSinceHeader(values ...string) Header {
	header := Header{
		Name:    name.IfModifiedSince,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewIfNoneMatchHeader creates a If-None-Match HTTP Header.
func NewIfNoneMatchHeader(values ...string) Header {
	header := Header{
		Name:    name.IfNoneMatch,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewIfRangeHeader creates a If-Range HTTP Header.
func NewIfRangeHeader(values ...string) Header {
	header := Header{
		Name:    name.IfRange,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewIfUnmodifiedSinceHeader creates a If-Unmodified-Since HTTP Header.
func NewIfUnmodifiedSinceHeader(values ...string) Header {
	header := Header{
		Name:    name.IfUnmodifiedSince,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewKeepAliveHeader creates a Keep-Alive HTTP Header.
func NewKeepAliveHeader(values ...string) Header {
	header := Header{
		Name:    name.KeepAlive,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewLargeAllocationHeader creates a Large-Allocation HTTP Header.
func NewLargeAllocationHeader(values ...string) Header {
	header := Header{
		Name:   name.LargeAllocation,
		Values: values}
	return header
}

// NewLastModifiedHeader creates a Last-Modified HTTP Header.
func NewLastModifiedHeader(values ...string) Header {
	header := Header{
		Name:   name.LastModified,
		Values: values}
	return header
}

// NewLinkHeader creates a Link HTTP Header.
func NewLinkHeader(values ...string) Header {
	header := Header{
		Name:   name.Link,
		Values: values}
	return header
}

// NewLocationHeader creates a Location HTTP Header.
func NewLocationHeader(values ...string) Header {
	header := Header{
		Name:   name.Location,
		Values: values}
	return header
}

// NewMaxForwardsHeader creates a Max-Forwards HTTP Header.
func NewMaxForwardsHeader(values ...string) Header {
	header := Header{
		Name:    name.MaxForwards,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewNELHeader creates a NEL HTTP Header.
func NewNELHeader(values ...string) Header {
	header := Header{
		Name:   name.NEL,
		Values: values}
	return header
}

// NewOriginHeader creates a Origin HTTP Header.
func NewOriginHeader(values ...string) Header {
	header := Header{
		Name:    name.Origin,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewP3PHeader creates a P3P HTTP Header.
func NewP3PHeader(values ...string) Header {
	header := Header{
		Name:   name.P3P,
		Values: values}
	return header
}

// NewPermissionsPolicyHeader creates a Permissions-Policy HTTP Header.
func NewPermissionsPolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.PermissionsPolicy,
		Values: values}
	return header
}

// NewPragmaHeader creates a Pragma HTTP Header.
func NewPragmaHeader(values ...string) Header {
	header := Header{
		Name:   name.Pragma,
		Values: values}
	return header
}

// NewPreferHeader creates a Prefer HTTP Header.
func NewPreferHeader(values ...string) Header {
	header := Header{
		Name:   name.Prefer,
		Values: values}
	return header
}

// NewPreferenceAppliedHeader creates a Preference-Applied HTTP Header.
func NewPreferenceAppliedHeader(values ...string) Header {
	header := Header{
		Name:   name.PreferenceApplied,
		Values: values}
	return header
}

// NewProxyAuthenticateHeader creates a Proxy-Authenticate HTTP Header.
func NewProxyAuthenticateHeader(values ...string) Header {
	header := Header{
		Name:    name.ProxyAuthenticate,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewProxyAuthorizationHeader creates a Proxy-Authorization HTTP Header.
func NewProxyAuthorizationHeader(values ...string) Header {
	header := Header{
		Name:    name.ProxyAuthorization,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewProxyConnectionHeader creates a Proxy-Connection HTTP Header.
func NewProxyConnectionHeader(values ...string) Header {
	header := Header{
		Name:   name.ProxyConnection,
		Values: values}
	return header
}

// NewPublicKeyPinsHeader creates a Public-Key-Pins HTTP Header.
func NewPublicKeyPinsHeader(values ...string) Header {
	header := Header{
		Name:   name.PublicKeyPins,
		Values: values}
	return header
}

// NewRTTHeader creates a RTT HTTP Header.
func NewRTTHeader(values ...string) Header {
	header := Header{
		Name:   name.RTT,
		Values: values}
	return header
}

// NewRangeHeader creates a Range HTTP Header.
func NewRangeHeader(values ...string) Header {
	header := Header{
		Name:    name.Range,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewRefererHeader creates a Referer HTTP Header.
func NewRefererHeader(values ...string) Header {
	header := Header{
		Name:    name.Referer,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewReferrerPolicyHeader creates a Referrer-Policy HTTP Header.
func NewReferrerPolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.ReferrerPolicy,
		Values: values}
	return header
}

// NewRefreshHeader creates a Refresh HTTP Header.
func NewRefreshHeader(values ...string) Header {
	header := Header{
		Name:   name.Refresh,
		Values: values}
	return header
}

// NewReportToHeader creates a Report-To HTTP Header.
func NewReportToHeader(values ...string) Header {
	header := Header{
		Name:   name.ReportTo,
		Values: values}
	return header
}

// NewRetryAfterHeader creates a Retry-After HTTP Header.
func NewRetryAfterHeader(values ...string) Header {
	header := Header{
		Name:   name.RetryAfter,
		Values: values}
	return header
}

// NewSaveDataHeader creates a Save-Data HTTP Header.
func NewSaveDataHeader(values ...string) Header {
	header := Header{
		Name:   name.SaveData,
		Values: values}
	return header
}

// NewSecCHPrefersColorSchemeHeader creates a Sec-CH-Prefers-Color-Scheme HTTP Header.
func NewSecCHPrefersColorSchemeHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHPrefersColorScheme,
		Values: values}
	return header
}

// NewSecCHPrefersReducedMotionHeader creates a Sec-CH-Prefers-Reduced-Motion HTTP Header.
func NewSecCHPrefersReducedMotionHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHPrefersReducedMotion,
		Values: values}
	return header
}

// NewSecCHPrefersReducedTransparencyHeader creates a Sec-CH-Prefers-Reduced-Transparency HTTP Header.
func NewSecCHPrefersReducedTransparencyHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHPrefersReducedTransparency,
		Values: values}
	return header
}

// NewSecCHUAHeader creates a Sec-CH-UA HTTP Header.
func NewSecCHUAHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUA,
		Values: values}
	return header
}

// NewSecCHUAArchHeader creates a Sec-CH-UA-Arch HTTP Header.
func NewSecCHUAArchHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAArch,
		Values: values}
	return header
}

// NewSecCHUABitnessHeader creates a Sec-CH-UA-Bitness HTTP Header.
func NewSecCHUABitnessHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUABitness,
		Values: values}
	return header
}

// NewSecCHUAFullVersionHeader creates a Sec-CH-UA-Full-Version HTTP Header.
func NewSecCHUAFullVersionHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAFullVersion,
		Values: values}
	return header
}

// NewSecCHUAFullVersionListHeader creates a Sec-CH-UA-Full-Version-List HTTP Header.
func NewSecCHUAFullVersionListHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAFullVersionList,
		Values: values}
	return header
}

// NewSecCHUAMobileHeader creates a Sec-CH-UA-Mobile HTTP Header.
func NewSecCHUAMobileHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAMobile,
		Values: values}
	return header
}

// NewSecCHUAModelHeader creates a Sec-CH-UA-Model HTTP Header.
func NewSecCHUAModelHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAModel,
		Values: values}
	return header
}

// NewSecCHUAPlatformHeader creates a Sec-CH-UA-Platform HTTP Header.
func NewSecCHUAPlatformHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAPlatform,
		Values: values}
	return header
}

// NewSecCHUAPlatformVersionHeader creates a Sec-CH-UA-Platform-Version HTTP Header.
func NewSecCHUAPlatformVersionHeader(values ...string) Header {
	header := Header{
		Name:   name.SecCHUAPlatformVersion,
		Values: values}
	return header
}

// NewSecFetchDestHeader creates a Sec-Fetch-Dest HTTP Header.
func NewSecFetchDestHeader(values ...string) Header {
	header := Header{
		Name:    name.SecFetchDest,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewSecFetchModeHeader creates a Sec-Fetch-Mode HTTP Header.
func NewSecFetchModeHeader(values ...string) Header {
	header := Header{
		Name:    name.SecFetchMode,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewSecFetchSiteHeader creates a Sec-Fetch-Site HTTP Header.
func NewSecFetchSiteHeader(values ...string) Header {
	header := Header{
		Name:    name.SecFetchSite,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewSecFetchUserHeader creates a Sec-Fetch-User HTTP Header.
func NewSecFetchUserHeader(values ...string) Header {
	header := Header{
		Name:    name.SecFetchUser,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewSecGPCHeader creates a Sec-GPC HTTP Header.
func NewSecGPCHeader(values ...string) Header {
	header := Header{
		Name:    name.SecGPC,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewSecPurposeHeader creates a Sec-Purpose HTTP Header.
func NewSecPurposeHeader(values ...string) Header {
	header := Header{
		Name:    name.SecPurpose,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewSecWebSocketAcceptHeader creates a Sec-WebSocket-Accept HTTP Header.
func NewSecWebSocketAcceptHeader(values ...string) Header {
	header := Header{
		Name:   name.SecWebSocketAccept,
		Values: values}
	return header
}

// NewServerHeader creates a Server HTTP Header.
func NewServerHeader(values ...string) Header {
	header := Header{
		Name:   name.Server,
		Values: values}
	return header
}

// NewServerTimingHeader creates a Server-Timing HTTP Header.
func NewServerTimingHeader(values ...string) Header {
	header := Header{
		Name:   name.ServerTiming,
		Values: values}
	return header
}

// NewServiceWorkerNavigationPreloadHeader creates a Service-Worker-Navigation-Preload HTTP Header.
func NewServiceWorkerNavigationPreloadHeader(values ...string) Header {
	header := Header{
		Name:   name.ServiceWorkerNavigationPreload,
		Values: values}
	return header
}

// NewSetCookieHeader creates a Set-Cookie HTTP Header.
func NewSetCookieHeader(values ...string) Header {
	header := Header{
		Name:   name.SetCookie,
		Values: values}
	return header
}

// NewSourceMapHeader creates a SourceMap HTTP Header.
func NewSourceMapHeader(values ...string) Header {
	header := Header{
		Name:   name.SourceMap,
		Values: values}
	return header
}

// NewStatusHeader creates a Status HTTP Header.
func NewStatusHeader(values ...string) Header {
	header := Header{
		Name:   name.Status,
		Values: values}
	return header
}

// NewStrictTransportSecurityHeader creates a Strict-Transport-Security HTTP Header.
func NewStrictTransportSecurityHeader(values ...string) Header {
	header := Header{
		Name:   name.StrictTransportSecurity,
		Values: values}
	return header
}

// NewTEHeader creates a TE HTTP Header.
func NewTEHeader(values ...string) Header {
	header := Header{
		Name:   name.TE,
		Values: values}
	return header
}

// NewTimingAllowOriginHeader creates a Timing-Allow-Origin HTTP Header.
func NewTimingAllowOriginHeader(values ...string) Header {
	header := Header{
		Name:   name.TimingAllowOrigin,
		Values: values}
	return header
}

// NewTKHeader creates a Tk HTTP Header.
func NewTKHeader(values ...string) Header {
	header := Header{
		Name:    name.TK,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewTrailerHeader creates a Trailer HTTP Header.
func NewTrailerHeader(values ...string) Header {
	header := Header{
		Name:    name.Trailer,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewTransferEncodingHeader creates a Transfer-Encoding HTTP Header.
func NewTransferEncodingHeader(values ...string) Header {
	header := Header{
		Name:    name.TransferEncoding,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewUpgradeHeader creates a Upgrade HTTP Header.
func NewUpgradeHeader(values ...string) Header {
	header := Header{
		Name:   name.Upgrade,
		Values: values}
	return header
}

// NewUpgradeInsecureRequestsHeader creates a Upgrade-Insecure-Requests HTTP Header.
func NewUpgradeInsecureRequestsHeader(values ...string) Header {
	header := Header{
		Name:    name.UpgradeInsecureRequests,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewUserAgentHeader creates a User-Agent HTTP Header.
func NewUserAgentHeader(values ...string) Header {
	header := Header{
		Name:    name.UserAgent,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewVaryHeader creates a Vary HTTP Header.
func NewVaryHeader(values ...string) Header {
	header := Header{
		Name:   name.Vary,
		Values: values}
	return header
}

// NewViaHeader creates a Via HTTP Header.
func NewViaHeader(values ...string) Header {
	header := Header{
		Name:   name.Via,
		Values: values}
	return header
}

// NewViewportWidthHeader creates a Viewport-Width HTTP Header.
func NewViewportWidthHeader(values ...string) Header {
	header := Header{
		Name:   name.ViewportWidth,
		Values: values}
	return header
}

// NewWWWAuthenticateHeader creates a WWW-Authenticate HTTP Header.
func NewWWWAuthenticateHeader(values ...string) Header {
	header := Header{
		Name:   name.WWWAuthenticate,
		Values: values}
	return header
}

// NewWantDigestHeader creates a Want-Digest HTTP Header.
func NewWantDigestHeader(values ...string) Header {
	header := Header{
		Name:   name.WantDigest,
		Values: values}
	return header
}

// NewWarningHeader creates a Warning HTTP Header.
func NewWarningHeader(values ...string) Header {
	header := Header{
		Name:   name.Warning,
		Values: values}
	return header
}

// NewWidthHeader creates a Width HTTP Header.
func NewWidthHeader(values ...string) Header {
	header := Header{
		Name:   name.Width,
		Values: values}
	return header
}

// NewXATTDeviceIDHeader creates a X-ATT-DeviceId HTTP Header.
func NewXATTDeviceIDHeader(values ...string) Header {
	header := Header{
		Name:    name.XATTDeviceID,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXContentDurationHeader creates a X-Content-Duration HTTP Header.
func NewXContentDurationHeader(values ...string) Header {
	header := Header{
		Name:   name.XContentDuration,
		Values: values}
	return header
}

// NewXContentSecurityPolicyHeader creates a X-Content-Security-Policy HTTP Header.
func NewXContentSecurityPolicyHeader(values ...string) Header {
	header := Header{
		Name:   name.XContentSecurityPolicy,
		Values: values}
	return header
}

// NewXContentTypeOptionsHeader creates a X-Content-Type-Options HTTP Header.
func NewXContentTypeOptionsHeader(values ...string) Header {
	header := Header{
		Name:   name.XContentTypeOptions,
		Values: values}
	return header
}

// NewXCorrelationIDHeader creates a X-Correlation-ID HTTP Header.
func NewXCorrelationIDHeader(values ...string) Header {
	header := Header{
		Name:   name.XCorrelationID,
		Values: values}
	return header
}

// NewXCSRFTokenHeader creates a X-CSRF-Token HTTP Header.
func NewXCSRFTokenHeader(values ...string) Header {
	header := Header{
		Name:    name.XCSRFToken,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXDNSPrefetchControlHeader creates a X-DNS-Prefetch-Control HTTP Header.
func NewXDNSPrefetchControlHeader(values ...string) Header {
	header := Header{
		Name:    name.XDNSPrefetchControl,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXForwardedForHeader creates a X-Forwarded-For HTTP Header.
func NewXForwardedForHeader(values ...string) Header {
	header := Header{
		Name:    name.XForwardedFor,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXForwardedHostHeader creates a X-Forwarded-Host HTTP Header.
func NewXForwardedHostHeader(values ...string) Header {
	header := Header{
		Name:    name.XForwardedHost,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXForwardedProtoHeader creates a X-Forwarded-Proto HTTP Header.
func NewXForwardedProtoHeader(values ...string) Header {
	header := Header{
		Name:    name.XForwardedProto,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXFrameOptionsHeader creates a X-Frame-Options HTTP Header.
func NewXFrameOptionsHeader(values ...string) Header {
	header := Header{
		Name:   name.XFrameOptions,
		Values: values}
	return header
}

// NewXHTTPMethodOverrideHeader creates a X-HTTP-Method-Override HTTP Header.
func NewXHTTPMethodOverrideHeader(values ...string) Header {
	header := Header{
		Name:    name.XHTTPMethodOverride,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXPoweredByHeader creates a X-Powered-By HTTP Header.
func NewXPoweredByHeader(values ...string) Header {
	header := Header{
		Name:    name.XPoweredBy,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXRedirectByHeader creates a X-Redirect-By HTTP Header.
func NewXRedirectByHeader(values ...string) Header {
	header := Header{
		Name:   name.XRedirectBy,
		Values: values}
	return header
}

// NewXRequestIDHeader creates a X-Request-ID HTTP Header.
func NewXRequestIDHeader(values ...string) Header {
	header := Header{
		Name:    name.XRequestID,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXRequestedWithHeader creates a X-Requested-With HTTP Header.
func NewXRequestedWithHeader(values ...string) Header {
	header := Header{
		Name:    name.XRequestedWith,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXUACompatibleHeader creates a X-UA-Compatible HTTP Header.
func NewXUACompatibleHeader(values ...string) Header {
	header := Header{
		Name:   name.XUACompatible,
		Values: values}
	return header
}

// NewXUIDHHeader creates a X-UIDH HTTP Header.
func NewXUIDHHeader(values ...string) Header {
	header := Header{
		Name:    name.XUIDH,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXWapProfileHeader creates a X-Wap-Profile HTTP Header.
func NewXWapProfileHeader(values ...string) Header {
	header := Header{
		Name:    name.XWapProfile,
		Request: true,
		// Response: false,
		Values: values}
	return header
}

// NewXWebKitCSPHeader creates a X-WebKit-CSP HTTP Header.
func NewXWebKitCSPHeader(values ...string) Header {
	header := Header{
		Name:   name.XWebKitCSP,
		Values: values}
	return header
}

// NewXXSSProtectionHeader creates a X-XSS-Protection HTTP Header.
func NewXXSSProtectionHeader(values ...string) Header {
	header := Header{
		Name:   name.XXSSProtection,
		Values: values}
	return header
}
