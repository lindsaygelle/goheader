package goheader

import "github.com/lindsaygelle/goheader/name"

type Header struct {
	Name name.Name
}

// NewAIMHeader creates a A-IM HTTP Header.
func NewAIMHeader() Header {
	header := Header{
		Name: name.AIM}
	return header
}

// NewAcceptHeader creates a Accept HTTP Header.
func NewAcceptHeader() Header {
	header := Header{
		Name: name.Accept}
	return header
}

// NewAcceptCHHeader creates a Accept-CH HTTP Header.
func NewAcceptCHHeader() Header {
	header := Header{
		Name: name.AcceptCH}
	return header
}

// NewAcceptCHLifetimeHeader creates a Accept-CH-Lifetime HTTP Header.
func NewAcceptCHLifetimeHeader() Header {
	header := Header{
		Name: name.AcceptCHLifetime}
	return header
}

// NewAcceptCharsetHeader creates a Accept-Charset HTTP Header.
func NewAcceptCharsetHeader() Header {
	header := Header{
		Name: name.AcceptCharset}
	return header
}

// NewAcceptDatetimeHeader creates a Accept-Datetime HTTP Header.
func NewAcceptDatetimeHeader() Header {
	header := Header{
		Name: name.AcceptDatetime}
	return header
}

// NewAcceptEncodingHeader creates a Accept-Encoding HTTP Header.
func NewAcceptEncodingHeader() Header {
	header := Header{
		Name: name.AcceptEncoding}
	return header
}

// NewAcceptLanguageHeader creates a Accept-Language HTTP Header.
func NewAcceptLanguageHeader() Header {
	header := Header{
		Name: name.AcceptLanguage}
	return header
}

// NewAcceptPatchHeader creates a Accept-Patch HTTP Header.
func NewAcceptPatchHeader() Header {
	header := Header{
		Name: name.AcceptPatch}
	return header
}

// NewAcceptPostHeader creates a Accept-Post HTTP Header.
func NewAcceptPostHeader() Header {
	header := Header{
		Name: name.AcceptPost}
	return header
}

// NewAcceptRangesHeader creates a Accept-Ranges HTTP Header.
func NewAcceptRangesHeader() Header {
	header := Header{
		Name: name.AcceptRanges}
	return header
}

// NewAccessControlAllowCredentialsHeader creates a Access-Control-Allow-Credentials HTTP Header.
func NewAccessControlAllowCredentialsHeader() Header {
	header := Header{
		Name: name.AccessControlAllowCredentials}
	return header
}

// NewAccessControlAllowHeadersHeader creates a Access-Control-Allow-Headers HTTP Header.
func NewAccessControlAllowHeadersHeader() Header {
	header := Header{
		Name: name.AccessControlAllowHeaders}
	return header
}

// NewAccessControlAllowMethodsHeader creates a Access-Control-Allow-Methods HTTP Header.
func NewAccessControlAllowMethodsHeader() Header {
	header := Header{
		Name: name.AccessControlAllowMethods}
	return header
}

// NewAccessControlAllowOriginHeader creates a Access-Control-Allow-Origin HTTP Header.
func NewAccessControlAllowOriginHeader() Header {
	header := Header{
		Name: name.AccessControlAllowOrigin}
	return header
}

// NewAccessControlExposeHeadersHeader creates a Access-Control-Expose-Headers HTTP Header.
func NewAccessControlExposeHeadersHeader() Header {
	header := Header{
		Name: name.AccessControlExposeHeaders}
	return header
}

// NewAccessControlMaxAgeHeader creates a Access-Control-Max-Age HTTP Header.
func NewAccessControlMaxAgeHeader() Header {
	header := Header{
		Name: name.AccessControlMaxAge}
	return header
}

// NewAccessControlRequestHeadersHeader creates a Access-Control-Request-Headers HTTP Header.
func NewAccessControlRequestHeadersHeader() Header {
	header := Header{
		Name: name.AccessControlRequestHeaders}
	return header
}

// NewAccessControlRequestMethodHeader creates a Access-Control-Request-Method HTTP Header.
func NewAccessControlRequestMethodHeader() Header {
	header := Header{
		Name: name.AccessControlRequestMethod}
	return header
}

// NewAgeHeader creates a Age HTTP Header.
func NewAgeHeader() Header {
	header := Header{
		Name: name.Age}
	return header
}

// NewAllowHeader creates a Allow HTTP Header.
func NewAllowHeader() Header {
	header := Header{
		Name: name.Allow}
	return header
}

// NewAltSvcHeader creates a Alt-Svc HTTP Header.
func NewAltSvcHeader() Header {
	header := Header{
		Name: name.AltSvc}
	return header
}

// NewAltUsedHeader creates a Alt-Used HTTP Header.
func NewAltUsedHeader() Header {
	header := Header{
		Name: name.AltUsed}
	return header
}

// NewAuthorizationHeader creates a Authorization HTTP Header.
func NewAuthorizationHeader() Header {
	header := Header{
		Name: name.Authorization}
	return header
}

// NewCacheControlHeader creates a Cache-Control HTTP Header.
func NewCacheControlHeader() Header {
	header := Header{
		Name: name.CacheControl}
	return header
}

// NewClearSiteDataHeader creates a Clear-Site-Data HTTP Header.
func NewClearSiteDataHeader() Header {
	header := Header{
		Name: name.ClearSiteData}
	return header
}

// NewConnectionHeader creates a Connection HTTP Header.
func NewConnectionHeader() Header {
	header := Header{
		Name: name.Connection}
	return header
}

// NewContentDPRHeader creates a Content-DPR HTTP Header.
func NewContentDPRHeader() Header {
	header := Header{
		Name: name.ContentDPR}
	return header
}

// NewContentDispositionHeader creates a Content-Disposition HTTP Header.
func NewContentDispositionHeader() Header {
	header := Header{
		Name: name.ContentDisposition}
	return header
}

// NewContentEncodingHeader creates a Content-Encoding HTTP Header.
func NewContentEncodingHeader() Header {
	header := Header{
		Name: name.ContentEncoding}
	return header
}

// NewContentLanguageHeader creates a Content-Language HTTP Header.
func NewContentLanguageHeader() Header {
	header := Header{
		Name: name.ContentLanguage}
	return header
}

// NewContentLengthHeader creates a Content-Length HTTP Header.
func NewContentLengthHeader() Header {
	header := Header{
		Name: name.ContentLength}
	return header
}

// NewContentLocationHeader creates a Content-Location HTTP Header.
func NewContentLocationHeader() Header {
	header := Header{
		Name: name.ContentLocation}
	return header
}

// NewContentMD5Header creates a Content-MD5 HTTP Header.
func NewContentMD5Header() Header {
	header := Header{
		Name: name.ContentMD5}
	return header
}

// NewContentRangeHeader creates a Content-Range HTTP Header.
func NewContentRangeHeader() Header {
	header := Header{
		Name: name.ContentRange}
	return header
}

// NewContentSecurityPolicyHeader creates a Content-Security-Policy HTTP Header.
func NewContentSecurityPolicyHeader() Header {
	header := Header{
		Name: name.ContentSecurityPolicy}
	return header
}

// NewContentSecurityPolicyReportOnlyHeader creates a Content-Security-Policy-Report-Only HTTP Header.
func NewContentSecurityPolicyReportOnlyHeader() Header {
	header := Header{
		Name: name.ContentSecurityPolicyReportOnly}
	return header
}

// NewContentTypeHeader creates a Content-Type HTTP Header.
func NewContentTypeHeader() Header {
	header := Header{
		Name: name.ContentType}
	return header
}

// NewCookieHeader creates a Cookie HTTP Header.
func NewCookieHeader() Header {
	header := Header{
		Name: name.Cookie}
	return header
}

// NewCorrelationIDHeader creates a Correlation-ID HTTP Header.
func NewCorrelationIDHeader() Header {
	header := Header{
		Name: name.CorrelationID}
	return header
}

// NewCriticalCHHeader creates a Critical-CH HTTP Header.
func NewCriticalCHHeader() Header {
	header := Header{
		Name: name.CriticalCH}
	return header
}

// NewCrossOriginEmbedderPolicyHeader creates a Cross-Origin-Embedder-Policy HTTP Header.
func NewCrossOriginEmbedderPolicyHeader() Header {
	header := Header{
		Name: name.CrossOriginEmbedderPolicy}
	return header
}

// NewCrossOriginOpenerPolicyHeader creates a Cross-Origin-Opener-Policy HTTP Header.
func NewCrossOriginOpenerPolicyHeader() Header {
	header := Header{
		Name: name.CrossOriginOpenerPolicy}
	return header
}

// NewCrossOriginResourcePolicyHeader creates a Cross-Origin-Resource-Policy HTTP Header.
func NewCrossOriginResourcePolicyHeader() Header {
	header := Header{
		Name: name.CrossOriginResourcePolicy}
	return header
}

// NewDNTHeader creates a DNT HTTP Header.
func NewDNTHeader() Header {
	header := Header{
		Name: name.DNT}
	return header
}

// NewDPRHeader creates a DPR HTTP Header.
func NewDPRHeader() Header {
	header := Header{
		Name: name.DPR}
	return header
}

// NewDateHeader creates a Date HTTP Header.
func NewDateHeader() Header {
	header := Header{
		Name: name.Date}
	return header
}

// NewDeltaBaseHeader creates a Delta-Base HTTP Header.
func NewDeltaBaseHeader() Header {
	header := Header{
		Name: name.DeltaBase}
	return header
}

// NewDeviceMemoryHeader creates a Device-Memory HTTP Header.
func NewDeviceMemoryHeader() Header {
	header := Header{
		Name: name.DeviceMemory}
	return header
}

// NewDigestHeader creates a Digest HTTP Header.
func NewDigestHeader() Header {
	header := Header{
		Name: name.Digest}
	return header
}

// NewDownlinkHeader creates a Downlink HTTP Header.
func NewDownlinkHeader() Header {
	header := Header{
		Name: name.Downlink}
	return header
}

// NewECTHeader creates a ECT HTTP Header.
func NewECTHeader() Header {
	header := Header{
		Name: name.ECT}
	return header
}

// NewETagHeader creates a ETag HTTP Header.
func NewETagHeader() Header {
	header := Header{
		Name: name.ETag}
	return header
}

// NewEarlyDataHeader creates a Early-Data HTTP Header.
func NewEarlyDataHeader() Header {
	header := Header{
		Name: name.EarlyData}
	return header
}

// NewExpectHeader creates a Expect HTTP Header.
func NewExpectHeader() Header {
	header := Header{
		Name: name.Expect}
	return header
}

// NewExpectCTHeader creates a Expect-CT HTTP Header.
func NewExpectCTHeader() Header {
	header := Header{
		Name: name.ExpectCT}
	return header
}

// NewExpiresHeader creates a Expires HTTP Header.
func NewExpiresHeader() Header {
	header := Header{
		Name: name.Expires}
	return header
}

// NewForwardedHeader creates a Forwarded HTTP Header.
func NewForwardedHeader() Header {
	header := Header{
		Name: name.Forwarded}
	return header
}

// NewFromHeader creates a From HTTP Header.
func NewFromHeader() Header {
	header := Header{
		Name: name.From}
	return header
}

// NewFrontEndHTTPSHeader creates a Front-End-HTTPS HTTP Header.
func NewFrontEndHTTPSHeader() Header {
	header := Header{
		Name: name.FrontEndHTTPS}
	return header
}

// NewHTTP2SettingsHeader creates a HTTP2-Settings HTTP Header.
func NewHTTP2SettingsHeader() Header {
	header := Header{
		Name: name.HTTP2Settings}
	return header
}

// NewHostHeader creates a Host HTTP Header.
func NewHostHeader() Header {
	header := Header{
		Name: name.Host}
	return header
}

// NewIMHeader creates a IM HTTP Header.
func NewIMHeader() Header {
	header := Header{
		Name: name.IM}
	return header
}

// NewIfMatchHeader creates a If-Match HTTP Header.
func NewIfMatchHeader() Header {
	header := Header{
		Name: name.IfMatch}
	return header
}

// NewIfModifiedSinceHeader creates a If-Modified-Since HTTP Header.
func NewIfModifiedSinceHeader() Header {
	header := Header{
		Name: name.IfModifiedSince}
	return header
}

// NewIfNoneMatchHeader creates a If-None-Match HTTP Header.
func NewIfNoneMatchHeader() Header {
	header := Header{
		Name: name.IfNoneMatch}
	return header
}

// NewIfRangeHeader creates a If-Range HTTP Header.
func NewIfRangeHeader() Header {
	header := Header{
		Name: name.IfRange}
	return header
}

// NewIfUnmodifiedSinceHeader creates a If-Unmodified-Since HTTP Header.
func NewIfUnmodifiedSinceHeader() Header {
	header := Header{
		Name: name.IfUnmodifiedSince}
	return header
}

// NewKeepAliveHeader creates a Keep-Alive HTTP Header.
func NewKeepAliveHeader() Header {
	header := Header{
		Name: name.KeepAlive}
	return header
}

// NewLargeAllocationHeader creates a Large-Allocation HTTP Header.
func NewLargeAllocationHeader() Header {
	header := Header{
		Name: name.LargeAllocation}
	return header
}

// NewLastModifiedHeader creates a Last-Modified HTTP Header.
func NewLastModifiedHeader() Header {
	header := Header{
		Name: name.LastModified}
	return header
}

// NewLinkHeader creates a Link HTTP Header.
func NewLinkHeader() Header {
	header := Header{
		Name: name.Link}
	return header
}

// NewLocationHeader creates a Location HTTP Header.
func NewLocationHeader() Header {
	header := Header{
		Name: name.Location}
	return header
}

// NewMaxForwardsHeader creates a Max-Forwards HTTP Header.
func NewMaxForwardsHeader() Header {
	header := Header{
		Name: name.MaxForwards}
	return header
}

// NewNELHeader creates a NEL HTTP Header.
func NewNELHeader() Header {
	header := Header{
		Name: name.NEL}
	return header
}

// NewOriginHeader creates a Origin HTTP Header.
func NewOriginHeader() Header {
	header := Header{
		Name: name.Origin}
	return header
}

// NewP3PHeader creates a P3P HTTP Header.
func NewP3PHeader() Header {
	header := Header{
		Name: name.P3P}
	return header
}

// NewPermissionsPolicyHeader creates a Permissions-Policy HTTP Header.
func NewPermissionsPolicyHeader() Header {
	header := Header{
		Name: name.PermissionsPolicy}
	return header
}

// NewPragmaHeader creates a Pragma HTTP Header.
func NewPragmaHeader() Header {
	header := Header{
		Name: name.Pragma}
	return header
}

// NewPreferHeader creates a Prefer HTTP Header.
func NewPreferHeader() Header {
	header := Header{
		Name: name.Prefer}
	return header
}

// NewPreferenceAppliedHeader creates a Preference-Applied HTTP Header.
func NewPreferenceAppliedHeader() Header {
	header := Header{
		Name: name.PreferenceApplied}
	return header
}

// NewProxyAuthenticateHeader creates a Proxy-Authenticate HTTP Header.
func NewProxyAuthenticateHeader() Header {
	header := Header{
		Name: name.ProxyAuthenticate}
	return header
}

// NewProxyAuthorizationHeader creates a Proxy-Authorization HTTP Header.
func NewProxyAuthorizationHeader() Header {
	header := Header{
		Name: name.ProxyAuthorization}
	return header
}

// NewProxyConnectionHeader creates a Proxy-Connection HTTP Header.
func NewProxyConnectionHeader() Header {
	header := Header{
		Name: name.ProxyConnection}
	return header
}

// NewPublicKeyPinsHeader creates a Public-Key-Pins HTTP Header.
func NewPublicKeyPinsHeader() Header {
	header := Header{
		Name: name.PublicKeyPins}
	return header
}

// NewRTTHeader creates a RTT HTTP Header.
func NewRTTHeader() Header {
	header := Header{
		Name: name.RTT}
	return header
}

// NewRangeHeader creates a Range HTTP Header.
func NewRangeHeader() Header {
	header := Header{
		Name: name.Range}
	return header
}

// NewRefererHeader creates a Referer HTTP Header.
func NewRefererHeader() Header {
	header := Header{
		Name: name.Referer}
	return header
}

// NewReferrerPolicyHeader creates a Referrer-Policy HTTP Header.
func NewReferrerPolicyHeader() Header {
	header := Header{
		Name: name.ReferrerPolicy}
	return header
}

// NewRefreshHeader creates a Refresh HTTP Header.
func NewRefreshHeader() Header {
	header := Header{
		Name: name.Refresh}
	return header
}

// NewReportToHeader creates a Report-To HTTP Header.
func NewReportToHeader() Header {
	header := Header{
		Name: name.ReportTo}
	return header
}

// NewRetryAfterHeader creates a Retry-After HTTP Header.
func NewRetryAfterHeader() Header {
	header := Header{
		Name: name.RetryAfter}
	return header
}

// NewSaveDataHeader creates a Save-Data HTTP Header.
func NewSaveDataHeader() Header {
	header := Header{
		Name: name.SaveData}
	return header
}

// NewSecCHPrefersColorSchemeHeader creates a Sec-CH-Prefers-Color-Scheme HTTP Header.
func NewSecCHPrefersColorSchemeHeader() Header {
	header := Header{
		Name: name.SecCHPrefersColorScheme}
	return header
}

// NewSecCHPrefersReducedMotionHeader creates a Sec-CH-Prefers-Reduced-Motion HTTP Header.
func NewSecCHPrefersReducedMotionHeader() Header {
	header := Header{
		Name: name.SecCHPrefersReducedMotion}
	return header
}

// NewSecCHPrefersReducedTransparencyHeader creates a Sec-CH-Prefers-Reduced-Transparency HTTP Header.
func NewSecCHPrefersReducedTransparencyHeader() Header {
	header := Header{
		Name: name.SecCHPrefersReducedTransparency}
	return header
}

// NewSecCHUAHeader creates a Sec-CH-UA HTTP Header.
func NewSecCHUAHeader() Header {
	header := Header{
		Name: name.SecCHUA}
	return header
}

// NewSecCHUAArchHeader creates a Sec-CH-UA-Arch HTTP Header.
func NewSecCHUAArchHeader() Header {
	header := Header{
		Name: name.SecCHUAArch}
	return header
}

// NewSecCHUABitnessHeader creates a Sec-CH-UA-Bitness HTTP Header.
func NewSecCHUABitnessHeader() Header {
	header := Header{
		Name: name.SecCHUABitness}
	return header
}

// NewSecCHUAFullVersionHeader creates a Sec-CH-UA-Full-Version HTTP Header.
func NewSecCHUAFullVersionHeader() Header {
	header := Header{
		Name: name.SecCHUAFullVersion}
	return header
}

// NewSecCHUAFullVersionListHeader creates a Sec-CH-UA-Full-Version-List HTTP Header.
func NewSecCHUAFullVersionListHeader() Header {
	header := Header{
		Name: name.SecCHUAFullVersionList}
	return header
}

// NewSecCHUAMobileHeader creates a Sec-CH-UA-Mobile HTTP Header.
func NewSecCHUAMobileHeader() Header {
	header := Header{
		Name: name.SecCHUAMobile}
	return header
}

// NewSecCHUAModelHeader creates a Sec-CH-UA-Model HTTP Header.
func NewSecCHUAModelHeader() Header {
	header := Header{
		Name: name.SecCHUAModel}
	return header
}

// NewSecCHUAPlatformHeader creates a Sec-CH-UA-Platform HTTP Header.
func NewSecCHUAPlatformHeader() Header {
	header := Header{
		Name: name.SecCHUAPlatform}
	return header
}

// NewSecCHUAPlatformVersionHeader creates a Sec-CH-UA-Platform-Version HTTP Header.
func NewSecCHUAPlatformVersionHeader() Header {
	header := Header{
		Name: name.SecCHUAPlatformVersion}
	return header
}

// NewSecFetchDestHeader creates a Sec-Fetch-Dest HTTP Header.
func NewSecFetchDestHeader() Header {
	header := Header{
		Name: name.SecFetchDest}
	return header
}

// NewSecFetchModeHeader creates a Sec-Fetch-Mode HTTP Header.
func NewSecFetchModeHeader() Header {
	header := Header{
		Name: name.SecFetchMode}
	return header
}

// NewSecFetchSiteHeader creates a Sec-Fetch-Site HTTP Header.
func NewSecFetchSiteHeader() Header {
	header := Header{
		Name: name.SecFetchSite}
	return header
}

// NewSecFetchUserHeader creates a Sec-Fetch-User HTTP Header.
func NewSecFetchUserHeader() Header {
	header := Header{
		Name: name.SecFetchUser}
	return header
}

// NewSecGPCHeader creates a Sec-GPC HTTP Header.
func NewSecGPCHeader() Header {
	header := Header{
		Name: name.SecGPC}
	return header
}

// NewSecPurposeHeader creates a Sec-Purpose HTTP Header.
func NewSecPurposeHeader() Header {
	header := Header{
		Name: name.SecPurpose}
	return header
}

// NewSecWebSocketAcceptHeader creates a Sec-WebSocket-Accept HTTP Header.
func NewSecWebSocketAcceptHeader() Header {
	header := Header{
		Name: name.SecWebSocketAccept}
	return header
}

// NewServerHeader creates a Server HTTP Header.
func NewServerHeader() Header {
	header := Header{
		Name: name.Server}
	return header
}

// NewServerTimingHeader creates a Server-Timing HTTP Header.
func NewServerTimingHeader() Header {
	header := Header{
		Name: name.ServerTiming}
	return header
}

// NewServiceWorkerNavigationPreloadHeader creates a Service-Worker-Navigation-Preload HTTP Header.
func NewServiceWorkerNavigationPreloadHeader() Header {
	header := Header{
		Name: name.ServiceWorkerNavigationPreload}
	return header
}

// NewSetCookieHeader creates a Set-Cookie HTTP Header.
func NewSetCookieHeader() Header {
	header := Header{
		Name: name.SetCookie}
	return header
}

// NewSourceMapHeader creates a SourceMap HTTP Header.
func NewSourceMapHeader() Header {
	header := Header{
		Name: name.SourceMap}
	return header
}

// NewStatusHeader creates a Status HTTP Header.
func NewStatusHeader() Header {
	header := Header{
		Name: name.Status}
	return header
}

// NewStrictTransportSecurityHeader creates a Strict-Transport-Security HTTP Header.
func NewStrictTransportSecurityHeader() Header {
	header := Header{
		Name: name.StrictTransportSecurity}
	return header
}

// NewTEHeader creates a TE HTTP Header.
func NewTEHeader() Header {
	header := Header{
		Name: name.TE}
	return header
}

// NewTimingAllowOriginHeader creates a Timing-Allow-Origin HTTP Header.
func NewTimingAllowOriginHeader() Header {
	header := Header{
		Name: name.TimingAllowOrigin}
	return header
}

// NewTKHeader creates a Tk HTTP Header.
func NewTKHeader() Header {
	header := Header{
		Name: name.TK}
	return header
}

// NewTrailerHeader creates a Trailer HTTP Header.
func NewTrailerHeader() Header {
	header := Header{
		Name: name.Trailer}
	return header
}

// NewTransferEncodingHeader creates a Transfer-Encoding HTTP Header.
func NewTransferEncodingHeader() Header {
	header := Header{
		Name: name.TransferEncoding}
	return header
}

// NewUpgradeHeader creates a Upgrade HTTP Header.
func NewUpgradeHeader() Header {
	header := Header{
		Name: name.Upgrade}
	return header
}

// NewUpgradeInsecureRequestsHeader creates a Upgrade-Insecure-Requests HTTP Header.
func NewUpgradeInsecureRequestsHeader() Header {
	header := Header{
		Name: name.UpgradeInsecureRequests}
	return header
}

// NewUserAgentHeader creates a User-Agent HTTP Header.
func NewUserAgentHeader() Header {
	header := Header{
		Name: name.UserAgent}
	return header
}

// NewVaryHeader creates a Vary HTTP Header.
func NewVaryHeader() Header {
	header := Header{
		Name: name.Vary}
	return header
}

// NewViaHeader creates a Via HTTP Header.
func NewViaHeader() Header {
	header := Header{
		Name: name.Via}
	return header
}

// NewViewportWidthHeader creates a Viewport-Width HTTP Header.
func NewViewportWidthHeader() Header {
	header := Header{
		Name: name.ViewportWidth}
	return header
}

// NewWWWAuthenticateHeader creates a WWW-Authenticate HTTP Header.
func NewWWWAuthenticateHeader() Header {
	header := Header{
		Name: name.WWWAuthenticate}
	return header
}

// NewWantDigestHeader creates a Want-Digest HTTP Header.
func NewWantDigestHeader() Header {
	header := Header{
		Name: name.WantDigest}
	return header
}

// NewWarningHeader creates a Warning HTTP Header.
func NewWarningHeader() Header {
	header := Header{
		Name: name.Warning}
	return header
}

// NewWidthHeader creates a Width HTTP Header.
func NewWidthHeader() Header {
	header := Header{
		Name: name.Width}
	return header
}

// NewXATTDeviceIDHeader creates a X-ATT-DeviceId HTTP Header.
func NewXATTDeviceIDHeader() Header {
	header := Header{
		Name: name.XATTDeviceID}
	return header
}

// NewXContentDurationHeader creates a X-Content-Duration HTTP Header.
func NewXContentDurationHeader() Header {
	header := Header{
		Name: name.XContentDuration}
	return header
}

// NewXContentSecurityPolicyHeader creates a X-Content-Security-Policy HTTP Header.
func NewXContentSecurityPolicyHeader() Header {
	header := Header{
		Name: name.XContentSecurityPolicy}
	return header
}

// NewXContentTypeOptionsHeader creates a X-Content-Type-Options HTTP Header.
func NewXContentTypeOptionsHeader() Header {
	header := Header{
		Name: name.XContentTypeOptions}
	return header
}

// NewXCorrelationIDHeader creates a X-Correlation-ID HTTP Header.
func NewXCorrelationIDHeader() Header {
	header := Header{
		Name: name.XCorrelationID}
	return header
}

// NewXCSRFTokenHeader creates a X-CSRF-Token HTTP Header.
func NewXCSRFTokenHeader() Header {
	header := Header{
		Name: name.XCSRFToken}
	return header
}

// NewXDNSPrefetchControlHeader creates a X-DNS-Prefetch-Control HTTP Header.
func NewXDNSPrefetchControlHeader() Header {
	header := Header{
		Name: name.XDNSPrefetchControl}
	return header
}

// NewXForwardedForHeader creates a X-Forwarded-For HTTP Header.
func NewXForwardedForHeader() Header {
	header := Header{
		Name: name.XForwardedFor}
	return header
}

// NewXForwardedHostHeader creates a X-Forwarded-Host HTTP Header.
func NewXForwardedHostHeader() Header {
	header := Header{
		Name: name.XForwardedHost}
	return header
}

// NewXForwardedProtoHeader creates a X-Forwarded-Proto HTTP Header.
func NewXForwardedProtoHeader() Header {
	header := Header{
		Name: name.XForwardedProto}
	return header
}

// NewXFrameOptionsHeader creates a X-Frame-Options HTTP Header.
func NewXFrameOptionsHeader() Header {
	header := Header{
		Name: name.XFrameOptions}
	return header
}

// NewXHTTPMethodOverrideHeader creates a X-HTTP-Method-Override HTTP Header.
func NewXHTTPMethodOverrideHeader() Header {
	header := Header{
		Name: name.XHTTPMethodOverride}
	return header
}

// NewXPoweredByHeader creates a X-Powered-By HTTP Header.
func NewXPoweredByHeader() Header {
	header := Header{
		Name: name.XPoweredBy}
	return header
}

// NewXRedirectByHeader creates a X-Redirect-By HTTP Header.
func NewXRedirectByHeader() Header {
	header := Header{
		Name: name.XRedirectBy}
	return header
}

// NewXRequestIDHeader creates a X-Request-ID HTTP Header.
func NewXRequestIDHeader() Header {
	header := Header{
		Name: name.XRequestID}
	return header
}

// NewXRequestedWithHeader creates a X-Requested-With HTTP Header.
func NewXRequestedWithHeader() Header {
	header := Header{
		Name: name.XRequestedWith}
	return header
}

// NewXUACompatibleHeader creates a X-UA-Compatible HTTP Header.
func NewXUACompatibleHeader() Header {
	header := Header{
		Name: name.XUACompatible}
	return header
}

// NewXUIDHHeader creates a X-UIDH HTTP Header.
func NewXUIDHHeader() Header {
	header := Header{
		Name: name.XUIDH}
	return header
}

// NewXWapProfileHeader creates a X-Wap-Profile HTTP Header.
func NewXWapProfileHeader() Header {
	header := Header{
		Name: name.XWapProfile}
	return header
}

// NewXWebKitCSPHeader creates a X-WebKit-CSP HTTP Header.
func NewXWebKitCSPHeader() Header {
	header := Header{
		Name: name.XWebKitCSP}
	return header
}

// NewXXSSProtectionHeader creates a X-XSS-Protection HTTP Header.
func NewXXSSProtectionHeader() Header {
	header := Header{
		Name: name.XXSSProtection}
	return header
}
