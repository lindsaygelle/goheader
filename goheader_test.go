package goheader_test

import (
	"testing"

	"github.com/lindsaygelle/goheader"
)

func TestNewAIMHeader(t *testing.T) {
	cfg := goheader.AIMConfig{}
	h := goheader.NewAIMHeader(cfg)
	if h.Name != goheader.AIM {
		t.Errorf("expected header name for AIM")
	}
}

func TestNewAcceptHeader(t *testing.T) {
	cfg := goheader.AcceptConfig{}
	h := goheader.NewAcceptHeader(cfg)
	if h.Name != goheader.Accept {
		t.Errorf("expected header name for Accept")
	}
}

func TestNewAcceptCHHeader(t *testing.T) {
	cfg := goheader.AcceptCHConfig{}
	h := goheader.NewAcceptCHHeader(cfg)
	if h.Name != goheader.AcceptCH {
		t.Errorf("expected header name for AcceptCH")
	}
}

func TestNewAcceptCHLifetimeHeader(t *testing.T) {
	cfg := goheader.AcceptCHLifetimeConfig{}
	h := goheader.NewAcceptCHLifetimeHeader(cfg)
	if h.Name != goheader.AcceptCHLifetime {
		t.Errorf("expected header name for AcceptCHLifetime")
	}
}

func TestNewAcceptCharsetHeader(t *testing.T) {
	cfg := goheader.AcceptCharsetConfig{}
	h := goheader.NewAcceptCharsetHeader(cfg)
	if h.Name != goheader.AcceptCharset {
		t.Errorf("expected header name for AcceptCharset")
	}
}

func TestNewAcceptDatetimeHeader(t *testing.T) {
	cfg := goheader.AcceptDatetimeConfig{}
	h := goheader.NewAcceptDatetimeHeader(cfg)
	if h.Name != goheader.AcceptDatetime {
		t.Errorf("expected header name for AcceptDatetime")
	}
}

func TestNewAcceptEncodingHeader(t *testing.T) {
	cfg := goheader.AcceptEncodingConfig{}
	h := goheader.NewAcceptEncodingHeader(cfg)
	if h.Name != goheader.AcceptEncoding {
		t.Errorf("expected header name for AcceptEncoding")
	}
}

func TestNewAcceptLanguageHeader(t *testing.T) {
	cfg := goheader.AcceptLanguageConfig{}
	h := goheader.NewAcceptLanguageHeader(cfg)
	if h.Name != goheader.AcceptLanguage {
		t.Errorf("expected header name for AcceptLanguage")
	}
}

func TestNewAcceptPatchHeader(t *testing.T) {
	cfg := goheader.AcceptPatchConfig{}
	h := goheader.NewAcceptPatchHeader(cfg)
	if h.Name != goheader.AcceptPatch {
		t.Errorf("expected header name for AcceptPatch")
	}
}

func TestNewAcceptPostHeader(t *testing.T) {
	cfg := goheader.AcceptPostConfig{}
	h := goheader.NewAcceptPostHeader(cfg)
	if h.Name != goheader.AcceptPost {
		t.Errorf("expected header name for AcceptPost")
	}
}

func TestNewAcceptRangesHeader(t *testing.T) {
	cfg := goheader.AcceptRangesConfig{}
	h := goheader.NewAcceptRangesHeader(cfg)
	if h.Name != goheader.AcceptRanges {
		t.Errorf("expected header name for AcceptRanges")
	}
}

func TestNewAccessControlAllowCredentialsHeader(t *testing.T) {
	cfg := goheader.AccessControlAllowCredentialsConfig{}
	h := goheader.NewAccessControlAllowCredentialsHeader(cfg)
	if h.Name != goheader.AccessControlAllowCredentials {
		t.Errorf("expected header name for AccessControlAllowCredentials")
	}
}

func TestNewAccessControlAllowHeadersHeader(t *testing.T) {
	cfg := goheader.AccessControlAllowHeadersConfig{}
	h := goheader.NewAccessControlAllowHeadersHeader(cfg)
	if h.Name != goheader.AccessControlAllowHeaders {
		t.Errorf("expected header name for AccessControlAllowHeaders")
	}
}

func TestNewAccessControlAllowMethodsHeader(t *testing.T) {
	cfg := goheader.AccessControlAllowMethodsConfig{}
	h := goheader.NewAccessControlAllowMethodsHeader(cfg)
	if h.Name != goheader.AccessControlAllowMethods {
		t.Errorf("expected header name for AccessControlAllowMethods")
	}
}

func TestNewAccessControlAllowOriginHeader(t *testing.T) {
	cfg := goheader.AccessControlAllowOriginConfig{}
	h := goheader.NewAccessControlAllowOriginHeader(cfg)
	if h.Name != goheader.AccessControlAllowOrigin {
		t.Errorf("expected header name for AccessControlAllowOrigin")
	}
}

func TestNewAccessControlExposeHeadersHeader(t *testing.T) {
	cfg := goheader.AccessControlExposeHeadersConfig{}
	h := goheader.NewAccessControlExposeHeadersHeader(cfg)
	if h.Name != goheader.AccessControlExposeHeaders {
		t.Errorf("expected header name for AccessControlExposeHeaders")
	}
}

func TestNewAccessControlMaxAgeHeader(t *testing.T) {
	cfg := goheader.AccessControlMaxAgeConfig{}
	h := goheader.NewAccessControlMaxAgeHeader(cfg)
	if h.Name != goheader.AccessControlMaxAge {
		t.Errorf("expected header name for AccessControlMaxAge")
	}
}

func TestNewAccessControlRequestHeadersHeader(t *testing.T) {
	cfg := goheader.AccessControlRequestHeadersConfig{}
	h := goheader.NewAccessControlRequestHeadersHeader(cfg)
	if h.Name != goheader.AccessControlRequestHeaders {
		t.Errorf("expected header name for AccessControlRequestHeaders")
	}
}

func TestNewAccessControlRequestMethodHeader(t *testing.T) {
	cfg := goheader.AccessControlRequestMethodConfig{}
	h := goheader.NewAccessControlRequestMethodHeader(cfg)
	if h.Name != goheader.AccessControlRequestMethod {
		t.Errorf("expected header name for AccessControlRequestMethod")
	}
}

func TestNewAgeHeader(t *testing.T) {
	cfg := goheader.AgeConfig{}
	h := goheader.NewAgeHeader(cfg)
	if h.Name != goheader.Age {
		t.Errorf("expected header name for Age")
	}
}

func TestNewAllowHeader(t *testing.T) {
	cfg := goheader.AllowConfig{}
	h := goheader.NewAllowHeader(cfg)
	if h.Name != goheader.Allow {
		t.Errorf("expected header name for Allow")
	}
}

func TestNewAltSvcHeader(t *testing.T) {
	cfg := goheader.AltSvcConfig{}
	h := goheader.NewAltSvcHeader(cfg)
	if h.Name != goheader.AltSvc {
		t.Errorf("expected header name for AltSvc")
	}
}

func TestNewAltUsedHeader(t *testing.T) {
	cfg := goheader.AltUsedConfig{}
	h := goheader.NewAltUsedHeader(cfg)
	if h.Name != goheader.AltUsed {
		t.Errorf("expected header name for AltUsed")
	}
}

func TestNewAuthorizationHeader(t *testing.T) {
	cfg := goheader.AuthorizationConfig{}
	h := goheader.NewAuthorizationHeader(cfg)
	if h.Name != goheader.Authorization {
		t.Errorf("expected header name for Authorization")
	}
}

func TestNewCacheControlHeader(t *testing.T) {
	cfg := goheader.CacheControlConfig{}
	h := goheader.NewCacheControlHeader(cfg)
	if h.Name != goheader.CacheControl {
		t.Errorf("expected header name for CacheControl")
	}
}

func TestNewClearSiteDataHeader(t *testing.T) {
	cfg := goheader.ClearSiteDataConfig{}
	h := goheader.NewClearSiteDataHeader(cfg)
	if h.Name != goheader.ClearSiteData {
		t.Errorf("expected header name for ClearSiteData")
	}
}

func TestNewConnectionHeader(t *testing.T) {
	cfg := goheader.ConnectionConfig{}
	h := goheader.NewConnectionHeader(cfg)
	if h.Name != goheader.Connection {
		t.Errorf("expected header name for Connection")
	}
}

func TestNewContentDPRHeader(t *testing.T) {
	cfg := goheader.ContentDPRConfig{}
	h := goheader.NewContentDPRHeader(cfg)
	if h.Name != goheader.ContentDPR {
		t.Errorf("expected header name for ContentDPR")
	}
}

func TestNewContentDispositionHeader(t *testing.T) {
	cfg := goheader.ContentDispositionConfig{}
	h := goheader.NewContentDispositionHeader(cfg)
	if h.Name != goheader.ContentDisposition {
		t.Errorf("expected header name for ContentDisposition")
	}
}

func TestNewContentEncodingHeader(t *testing.T) {
	cfg := goheader.ContentEncodingConfig{}
	h := goheader.NewContentEncodingHeader(cfg)
	if h.Name != goheader.ContentEncoding {
		t.Errorf("expected header name for ContentEncoding")
	}
}

func TestNewContentLanguageHeader(t *testing.T) {
	cfg := goheader.ContentLanguageConfig{}
	h := goheader.NewContentLanguageHeader(cfg)
	if h.Name != goheader.ContentLanguage {
		t.Errorf("expected header name for ContentLanguage")
	}
}

func TestNewContentLengthHeader(t *testing.T) {
	cfg := goheader.ContentLengthConfig{}
	h := goheader.NewContentLengthHeader(cfg)
	if h.Name != goheader.ContentLength {
		t.Errorf("expected header name for ContentLength")
	}
}

func TestNewContentLocationHeader(t *testing.T) {
	cfg := goheader.ContentLocationConfig{}
	h := goheader.NewContentLocationHeader(cfg)
	if h.Name != goheader.ContentLocation {
		t.Errorf("expected header name for ContentLocation")
	}
}

func TestNewContentMD5Header(t *testing.T) {
	cfg := goheader.ContentMD5Config{}
	h := goheader.NewContentMD5Header(cfg)
	if h.Name != goheader.ContentMD5 {
		t.Errorf("expected header name for ContentMD5")
	}
}

func TestNewContentRangeHeader(t *testing.T) {
	cfg := goheader.ContentRangeConfig{}
	h := goheader.NewContentRangeHeader(cfg)
	if h.Name != goheader.ContentRange {
		t.Errorf("expected header name for ContentRange")
	}
}

func TestNewContentSecurityPolicyHeader(t *testing.T) {
	cfg := goheader.ContentSecurityPolicyConfig{}
	h := goheader.NewContentSecurityPolicyHeader(cfg)
	if h.Name != goheader.ContentSecurityPolicy {
		t.Errorf("expected header name for ContentSecurityPolicy")
	}
}

func TestNewContentSecurityPolicyReportOnlyHeader(t *testing.T) {
	cfg := goheader.ContentSecurityPolicyReportOnlyConfig{}
	h := goheader.NewContentSecurityPolicyReportOnlyHeader(cfg)
	if h.Name != goheader.ContentSecurityPolicyReportOnly {
		t.Errorf("expected header name for ContentSecurityPolicyReportOnly")
	}
}

func TestNewContentTypeHeader(t *testing.T) {
	cfg := goheader.ContentTypeConfig{}
	h := goheader.NewContentTypeHeader(cfg)
	if h.Name != goheader.ContentType {
		t.Errorf("expected header name for ContentType")
	}
}

func TestNewCookieHeader(t *testing.T) {
	cfg := goheader.CookieConfig{}
	h := goheader.NewCookieHeader(cfg)
	if h.Name != goheader.Cookie {
		t.Errorf("expected header name for Cookie")
	}
}

func TestNewCorrelationIDHeader(t *testing.T) {
	cfg := goheader.CorrelationIDConfig{}
	h := goheader.NewCorrelationIDHeader(cfg)
	if h.Name != goheader.CorrelationID {
		t.Errorf("expected header name for CorrelationID")
	}
}

func TestNewCriticalCHHeader(t *testing.T) {
	cfg := goheader.CriticalCHConfig{}
	h := goheader.NewCriticalCHHeader(cfg)
	if h.Name != goheader.CriticalCH {
		t.Errorf("expected header name for CriticalCH")
	}
}

func TestNewCrossOriginEmbedderPolicyHeader(t *testing.T) {
	cfg := goheader.CrossOriginEmbedderPolicyConfig{}
	h := goheader.NewCrossOriginEmbedderPolicyHeader(cfg)
	if h.Name != goheader.CrossOriginEmbedderPolicy {
		t.Errorf("expected header name for CrossOriginEmbedderPolicy")
	}
}

func TestNewCrossOriginOpenerPolicyHeader(t *testing.T) {
	cfg := goheader.CrossOriginOpenerPolicyConfig{}
	h := goheader.NewCrossOriginOpenerPolicyHeader(cfg)
	if h.Name != goheader.CrossOriginOpenerPolicy {
		t.Errorf("expected header name for CrossOriginOpenerPolicy")
	}
}

func TestNewCrossOriginResourcePolicyHeader(t *testing.T) {
	cfg := goheader.CrossOriginResourcePolicyConfig{}
	h := goheader.NewCrossOriginResourcePolicyHeader(cfg)
	if h.Name != goheader.CrossOriginResourcePolicy {
		t.Errorf("expected header name for CrossOriginResourcePolicy")
	}
}

func TestNewDNTHeader(t *testing.T) {
	cfg := goheader.DNTConfig{}
	h := goheader.NewDNTHeader(cfg)
	if h.Name != goheader.DNT {
		t.Errorf("expected header name for DNT")
	}
}

func TestNewDPRHeader(t *testing.T) {
	cfg := goheader.DPRConfig{}
	h := goheader.NewDPRHeader(cfg)
	if h.Name != goheader.DPR {
		t.Errorf("expected header name for DPR")
	}
}

func TestNewDateHeader(t *testing.T) {
	cfg := goheader.DateConfig{}
	h := goheader.NewDateHeader(cfg)
	if h.Name != goheader.Date {
		t.Errorf("expected header name for Date")
	}
}

func TestNewDeltaBaseHeader(t *testing.T) {
	cfg := goheader.DeltaBaseConfig{}
	h := goheader.NewDeltaBaseHeader(cfg)
	if h.Name != goheader.DeltaBase {
		t.Errorf("expected header name for DeltaBase")
	}
}

func TestNewDeviceMemoryHeader(t *testing.T) {
	cfg := goheader.DeviceMemoryConfig{}
	h := goheader.NewDeviceMemoryHeader(cfg)
	if h.Name != goheader.DeviceMemory {
		t.Errorf("expected header name for DeviceMemory")
	}
}

func TestNewDigestHeader(t *testing.T) {
	cfg := goheader.DigestConfig{}
	h := goheader.NewDigestHeader(cfg)
	if h.Name != goheader.Digest {
		t.Errorf("expected header name for Digest")
	}
}

func TestNewDownlinkHeader(t *testing.T) {
	cfg := goheader.DownlinkConfig{}
	h := goheader.NewDownlinkHeader(cfg)
	if h.Name != goheader.Downlink {
		t.Errorf("expected header name for Downlink")
	}
}

func TestNewECTHeader(t *testing.T) {
	cfg := goheader.ECTConfig{}
	h := goheader.NewECTHeader(cfg)
	if h.Name != goheader.ECT {
		t.Errorf("expected header name for ECT")
	}
}

func TestNewETagHeader(t *testing.T) {
	cfg := goheader.ETagConfig{}
	h := goheader.NewETagHeader(cfg)
	if h.Name != goheader.ETag {
		t.Errorf("expected header name for ETag")
	}
}

func TestNewEarlyDataHeader(t *testing.T) {
	cfg := goheader.EarlyDataConfig{}
	h := goheader.NewEarlyDataHeader(cfg)
	if h.Name != goheader.EarlyData {
		t.Errorf("expected header name for EarlyData")
	}
}

func TestNewExpectHeader(t *testing.T) {
	cfg := goheader.ExpectConfig{}
	h := goheader.NewExpectHeader(cfg)
	if h.Name != goheader.Expect {
		t.Errorf("expected header name for Expect")
	}
}

func TestNewExpectCTHeader(t *testing.T) {
	cfg := goheader.ExpectCTConfig{}
	h := goheader.NewExpectCTHeader(cfg)
	if h.Name != goheader.ExpectCT {
		t.Errorf("expected header name for ExpectCT")
	}
}

func TestNewExpiresHeader(t *testing.T) {
	cfg := goheader.ExpiresConfig{}
	h := goheader.NewExpiresHeader(cfg)
	if h.Name != goheader.Expires {
		t.Errorf("expected header name for Expires")
	}
}

func TestNewForwardedHeader(t *testing.T) {
	cfg := goheader.ForwardedConfig{}
	h := goheader.NewForwardedHeader(cfg)
	if h.Name != goheader.Forwarded {
		t.Errorf("expected header name for Forwarded")
	}
}

func TestNewFromHeader(t *testing.T) {
	cfg := goheader.FromConfig{}
	h := goheader.NewFromHeader(cfg)
	if h.Name != goheader.From {
		t.Errorf("expected header name for From")
	}
}

func TestNewFrontEndHTTPSHeader(t *testing.T) {
	cfg := goheader.FrontEndHTTPSConfig{}
	h := goheader.NewFrontEndHTTPSHeader(cfg)
	if h.Name != goheader.FrontEndHTTPS {
		t.Errorf("expected header name for FrontEndHTTPS")
	}
}

func TestNewHTTP2SettingsHeader(t *testing.T) {
	cfg := goheader.HTTP2SettingsConfig{}
	h := goheader.NewHTTP2SettingsHeader(cfg)
	if h.Name != goheader.HTTP2Settings {
		t.Errorf("expected header name for HTTP2Settings")
	}
}

func TestNewHostHeader(t *testing.T) {
	cfg := goheader.HostConfig{}
	h := goheader.NewHostHeader(cfg)
	if h.Name != goheader.Host {
		t.Errorf("expected header name for Host")
	}
}

func TestNewIMHeader(t *testing.T) {
	cfg := goheader.IMConfig{}
	h := goheader.NewIMHeader(cfg)
	if h.Name != goheader.IM {
		t.Errorf("expected header name for IM")
	}
}

func TestNewIfMatchHeader(t *testing.T) {
	cfg := goheader.IfMatchConfig{}
	h := goheader.NewIfMatchHeader(cfg)
	if h.Name != goheader.IfMatch {
		t.Errorf("expected header name for IfMatch")
	}
}

func TestNewIfModifiedSinceHeader(t *testing.T) {
	cfg := goheader.IfModifiedSinceConfig{}
	h := goheader.NewIfModifiedSinceHeader(cfg)
	if h.Name != goheader.IfModifiedSince {
		t.Errorf("expected header name for IfModifiedSince")
	}
}

func TestNewIfNoneMatchHeader(t *testing.T) {
	cfg := goheader.IfNoneMatchConfig{}
	h := goheader.NewIfNoneMatchHeader(cfg)
	if h.Name != goheader.IfNoneMatch {
		t.Errorf("expected header name for IfNoneMatch")
	}
}

func TestNewIfRangeHeader(t *testing.T) {
	cfg := goheader.IfRangeConfig{}
	h := goheader.NewIfRangeHeader(cfg)
	if h.Name != goheader.IfRange {
		t.Errorf("expected header name for IfRange")
	}
}

func TestNewIfUnmodifiedSinceHeader(t *testing.T) {
	cfg := goheader.IfUnmodifiedSinceConfig{}
	h := goheader.NewIfUnmodifiedSinceHeader(cfg)
	if h.Name != goheader.IfUnmodifiedSince {
		t.Errorf("expected header name for IfUnmodifiedSince")
	}
}

func TestNewKeepAliveHeader(t *testing.T) {
	cfg := goheader.KeepAliveConfig{}
	h := goheader.NewKeepAliveHeader(cfg)
	if h.Name != goheader.KeepAlive {
		t.Errorf("expected header name for KeepAlive")
	}
}

func TestNewLargeAllocationHeader(t *testing.T) {
	cfg := goheader.LargeAllocationConfig{}
	h := goheader.NewLargeAllocationHeader(cfg)
	if h.Name != goheader.LargeAllocation {
		t.Errorf("expected header name for LargeAllocation")
	}
}

func TestNewLastModifiedHeader(t *testing.T) {
	cfg := goheader.LastModifiedConfig{}
	h := goheader.NewLastModifiedHeader(cfg)
	if h.Name != goheader.LastModified {
		t.Errorf("expected header name for LastModified")
	}
}

func TestNewLinkHeader(t *testing.T) {
	cfg := goheader.LinkConfig{}
	h := goheader.NewLinkHeader(cfg)
	if h.Name != goheader.Link {
		t.Errorf("expected header name for Link")
	}
}

func TestNewLocationHeader(t *testing.T) {
	cfg := goheader.LocationConfig{}
	h := goheader.NewLocationHeader(cfg)
	if h.Name != goheader.Location {
		t.Errorf("expected header name for Location")
	}
}

func TestNewMaxForwardsHeader(t *testing.T) {
	cfg := goheader.MaxForwardsConfig{}
	h := goheader.NewMaxForwardsHeader(cfg)
	if h.Name != goheader.MaxForwards {
		t.Errorf("expected header name for MaxForwards")
	}
}

func TestNewNELHeader(t *testing.T) {
	cfg := goheader.NELConfig{}
	h := goheader.NewNELHeader(cfg)
	if h.Name != goheader.NEL {
		t.Errorf("expected header name for NEL")
	}
}

func TestNewOriginHeader(t *testing.T) {
	cfg := goheader.OriginConfig{}
	h := goheader.NewOriginHeader(cfg)
	if h.Name != goheader.Origin {
		t.Errorf("expected header name for Origin")
	}
}

func TestNewP3PHeader(t *testing.T) {
	cfg := goheader.P3PConfig{}
	h := goheader.NewP3PHeader(cfg)
	if h.Name != goheader.P3P {
		t.Errorf("expected header name for P3P")
	}
}

func TestNewPermissionsPolicyHeader(t *testing.T) {
	cfg := goheader.PermissionsPolicyConfig{}
	h := goheader.NewPermissionsPolicyHeader(cfg)
	if h.Name != goheader.PermissionsPolicy {
		t.Errorf("expected header name for PermissionsPolicy")
	}
}

func TestNewPragmaHeader(t *testing.T) {
	cfg := goheader.PragmaConfig{}
	h := goheader.NewPragmaHeader(cfg)
	if h.Name != goheader.Pragma {
		t.Errorf("expected header name for Pragma")
	}
}

func TestNewPreferHeader(t *testing.T) {
	cfg := goheader.PreferConfig{}
	h := goheader.NewPreferHeader(cfg)
	if h.Name != goheader.Prefer {
		t.Errorf("expected header name for Prefer")
	}
}

func TestNewPreferenceAppliedHeader(t *testing.T) {
	cfg := goheader.PreferenceAppliedConfig{}
	h := goheader.NewPreferenceAppliedHeader(cfg)
	if h.Name != goheader.PreferenceApplied {
		t.Errorf("expected header name for PreferenceApplied")
	}
}

func TestNewPriorityHeader(t *testing.T) {
	cfg := goheader.PriorityConfig{}
	h := goheader.NewPriorityHeader(cfg)
	if h.Name != goheader.Priority {
		t.Errorf("expected header name for Priority")
	}
}

func TestNewProxyAuthenticateHeader(t *testing.T) {
	cfg := goheader.ProxyAuthenticateConfig{}
	h := goheader.NewProxyAuthenticateHeader(cfg)
	if h.Name != goheader.ProxyAuthenticate {
		t.Errorf("expected header name for ProxyAuthenticate")
	}
}

func TestNewProxyAuthenticationInfoHeader(t *testing.T) {
	cfg := goheader.ProxyAuthenticationInfoConfig{}
	h := goheader.NewProxyAuthenticationInfoHeader(cfg)
	if h.Name != goheader.ProxyAuthenticationInfo {
		t.Errorf("expected header name for ProxyAuthenticationInfo")
	}
}

func TestNewProxyAuthorizationHeader(t *testing.T) {
	cfg := goheader.ProxyAuthorizationConfig{}
	h := goheader.NewProxyAuthorizationHeader(cfg)
	if h.Name != goheader.ProxyAuthorization {
		t.Errorf("expected header name for ProxyAuthorization")
	}
}

func TestNewProxyConnectionHeader(t *testing.T) {
	cfg := goheader.ProxyConnectionConfig{}
	h := goheader.NewProxyConnectionHeader(cfg)
	if h.Name != goheader.ProxyConnection {
		t.Errorf("expected header name for ProxyConnection")
	}
}

func TestNewPublicKeyPinsHeader(t *testing.T) {
	cfg := goheader.PublicKeyPinsConfig{}
	h := goheader.NewPublicKeyPinsHeader(cfg)
	if h.Name != goheader.PublicKeyPins {
		t.Errorf("expected header name for PublicKeyPins")
	}
}

func TestNewPublicKeyPinsReportOnlyHeader(t *testing.T) {
	cfg := goheader.PublicKeyPinsReportOnlyConfig{}
	h := goheader.NewPublicKeyPinsReportOnlyHeader(cfg)
	if h.Name != goheader.PublicKeyPinsReportOnly {
		t.Errorf("expected header name for PublicKeyPinsReportOnly")
	}
}

func TestNewRTTHeader(t *testing.T) {
	cfg := goheader.RTTConfig{}
	h := goheader.NewRTTHeader(cfg)
	if h.Name != goheader.RTT {
		t.Errorf("expected header name for RTT")
	}
}

func TestNewRangeHeader(t *testing.T) {
	cfg := goheader.RangeConfig{}
	h := goheader.NewRangeHeader(cfg)
	if h.Name != goheader.Range {
		t.Errorf("expected header name for Range")
	}
}

func TestNewRefererHeader(t *testing.T) {
	cfg := goheader.RefererConfig{}
	h := goheader.NewRefererHeader(cfg)
	if h.Name != goheader.Referer {
		t.Errorf("expected header name for Referer")
	}
}

func TestNewReferrerPolicyHeader(t *testing.T) {
	cfg := goheader.ReferrerPolicyConfig{}
	h := goheader.NewReferrerPolicyHeader(cfg)
	if h.Name != goheader.ReferrerPolicy {
		t.Errorf("expected header name for ReferrerPolicy")
	}
}

func TestNewRefreshHeader(t *testing.T) {
	cfg := goheader.RefreshConfig{}
	h := goheader.NewRefreshHeader(cfg)
	if h.Name != goheader.Refresh {
		t.Errorf("expected header name for Refresh")
	}
}

func TestNewReplayNonceHeader(t *testing.T) {
	cfg := goheader.ReplayNonceConfig{}
	h := goheader.NewReplayNonceHeader(cfg)
	if h.Name != goheader.ReplayNonce {
		t.Errorf("expected header name for ReplayNonce")
	}
}

func TestNewReportToHeader(t *testing.T) {
	cfg := goheader.ReportToConfig{}
	h := goheader.NewReportToHeader(cfg)
	if h.Name != goheader.ReportTo {
		t.Errorf("expected header name for ReportTo")
	}
}

func TestNewReportingEndpointsHeader(t *testing.T) {
	cfg := goheader.ReportingEndpointsConfig{}
	h := goheader.NewReportingEndpointsHeader(cfg)
	if h.Name != goheader.ReportingEndpoints {
		t.Errorf("expected header name for ReportingEndpoints")
	}
}

func TestNewRetryAfterHeader(t *testing.T) {
	cfg := goheader.RetryAfterConfig{}
	h := goheader.NewRetryAfterHeader(cfg)
	if h.Name != goheader.RetryAfter {
		t.Errorf("expected header name for RetryAfter")
	}
}

func TestNewSaveDataHeader(t *testing.T) {
	cfg := goheader.SaveDataConfig{}
	h := goheader.NewSaveDataHeader(cfg)
	if h.Name != goheader.SaveData {
		t.Errorf("expected header name for SaveData")
	}
}

func TestNewSecCHPrefersColorSchemeHeader(t *testing.T) {
	cfg := goheader.SecCHPrefersColorSchemeConfig{}
	h := goheader.NewSecCHPrefersColorSchemeHeader(cfg)
	if h.Name != goheader.SecCHPrefersColorScheme {
		t.Errorf("expected header name for SecCHPrefersColorScheme")
	}
}

func TestNewSecCHPrefersReducedMotionHeader(t *testing.T) {
	cfg := goheader.SecCHPrefersReducedMotionConfig{}
	h := goheader.NewSecCHPrefersReducedMotionHeader(cfg)
	if h.Name != goheader.SecCHPrefersReducedMotion {
		t.Errorf("expected header name for SecCHPrefersReducedMotion")
	}
}

func TestNewSecCHPrefersReducedTransparencyHeader(t *testing.T) {
	cfg := goheader.SecCHPrefersReducedTransparencyConfig{}
	h := goheader.NewSecCHPrefersReducedTransparencyHeader(cfg)
	if h.Name != goheader.SecCHPrefersReducedTransparency {
		t.Errorf("expected header name for SecCHPrefersReducedTransparency")
	}
}

func TestNewSecCHUAHeader(t *testing.T) {
	cfg := goheader.SecCHUAConfig{}
	h := goheader.NewSecCHUAHeader(cfg)
	if h.Name != goheader.SecCHUA {
		t.Errorf("expected header name for SecCHUA")
	}
}

func TestNewSecCHUAArchHeader(t *testing.T) {
	cfg := goheader.SecCHUAArchConfig{}
	h := goheader.NewSecCHUAArchHeader(cfg)
	if h.Name != goheader.SecCHUAArch {
		t.Errorf("expected header name for SecCHUAArch")
	}
}

func TestNewSecCHUABitnessHeader(t *testing.T) {
	cfg := goheader.SecCHUABitnessConfig{}
	h := goheader.NewSecCHUABitnessHeader(cfg)
	if h.Name != goheader.SecCHUABitness {
		t.Errorf("expected header name for SecCHUABitness")
	}
}

func TestNewSecCHUAFullVersionHeader(t *testing.T) {
	cfg := goheader.SecCHUAFullVersionConfig{}
	h := goheader.NewSecCHUAFullVersionHeader(cfg)
	if h.Name != goheader.SecCHUAFullVersion {
		t.Errorf("expected header name for SecCHUAFullVersion")
	}
}

func TestNewSecCHUAFullVersionListHeader(t *testing.T) {
	cfg := goheader.SecCHUAFullVersionListConfig{}
	h := goheader.NewSecCHUAFullVersionListHeader(cfg)
	if h.Name != goheader.SecCHUAFullVersionList {
		t.Errorf("expected header name for SecCHUAFullVersionList")
	}
}

func TestNewSecCHUAMobileHeader(t *testing.T) {
	cfg := goheader.SecCHUAMobileConfig{}
	h := goheader.NewSecCHUAMobileHeader(cfg)
	if h.Name != goheader.SecCHUAMobile {
		t.Errorf("expected header name for SecCHUAMobile")
	}
}

func TestNewSecCHUAModelHeader(t *testing.T) {
	cfg := goheader.SecCHUAModelConfig{}
	h := goheader.NewSecCHUAModelHeader(cfg)
	if h.Name != goheader.SecCHUAModel {
		t.Errorf("expected header name for SecCHUAModel")
	}
}

func TestNewSecCHUAPlatformHeader(t *testing.T) {
	cfg := goheader.SecCHUAPlatformConfig{}
	h := goheader.NewSecCHUAPlatformHeader(cfg)
	if h.Name != goheader.SecCHUAPlatform {
		t.Errorf("expected header name for SecCHUAPlatform")
	}
}

func TestNewSecCHUAPlatformVersionHeader(t *testing.T) {
	cfg := goheader.SecCHUAPlatformVersionConfig{}
	h := goheader.NewSecCHUAPlatformVersionHeader(cfg)
	if h.Name != goheader.SecCHUAPlatformVersion {
		t.Errorf("expected header name for SecCHUAPlatformVersion")
	}
}

func TestNewSecCHUAWoW64Header(t *testing.T) {
	cfg := goheader.SecCHUAWoW64Config{}
	h := goheader.NewSecCHUAWoW64Header(cfg)
	if h.Name != goheader.SecCHUAWoW64 {
		t.Errorf("expected header name for SecCHUAWoW64")
	}
}

func TestNewSecFetchDestHeader(t *testing.T) {
	cfg := goheader.SecFetchDestConfig{}
	h := goheader.NewSecFetchDestHeader(cfg)
	if h.Name != goheader.SecFetchDest {
		t.Errorf("expected header name for SecFetchDest")
	}
}

func TestNewSecFetchModeHeader(t *testing.T) {
	cfg := goheader.SecFetchModeConfig{}
	h := goheader.NewSecFetchModeHeader(cfg)
	if h.Name != goheader.SecFetchMode {
		t.Errorf("expected header name for SecFetchMode")
	}
}

func TestNewSecFetchSiteHeader(t *testing.T) {
	cfg := goheader.SecFetchSiteConfig{}
	h := goheader.NewSecFetchSiteHeader(cfg)
	if h.Name != goheader.SecFetchSite {
		t.Errorf("expected header name for SecFetchSite")
	}
}

func TestNewSecFetchUserHeader(t *testing.T) {
	cfg := goheader.SecFetchUserConfig{}
	h := goheader.NewSecFetchUserHeader(cfg)
	if h.Name != goheader.SecFetchUser {
		t.Errorf("expected header name for SecFetchUser")
	}
}

func TestNewSecGPCHeader(t *testing.T) {
	cfg := goheader.SecGPCConfig{}
	h := goheader.NewSecGPCHeader(cfg)
	if h.Name != goheader.SecGPC {
		t.Errorf("expected header name for SecGPC")
	}
}

func TestNewSecPurposeHeader(t *testing.T) {
	cfg := goheader.SecPurposeConfig{}
	h := goheader.NewSecPurposeHeader(cfg)
	if h.Name != goheader.SecPurpose {
		t.Errorf("expected header name for SecPurpose")
	}
}

func TestNewSecWebSocketAcceptHeader(t *testing.T) {
	cfg := goheader.SecWebSocketAcceptConfig{}
	h := goheader.NewSecWebSocketAcceptHeader(cfg)
	if h.Name != goheader.SecWebSocketAccept {
		t.Errorf("expected header name for SecWebSocketAccept")
	}
}

func TestNewSecWebSocketExtensionsHeader(t *testing.T) {
	cfg := goheader.SecWebSocketExtensionsConfig{}
	h := goheader.NewSecWebSocketExtensionsHeader(cfg)
	if h.Name != goheader.SecWebSocketExtensions {
		t.Errorf("expected header name for SecWebSocketExtensions")
	}
}

func TestNewSecWebSocketKeyHeader(t *testing.T) {
	cfg := goheader.SecWebSocketKeyConfig{}
	h := goheader.NewSecWebSocketKeyHeader(cfg)
	if h.Name != goheader.SecWebSocketKey {
		t.Errorf("expected header name for SecWebSocketKey")
	}
}

func TestNewSecWebSocketProtocolHeader(t *testing.T) {
	cfg := goheader.SecWebSocketProtocolConfig{}
	h := goheader.NewSecWebSocketProtocolHeader(cfg)
	if h.Name != goheader.SecWebSocketProtocol {
		t.Errorf("expected header name for SecWebSocketProtocol")
	}
}

func TestNewSecWebSocketVersionHeader(t *testing.T) {
	cfg := goheader.SecWebSocketVersionConfig{}
	h := goheader.NewSecWebSocketVersionHeader(cfg)
	if h.Name != goheader.SecWebSocketVersion {
		t.Errorf("expected header name for SecWebSocketVersion")
	}
}

func TestNewServerHeader(t *testing.T) {
	cfg := goheader.ServerConfig{}
	h := goheader.NewServerHeader(cfg)
	if h.Name != goheader.Server {
		t.Errorf("expected header name for Server")
	}
}

func TestNewServerTimingHeader(t *testing.T) {
	cfg := goheader.ServerTimingConfig{}
	h := goheader.NewServerTimingHeader(cfg)
	if h.Name != goheader.ServerTiming {
		t.Errorf("expected header name for ServerTiming")
	}
}

func TestNewServiceWorkerNavigationPreloadHeader(t *testing.T) {
	cfg := goheader.ServiceWorkerNavigationPreloadConfig{}
	h := goheader.NewServiceWorkerNavigationPreloadHeader(cfg)
	if h.Name != goheader.ServiceWorkerNavigationPreload {
		t.Errorf("expected header name for ServiceWorkerNavigationPreload")
	}
}

func TestNewSetCookieHeader(t *testing.T) {
	cfg := goheader.SetCookieConfig{}
	h := goheader.NewSetCookieHeader(cfg)
	if h.Name != goheader.SetCookie {
		t.Errorf("expected header name for SetCookie")
	}
}

func TestNewSourceMapHeader(t *testing.T) {
	cfg := goheader.SourceMapConfig{}
	h := goheader.NewSourceMapHeader(cfg)
	if h.Name != goheader.SourceMap {
		t.Errorf("expected header name for SourceMap")
	}
}

func TestNewStatusHeader(t *testing.T) {
	cfg := goheader.StatusConfig{}
	h := goheader.NewStatusHeader(cfg)
	if h.Name != goheader.Status {
		t.Errorf("expected header name for Status")
	}
}

func TestNewStrictTransportSecurityHeader(t *testing.T) {
	cfg := goheader.StrictTransportSecurityConfig{}
	h := goheader.NewStrictTransportSecurityHeader(cfg)
	if h.Name != goheader.StrictTransportSecurity {
		t.Errorf("expected header name for StrictTransportSecurity")
	}
}

func TestNewSupportsLoadingModeHeader(t *testing.T) {
	cfg := goheader.SupportsLoadingModeConfig{}
	h := goheader.NewSupportsLoadingModeHeader(cfg)
	if h.Name != goheader.SupportsLoadingMode {
		t.Errorf("expected header name for SupportsLoadingMode")
	}
}

func TestNewTEHeader(t *testing.T) {
	cfg := goheader.TEConfig{}
	h := goheader.NewTEHeader(cfg)
	if h.Name != goheader.TE {
		t.Errorf("expected header name for TE")
	}
}

func TestNewTKHeader(t *testing.T) {
	cfg := goheader.TKConfig{}
	h := goheader.NewTKHeader(cfg)
	if h.Name != goheader.TK {
		t.Errorf("expected header name for TK")
	}
}

func TestNewTimingAllowOriginHeader(t *testing.T) {
	cfg := goheader.TimingAllowOriginConfig{}
	h := goheader.NewTimingAllowOriginHeader(cfg)
	if h.Name != goheader.TimingAllowOrigin {
		t.Errorf("expected header name for TimingAllowOrigin")
	}
}

func TestNewTrailerHeader(t *testing.T) {
	cfg := goheader.TrailerConfig{}
	h := goheader.NewTrailerHeader(cfg)
	if h.Name != goheader.Trailer {
		t.Errorf("expected header name for Trailer")
	}
}

func TestNewTransferEncodingHeader(t *testing.T) {
	cfg := goheader.TransferEncodingConfig{}
	h := goheader.NewTransferEncodingHeader(cfg)
	if h.Name != goheader.TransferEncoding {
		t.Errorf("expected header name for TransferEncoding")
	}
}

func TestNewUpgradeHeader(t *testing.T) {
	cfg := goheader.UpgradeConfig{}
	h := goheader.NewUpgradeHeader(cfg)
	if h.Name != goheader.Upgrade {
		t.Errorf("expected header name for Upgrade")
	}
}

func TestNewUpgradeInsecureRequestsHeader(t *testing.T) {
	cfg := goheader.UpgradeInsecureRequestsConfig{}
	h := goheader.NewUpgradeInsecureRequestsHeader(cfg)
	if h.Name != goheader.UpgradeInsecureRequests {
		t.Errorf("expected header name for UpgradeInsecureRequests")
	}
}

func TestNewUrgencyHeader(t *testing.T) {
	cfg := goheader.UrgencyConfig{}
	h := goheader.NewUrgencyHeader(cfg)
	if h.Name != goheader.Urgency {
		t.Errorf("expected header name for Urgency")
	}
}

func TestNewUserAgentHeader(t *testing.T) {
	cfg := goheader.UserAgentConfig{}
	h := goheader.NewUserAgentHeader(cfg)
	if h.Name != goheader.UserAgent {
		t.Errorf("expected header name for UserAgent")
	}
}

func TestNewVariantKeyHeader(t *testing.T) {
	cfg := goheader.VariantKeyConfig{}
	h := goheader.NewVariantKeyHeader(cfg)
	if h.Name != goheader.VariantKey {
		t.Errorf("expected header name for VariantKey")
	}
}

func TestNewVaryHeader(t *testing.T) {
	cfg := goheader.VaryConfig{}
	h := goheader.NewVaryHeader(cfg)
	if h.Name != goheader.Vary {
		t.Errorf("expected header name for Vary")
	}
}

func TestNewViaHeader(t *testing.T) {
	cfg := goheader.ViaConfig{}
	h := goheader.NewViaHeader(cfg)
	if h.Name != goheader.Via {
		t.Errorf("expected header name for Via")
	}
}

func TestNewViewportWidthHeader(t *testing.T) {
	cfg := goheader.ViewportWidthConfig{}
	h := goheader.NewViewportWidthHeader(cfg)
	if h.Name != goheader.ViewportWidth {
		t.Errorf("expected header name for ViewportWidth")
	}
}

func TestNewWWWAuthenticateHeader(t *testing.T) {
	cfg := goheader.WWWAuthenticateConfig{}
	h := goheader.NewWWWAuthenticateHeader(cfg)
	if h.Name != goheader.WWWAuthenticate {
		t.Errorf("expected header name for WWWAuthenticate")
	}
}

func TestNewWantDigestHeader(t *testing.T) {
	cfg := goheader.WantDigestConfig{}
	h := goheader.NewWantDigestHeader(cfg)
	if h.Name != goheader.WantDigest {
		t.Errorf("expected header name for WantDigest")
	}
}

func TestNewWarningHeader(t *testing.T) {
	cfg := goheader.WarningConfig{}
	h := goheader.NewWarningHeader(cfg)
	if h.Name != goheader.Warning {
		t.Errorf("expected header name for Warning")
	}
}

func TestNewWidthHeader(t *testing.T) {
	cfg := goheader.WidthConfig{}
	h := goheader.NewWidthHeader(cfg)
	if h.Name != goheader.Width {
		t.Errorf("expected header name for Width")
	}
}

func TestNewXATTDeviceIDHeader(t *testing.T) {
	cfg := goheader.XATTDeviceIDConfig{}
	h := goheader.NewXATTDeviceIDHeader(cfg)
	if h.Name != goheader.XATTDeviceID {
		t.Errorf("expected header name for XATTDeviceID")
	}
}

func TestNewXContentDurationHeader(t *testing.T) {
	cfg := goheader.XContentDurationConfig{}
	h := goheader.NewXContentDurationHeader(cfg)
	if h.Name != goheader.XContentDuration {
		t.Errorf("expected header name for XContentDuration")
	}
}

func TestNewXContentSecurityPolicyHeader(t *testing.T) {
	cfg := goheader.XContentSecurityPolicyConfig{}
	h := goheader.NewXContentSecurityPolicyHeader(cfg)
	if h.Name != goheader.XContentSecurityPolicy {
		t.Errorf("expected header name for XContentSecurityPolicy")
	}
}

func TestNewXContentTypeOptionsHeader(t *testing.T) {
	cfg := goheader.XContentTypeOptionsConfig{}
	h := goheader.NewXContentTypeOptionsHeader(cfg)
	if h.Name != goheader.XContentTypeOptions {
		t.Errorf("expected header name for XContentTypeOptions")
	}
}

func TestNewXCorrelationIDHeader(t *testing.T) {
	cfg := goheader.XCorrelationIDConfig{}
	h := goheader.NewXCorrelationIDHeader(cfg)
	if h.Name != goheader.XCorrelationID {
		t.Errorf("expected header name for XCorrelationID")
	}
}

func TestNewXCSRFTokenHeader(t *testing.T) {
	cfg := goheader.XCSRFTokenConfig{}
	h := goheader.NewXCSRFTokenHeader(cfg)
	if h.Name != goheader.XCSRFToken {
		t.Errorf("expected header name for XCSRFToken")
	}
}

func TestNewXDNSPrefetchControlHeader(t *testing.T) {
	cfg := goheader.XDNSPrefetchControlConfig{}
	h := goheader.NewXDNSPrefetchControlHeader(cfg)
	if h.Name != goheader.XDNSPrefetchControl {
		t.Errorf("expected header name for XDNSPrefetchControl")
	}
}

func TestNewXForwardedForHeader(t *testing.T) {
	cfg := goheader.XForwardedForConfig{}
	h := goheader.NewXForwardedForHeader(cfg)
	if h.Name != goheader.XForwardedFor {
		t.Errorf("expected header name for XForwardedFor")
	}
}

func TestNewXForwardedHostHeader(t *testing.T) {
	cfg := goheader.XForwardedHostConfig{}
	h := goheader.NewXForwardedHostHeader(cfg)
	if h.Name != goheader.XForwardedHost {
		t.Errorf("expected header name for XForwardedHost")
	}
}

func TestNewXForwardedProtoHeader(t *testing.T) {
	cfg := goheader.XForwardedProtoConfig{}
	h := goheader.NewXForwardedProtoHeader(cfg)
	if h.Name != goheader.XForwardedProto {
		t.Errorf("expected header name for XForwardedProto")
	}
}

func TestNewXFrameOptionsHeader(t *testing.T) {
	cfg := goheader.XFrameOptionsConfig{}
	h := goheader.NewXFrameOptionsHeader(cfg)
	if h.Name != goheader.XFrameOptions {
		t.Errorf("expected header name for XFrameOptions")
	}
}

func TestNewXHTTPMethodOverrideHeader(t *testing.T) {
	cfg := goheader.XHTTPMethodOverrideConfig{}
	h := goheader.NewXHTTPMethodOverrideHeader(cfg)
	if h.Name != goheader.XHTTPMethodOverride {
		t.Errorf("expected header name for XHTTPMethodOverride")
	}
}

func TestNewXPermittedCrossDomainPoliciesHeader(t *testing.T) {
	cfg := goheader.XPermittedCrossDomainPoliciesConfig{}
	h := goheader.NewXPermittedCrossDomainPoliciesHeader(cfg)
	if h.Name != goheader.XPermittedCrossDomainPolicies {
		t.Errorf("expected header name for XPermittedCrossDomainPolicies")
	}
}

func TestNewXPoweredByHeader(t *testing.T) {
	cfg := goheader.XPoweredByConfig{}
	h := goheader.NewXPoweredByHeader(cfg)
	if h.Name != goheader.XPoweredBy {
		t.Errorf("expected header name for XPoweredBy")
	}
}

func TestNewXRedirectByHeader(t *testing.T) {
	cfg := goheader.XRedirectByConfig{}
	h := goheader.NewXRedirectByHeader(cfg)
	if h.Name != goheader.XRedirectBy {
		t.Errorf("expected header name for XRedirectBy")
	}
}

func TestNewXRequestIDHeader(t *testing.T) {
	cfg := goheader.XRequestIDConfig{}
	h := goheader.NewXRequestIDHeader(cfg)
	if h.Name != goheader.XRequestID {
		t.Errorf("expected header name for XRequestID")
	}
}

func TestNewXRequestedWithHeader(t *testing.T) {
	cfg := goheader.XRequestedWithConfig{}
	h := goheader.NewXRequestedWithHeader(cfg)
	if h.Name != goheader.XRequestedWith {
		t.Errorf("expected header name for XRequestedWith")
	}
}

func TestNewXRobotsTagHeader(t *testing.T) {
	cfg := goheader.XRobotsTagConfig{}
	h := goheader.NewXRobotsTagHeader(cfg)
	if h.Name != goheader.XRobotsTag {
		t.Errorf("expected header name for XRobotsTag")
	}
}

func TestNewXUACompatibleHeader(t *testing.T) {
	cfg := goheader.XUACompatibleConfig{}
	h := goheader.NewXUACompatibleHeader(cfg)
	if h.Name != goheader.XUACompatible {
		t.Errorf("expected header name for XUACompatible")
	}
}

func TestNewXUIDHHeader(t *testing.T) {
	cfg := goheader.XUIDHConfig{}
	h := goheader.NewXUIDHHeader(cfg)
	if h.Name != goheader.XUIDH {
		t.Errorf("expected header name for XUIDH")
	}
}

func TestNewXWapProfileHeader(t *testing.T) {
	cfg := goheader.XWapProfileConfig{}
	h := goheader.NewXWapProfileHeader(cfg)
	if h.Name != goheader.XWapProfile {
		t.Errorf("expected header name for XWapProfile")
	}
}

func TestNewXWebKitCSPHeader(t *testing.T) {
	cfg := goheader.XWebKitCSPConfig{}
	h := goheader.NewXWebKitCSPHeader(cfg)
	if h.Name != goheader.XWebKitCSP {
		t.Errorf("expected header name for XWebKitCSP")
	}
}

func TestNewXXSSProtectionHeader(t *testing.T) {
	cfg := goheader.XXSSProtectionConfig{}
	h := goheader.NewXXSSProtectionHeader(cfg)
	if h.Name != goheader.XXSSProtection {
		t.Errorf("expected header name for XXSSProtection")
	}
}
