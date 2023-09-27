package name

// Name represents the name of an HTTP header.
type Name string

// AIM refers to the AcceptInfo-Messages (AIM) Header
const AIM Name = "A-IM"

// Accept refers to the Accept Header, used to indicate the media types that the client can process.
const Accept Name = "Accept"

// AcceptCH refers to the Accept-CH Header, used to indicate the client's willingness to accept server hints.
const AcceptCH Name = "Accept-CH"

// AcceptCHLifetime refers to the Accept-CH-Lifetime Header, specifying the time in seconds that hints are accepted.
const AcceptCHLifetime Name = "Accept-CH-Lifetime"

// AcceptCharset refers to the Accept-Charset Header, indicating character sets accepted by the client.
const AcceptCharset Name = "Accept-Charset"

// AcceptDatetime refers to the Accept-Datetime Header, indicating the client's preferred timestamp format.
const AcceptDatetime Name = "Accept-Datetime"

// AcceptEncoding refers to the Accept-Encoding Header, specifying encoding methods accepted by the client.
const AcceptEncoding Name = "Accept-Encoding"

// AcceptLanguage refers to the Accept-Language Header, indicating the preferred language of the client.
const AcceptLanguage Name = "Accept-Language"

// AcceptPatch refers to the Accept-Patch Header, specifying media types that are accepted for HTTP PATCH requests.
const AcceptPatch Name = "Accept-Patch"

// AcceptPost refers to the Accept-Post Header, indicating media types accepted for POST requests.
const AcceptPost Name = "Accept-Post"

// AcceptRanges refers to the Accept-Ranges Header, indicating server support for byte-range requests.
const AcceptRanges Name = "Accept-Ranges"

// AccessControlAllowCredentials refers to the Access-Control-Allow-Credentials Header, allowing credentials in cross-origin requests.
const AccessControlAllowCredentials Name = "Access-Control-Allow-Credentials"

// AccessControlAllowHeaders refers to the Access-Control-Allow-Headers Header, specifying allowed headers in CORS requests.
const AccessControlAllowHeaders Name = "Access-Control-Allow-Headers"

// AccessControlAllowMethods refers to the Access-Control-Allow-Methods Header, indicating allowed HTTP methods in CORS.
const AccessControlAllowMethods Name = "Access-Control-Allow-Methods"

// AccessControlAllowOrigin refers to the Access-Control-Allow-Origin Header, specifying allowed origins in CORS.
const AccessControlAllowOrigin Name = "Access-Control-Allow-Origin"

// AccessControlExposeHeaders refers to the Access-Control-Expose-Headers Header, specifying headers exposed in CORS responses.
const AccessControlExposeHeaders Name = "Access-Control-Expose-Headers"

// AccessControlMaxAge refers to the Access-Control-Max-Age Header, indicating how long CORS preflight responses can be cached.
const AccessControlMaxAge Name = "Access-Control-Max-Age"

// AccessControlRequestHeaders refers to the Access-Control-Request-Headers Header, indicating headers in a preflight request.
const AccessControlRequestHeaders Name = "Access-Control-Request-Headers"

// AccessControlRequestMethod refers to the Access-Control-Request-Method Header, indicating the HTTP method in a preflight request.
const AccessControlRequestMethod Name = "Access-Control-Request-Method"

// Age refers to the Age Header, indicating the age of a response in seconds.
const Age Name = "Age"

// Allow refers to the Allow Header, specifying HTTP methods allowed on a resource.
const Allow Name = "Allow"

// AltSvc refers to the Alt-Svc Header, providing alternative services for the same resource.
const AltSvc Name = "Alt-Svc"

// AltUsed refers to the Alt-Used Header, indicating the alternative service used to retrieve a resource.
const AltUsed Name = "Alt-Used"

// Authorization refers to the Authorization Header, used for user authentication credentials.
const Authorization Name = "Authorization"

// CacheControl refers to the Cache-Control Header, specifying caching directives for responses.
const CacheControl Name = "Cache-Control"

// ClearSiteData refers to the Clear-Site-Data Header, used to request data clearing from a site.
const ClearSiteData Name = "Clear-Site-Data"

// Connection refers to the Connection Header, indicating control options for the current connection.
const Connection Name = "Connection"

// ContentDPR refers to the Content-DPR Header, indicating the device pixel ratio of the rendering surface.
const ContentDPR Name = "Content-DPR"

// ContentDisposition refers to the Content-Disposition Header, specifying presentation style for the response.
const ContentDisposition Name = "Content-Disposition"

// ContentEncoding refers to the Content-Encoding Header, specifying the encoding transformations applied to the body.
const ContentEncoding Name = "Content-Encoding"

// ContentLanguage refers to the Content-Language Header, indicating the natural language of the content.
const ContentLanguage Name = "Content-Language"

// ContentLength refers to the Content-Length Header, indicating the size of the response body in bytes.
const ContentLength Name = "Content-Length"

// ContentLocation refers to the Content-Location Header, indicating the URL of the resource represented by the response.
const ContentLocation Name = "Content-Location"

// ContentMD5 refers to the Content-MD5 Header, providing a base64-encoded MD5 digest of the response content.
const ContentMD5 Name = "Content-MD5"

// ContentRange refers to the Content-Range Header, specifying the byte range of the response.
const ContentRange Name = "Content-Range"

// ContentSecurityPolicy refers to the Content-Security-Policy Header, specifying security policies for the resource.
const ContentSecurityPolicy Name = "Content-Security-Policy"

// ContentSecurityPolicyReportOnly refers to the Content-Security-Policy-Report-Only Header, specifying security policies for reporting only.
const ContentSecurityPolicyReportOnly Name = "Content-Security-Policy-Report-Only"

// ContentType refers to the Content-Type Header, indicating the media type of the response.
const ContentType Name = "Content-Type"

// Cookie refers to the Cookie Header, containing cookies associated with the request.
const Cookie Name = "Cookie"

// CorrelationID refers to the Correlation-ID Header, used for tracing and correlating requests.
const CorrelationID Name = "Correlation-ID"

// CriticalCH refers to the Critical-CH Header, indicating that certain hints are critical for rendering.
const CriticalCH Name = "Critical-CH"

// CrossOriginEmbedderPolicy refers to the Cross-Origin-Embedder-Policy Header, specifying cross-origin embedder policies.
const CrossOriginEmbedderPolicy Name = "Cross-Origin-Embedder-Policy"

// CrossOriginOpenerPolicy refers to the Cross-Origin-Opener-Policy Header, specifying cross-origin opener policies.
const CrossOriginOpenerPolicy Name = "Cross-Origin-Opener-Policy"

// CrossOriginResourcePolicy refers to the Cross-Origin-Resource-Policy Header, specifying cross-origin resource policies.
const CrossOriginResourcePolicy Name = "Cross-Origin-Resource-Policy"

// DNT refers to the DNT (Do Not Track) Header, indicating the user's tracking preference.
const DNT Name = "DNT"

// DPR refers to the DPR (Device Pixel Ratio) Header, indicating the device's pixel density.
const DPR Name = "DPR"

// Date refers to the Date Header, indicating the date and time when the response was generated.
const Date Name = "Date"

// DeltaBase refers to the Delta-Base Header, specifying the base for delta encoding.
const DeltaBase Name = "Delta-Base"

// DeviceMemory refers to the Device-Memory Header, indicating the device's available memory.
const DeviceMemory Name = "Device-Memory"

// Digest refers to the Digest Header, providing integrity verification information for a response.
const Digest Name = "Digest"

// Downlink refers to the Downlink Header, indicating the client's downlink speed in Mbps.
const Downlink Name = "Downlink"

// ECT refers to the ECT (Explicit Congestion Notification) Header, specifying network congestion information.
const ECT Name = "ECT"

// ETag refers to the ETag Header, providing a unique identifier for a resource.
const ETag Name = "ETag"

// EarlyData refers to the Early-Data Header, indicating that the request is sent in early data mode.
const EarlyData Name = "Early-Data"

// Expect refers to the Expect Header, specifying expectations for server behavior.
const Expect Name = "Expect"

// ExpectCT refers to the Expect-CT Header, specifying expectations for Certificate Transparency.
const ExpectCT Name = "Expect-CT"

// Expires refers to the Expires Header, indicating the date and time when the response expires.
const Expires Name = "Expires"

// Forwarded refers to the Forwarded Header, indicating the client's forwarding information.
const Forwarded Name = "Forwarded"

// From refers to the From Header, indicating the user's email address or name.
const From Name = "From"

// FrontEndHTTPS refers to the Front-End-Https Header, indicating the presence of a secure frontend.
const FrontEndHTTPS Name = "Front-End-Https"

// HTTP2Settings refers to the HTTP2-Settings Header, specifying settings for HTTP/2.
const HTTP2Settings Name = "HTTP2-Settings"

// Host refers to the Host Header, indicating the domain name of the server.
const Host Name = "Host"

// IM refers to the IM (InstanceManipulations) Header, indicating instance manipulations for HTTP/1.1.
const IM Name = "IM"

// IfMatch refers to the If-Match Header, specifying conditions for a conditional request.
const IfMatch Name = "If-Match"

// IfModifiedSince refers to the If-Modified-Since Header, indicating a conditional request based on modification time.
const IfModifiedSince Name = "If-Modified-Since"

// IfNoneMatch refers to the If-None-Match Header, specifying conditions for a conditional request.
const IfNoneMatch Name = "If-None-Match"

// IfRange refers to the If-Range Header, used in conditional range requests.
const IfRange Name = "If-Range"

// IfUnmodified-Since refers to the If-Unmodified-Since Header, indicating a conditional request based on unmodified time.
const IfUnmodifiedSince Name = "If-Unmodified-Since"

// KeepAlive refers to the Keep-Alive Header, indicating options for persistent connections.
const KeepAlive Name = "Keep-Alive"

// LargeAllocation refers to the Large-Allocation Header, indicating resource allocation preferences.
const LargeAllocation Name = "Large-Allocation"

// LastModified refers to the Last-Modified Header, indicating the last modification date of the resource.
const LastModified Name = "Last-Modified"

// Link refers to the Link Header, specifying relationships between resources.
const Link Name = "Link"

// Location refers to the Location Header, indicating the URL to which a client should redirect.
const Location Name = "Location"

// MaxForwards refers to the Max-Forwards Header, specifying the maximum number of forwards in a request chain.
const MaxForwards Name = "Max-Forwards"

// NEL refers to the NEL (Network Error Logging) Header, indicating error reporting policies.
const NEL Name = "NEL"

// Origin refers to the Origin Header, indicating the origin of the initiating request.
const Origin Name = "Origin"

// P3P refers to the P3P (Platform for Privacy Preferences) Header, indicating privacy preferences.
const P3P Name = "P3P"

// PermissionsPolicy refers to the Permissions-Policy Header, specifying feature policies for a page.
const PermissionsPolicy Name = "Permissions-Policy"

// Pragma refers to the Pragma Header, specifying implementationspecific directives.
const Pragma Name = "Pragma"

// Prefer refers to the Prefer Header, specifying preferences for the response.
const Prefer Name = "Prefer"

// PreferenceApplied refers to the Preference-Applied Header, indicating applied preferences.
const PreferenceApplied Name = "Preference-Applied"

// ProxyAuthenticate refers to the Proxy-Authenticate Header, indicating authentication for a proxy.
const ProxyAuthenticate Name = "Proxy-Authenticate"

// ProxyAuthorization refers to the Proxy-Authorization Header, providing credentials for a proxy.
const ProxyAuthorization Name = "Proxy-Authorization"

// ProxyConnection refers to the Proxy-Connection Header, indicating options for a proxy connection.
const ProxyConnection Name = "Proxy-Connection"

// PublicKey-Pins refers to the Public-Key-Pins Header, specifying public key pinning for a host.
const PublicKeyPins Name = "Public-Key-Pins"

// RTT refers to the RTT (RoundTrip Time) Header, indicating the estimated round-trip time.
const RTT Name = "RTT"

// Range refers to the Range Header, specifying the byte range of a partial response.
const Range Name = "Range"

// Referer refers to the Referer Header, indicating the referring URL.
const Referer Name = "Referer"

// ReferrerPolicy refers to the Referrer-Policy Header, specifying the referrer policy for requests.
const ReferrerPolicy Name = "Referrer-Policy"

// Refresh refers to the Refresh Header, indicating a delay before reloading a resource.
const Refresh Name = "Refresh"

// ReportTo refers to the Report-To Header, specifying endpoints for reporting violations.
const ReportTo Name = "Report-To"

// RetryAfter refers to the Retry-After Header, indicating when a request can be retried.
const RetryAfter Name = "Retry-After"

// SaveData refers to the Save-Data Header, indicating data-saving preferences.
const SaveData Name = "Save-Data"

// SecCHPrefersColorScheme refers to the Sec-CH-Prefers-Color-Scheme Header, indicating color scheme preferences.
const SecCHPrefersColorScheme Name = "Sec-CH-Prefers-Color-Scheme"

// SecCHPrefersReducedMotion refers to the Sec-CH-Prefers-Reduced-Motion Header, indicating a preference for reduced motion.
const SecCHPrefersReducedMotion Name = "Sec-CH-Prefers-Reduced-Motion"

// SecCHPrefersReducedTransparency refers to the Sec-CH-Prefers-Reduced-Transparency Header, indicating a preference for reduced transparency.
const SecCHPrefersReducedTransparency Name = "Sec-CH-Prefers-Reduced-Transparency"

// SecCHUA refers to the Sec-CH-UA (User-Agent) Header, indicating the client's User-Agent string.
const SecCHUA Name = "Sec-CH-UA"

// SecCHUAArch refers to the Sec-CH-UA-Arch Header, indicating the client's architecture.
const SecCHUAArch Name = "Sec-CH-UA-Arch"

// SecCHUABitness refers to the Sec-CH-UA-Bitness Header, indicating the client's bitness.
const SecCHUABitness Name = "Sec-CH-UA-Bitness"

// SecCHUAFull-Version refers to the Sec-CH-UA-Full-Version Header, indicating the client's full version.
const SecCHUAFullVersion Name = "Sec-CH-UA-Full-Version"

// SecCHUAFullVersionList refers to the Sec-CH-UA-Full-Version-List Header, indicating a list of full versions.
const SecCHUAFullVersionList Name = "Sec-CH-UA-Full-Version-List"

// SecCHUAMobile refers to the Sec-CH-UA-Mobile Header, indicating if the client is a mobile device.
const SecCHUAMobile Name = "Sec-CH-UA-Mobile"

// SecCHUAModel refers to the Sec-CH-UA-Model Header, indicating the client's model.
const SecCHUAModel Name = "Sec-CH-UA-Model"

// SecCHUAPlatform refers to the Sec-CH-UA-Platform Header, indicating the client's platform.
const SecCHUAPlatform Name = "Sec-CH-UA-Platform"

// SecCHUAPlatformVersion refers to the Sec-CH-UA-Platform-Version Header, indicating the client's platform version.
const SecCHUAPlatformVersion Name = "Sec-CH-UA-Platform-Version"

// SecFetchDest refers to the Sec-Fetch-Dest Header, indicating the destination of a fetch request.
const SecFetchDest Name = "Sec-Fetch-Dest"

// SecFetchMode refers to the Sec-Fetch-Mode Header, indicating the mode of a fetch request.
const SecFetchMode Name = "Sec-Fetch-Mode"

// SecFetchSite refers to the Sec-Fetch-Site Header, indicating the site type of a fetch request.
const SecFetchSite Name = "Sec-Fetch-Site"

// SecFetchUser refers to the Sec-Fetch-User Header, indicating the user type of a fetch request.
const SecFetchUser Name = "Sec-Fetch-User"

// SecGPC refers to the Sec-GPC Header, indicating the Google Page Cached status.
const SecGPC Name = "Sec-GPC"

// SecPurpose refers to the Sec-Purpose Header, indicating the purpose of a request.
const SecPurpose Name = "Sec-Purpose"

// SecWebSocketAccept refers to the Sec-WebSocket-Accept Header, indicating acceptance of a WebSocket handshake.
const SecWebSocketAccept Name = "Sec-WebSocket-Accept"

// Server refers to the Server Header, indicating the server software and version.
const Server Name = "Server"

// ServerTiming refers to the Server-Timing Header, providing performance timing data.
const ServerTiming Name = "Server-Timing"

// ServiceWorkerNavigationPreload refers to the Service-Worker-Navigation-Preload Header, indicating navigation preload status.
const ServiceWorkerNavigationPreload Name = "Service-Worker-Navigation-Preload"

// SetCookie refers to the Set-Cookie Header, setting cookies in HTTP responses.
const SetCookie Name = "Set-Cookie"

// SourceMap refers to the SourceMap Header, indicating the source map for JavaScript resources.
const SourceMap Name = "SourceMap"

// Status refers to the Status Header, indicating the status of a response.
const Status Name = "Status"

// StrictTransportSecurity refers to the Strict-Transport-Security Header, specifying security policies for HTTPS.
const StrictTransportSecurity Name = "Strict-Transport-Security"

// TE refers to the TE (TransferEncoding) Header, specifying transfer encodings accepted by the client.
const TE Name = "TE"

// TimingAllowOrigin refers to the Timing-Allow-Origin Header, specifying origins for resource timing.
const TimingAllowOrigin Name = "Timing-Allow-Origin"

// TK refers to the Tk Header, indicating tracking preferences of the user agent.
const TK Name = "Tk"

// Trailer refers to the Trailer Header, indicating the trailers present in chunkedencoded responses.
const Trailer Name = "Trailer"

// TransferEncoding refers to the Transfer-Encoding Header, specifying transfer encodings applied to the message body.
const TransferEncoding Name = "Transfer-Encoding"

// Upgrade refers to the Upgrade Header, specifying protocols for upgrade in a connection.
const Upgrade Name = "Upgrade"

// UpgradeInsecureRequests refers to the Upgrade-Insecure-Requests Header, requesting an upgrade to HTTPS.
const UpgradeInsecureRequests Name = "Upgrade-Insecure-Requests"

// UserAgent refers to the User-Agent Header, indicating the user agent making the request.
const UserAgent Name = "User-Agent"

// Vary refers to the Vary Header, specifying response headers that affect caching.
const Vary Name = "Vary"

// Via refers to the Via Header, indicating intermediate proxies or gateways used.
const Via Name = "Via"

// ViewportWidth refers to the Viewport-Width Header, indicating the viewport width of the user's device.
const ViewportWidth Name = "Viewport-Width"

// WWWAuthenticate refers to the WWW-Authenticate Header, indicating authentication methods for the resource.
const WWWAuthenticate Name = "WWW-Authenticate"

// WantDigest refers to the Want-Digest Header, specifying digest algorithms for integrity verification.
const WantDigest Name = "Want-Digest"

// Warning refers to the Warning Header, providing information about possible issues with the response.
const Warning Name = "Warning"

// Width refers to the Width Header, indicating the width of the rendering surface.
const Width Name = "Width"

// XATTDeviceId refers to the X-ATT-DeviceId Header, indicating the AT&T device ID.
const XATTDeviceId Name = "X-ATT-DeviceId"

// XContentDuration refers to the X-Content-Duration Header, indicating the duration of media resources.
const XContentDuration Name = "X-Content-Duration"

// XContentSecurityPolicy refers to the X-Content-Security-Policy Header, specifying security policies for the resource.
const XContentSecurityPolicy Name = "X-Content-Security-Policy"

// XContentTypeOptions refers to the X-Content-Type-Options Header, controlling MIME type sniffing.
const XContentTypeOptions Name = "X-Content-Type-Options"

// XCorrelationID refers to the X-Correlation-ID Header, indicating a unique correlation identifier.
const XCorrelationID Name = "X-Correlation-ID"

// XCSRFToken refers to the X-Csrf-Token Header, providing a Cross-Site Request Forgery (CSRF) token.
const XCSRFToken Name = "X-Csrf-Token"

// XDNSPrefetchControl refers to the X-DNS-Prefetch-Control Header, controlling DNS prefetching behavior.
const XDNSPrefetchControl Name = "X-DNS-Prefetch-Control"

// XForwardedFor refers to the X-Forwarded-For Header, indicating the client's original IP address in a proxy chain.
const XForwardedFor Name = "X-Forwarded-For"

// XForwardedHost refers to the X-Forwarded-Host Header, indicating the original host requested by the client in a proxy chain.
const XForwardedHost Name = "X-Forwarded-Host"

// XForwardedProto refers to the X-Forwarded-Proto Header, indicating the original protocol used by the client in a proxy chain.
const XForwardedProto Name = "X-Forwarded-Proto"

// XFrameOptions refers to the X-Frame-Options Header, controlling framing permissions for a resource.
const XFrameOptions Name = "X-Frame-Options"

// XHTTPMethodOverride refers to the X-Http-Method-Override Header, overriding the HTTP method in a request.
const XHTTPMethodOverride Name = "X-Http-Method-Override"

// XPoweredBy refers to the X-Powered-By Header, indicating the technology or framework powering the server.
const XPoweredBy Name = "X-Powered-By"

// XRedirectBy refers to the X-Redirect-By Header, indicating the mechanism by which a redirection occurred.
const XRedirectBy Name = "X-Redirect-By"

// XRequestID refers to the X-Request-ID Header, indicating a unique identifier for the request.
const XRequestID Name = "X-Request-ID"

// XRequestedWith refers to the X-Requested-With Header, indicating an XMLHttpRequest in the request.
const XRequestedWith Name = "X-Requested-With"

// XUACompatible refers to the X-UA-Compatible Header, specifying the document compatibility mode.
const XUACompatible Name = "X-UA-Compatible"

// XUIDH refers to the X-UIDH Header, indicating the Verizon Unique Identifier Header.
const XUIDH Name = "X-UIDH"

// XWapProfile refers to the X-Wap-Profile Header, indicating the device's WAP profile.
const XWapProfile Name = "X-Wap-Profile"

// XWebKitCSP refers to the X-WebKit-CSP Header, specifying content security policies for WebKit browsers.
const XWebKitCSP Name = "X-WebKit-CSP"

// XXSSProtection refers to the X-XSS-Protection Header, enabling or disabling cross-site scripting (XSS) protection.
const XXSSProtection Name = "X-XSS-Protection"
