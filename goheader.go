package goheader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AIM header field is used to indicate acceptable instance-manipulations for the request.
const AIM = "A-IM"

// Accept header field is used to specify certain media types which are acceptable for the response.
const Accept = "Accept"

// AcceptCH header field is used to indicate which client hints the server supports.
const AcceptCH = "Accept-CH"

// AcceptCHLifetime header field is used to indicate the maximum duration (in seconds) for which the user agent should store and make use of the received server configuration.
const AcceptCHLifetime = "Accept-CH-Lifetime"

// AcceptCharset header field is used to indicate which character encodings are acceptable in the response.
const AcceptCharset = "Accept-Charset"

// AcceptDatetime header field is used to indicate the date and time formats that the client supports.
const AcceptDatetime = "Accept-Datetime"

// AcceptEncoding header field is used to indicate which content codings are acceptable in the response.
const AcceptEncoding = "Accept-Encoding"

// AcceptLanguage header field is used to indicate which natural languages are preferred for the response.
const AcceptLanguage = "Accept-Language"

// AcceptPatch header field is used to indicate which patch document formats are accepted by the server.
const AcceptPatch = "Accept-Patch"

// AcceptPost header field is used to indicate which media types are accepted in the body of the request if the request method does not natively support the media type.
const AcceptPost = "Accept-Post"

// AcceptRanges header field is used to indicate which range units are supported by the server.
const AcceptRanges = "Accept-Ranges"

// AccessControlAllowCredentials header field is used to indicate whether the response can be shared when requests are made with credentials.
const AccessControlAllowCredentials = "Access-Control-Allow-Credentials"

// AccessControlAllowHeaders header field is used to specify which headers are allowed in a preflight request via the Access-Control-Request-Headers header.
const AccessControlAllowHeaders = "Access-Control-Allow-Headers"

// AccessControlAllowMethods header field is used to specify the methods that are allowed when accessing the resource in response to a preflight request.
const AccessControlAllowMethods = "Access-Control-Allow-Methods"

// AccessControlAllowOrigin header field is used to specify which origins are allowed to access the resource.
const AccessControlAllowOrigin = "Access-Control-Allow-Origin"

// AccessControlExposeHeaders header field is used to specify which headers should be exposed to the response.
const AccessControlExposeHeaders = "Access-Control-Expose-Headers"

// AccessControlMaxAge header field is used to indicate how long the results of a preflight request can be cached.
const AccessControlMaxAge = "Access-Control-Max-Age"

// AccessControlRequestHeaders header field is used to indicate which headers can be used during the actual request.
const AccessControlRequestHeaders = "Access-Control-Request-Headers"

// AccessControlRequestMethod header field is used to indicate which method can be used during the actual request.
const AccessControlRequestMethod = "Access-Control-Request-Method"

// Age header field is used to indicate the age of the response.
const Age = "Age"

// Allow header field is used to indicate the HTTP methods that are supported by the resource.
const Allow = "Allow"

// AltSvc header field is used to indicate that an alternative service is available for the given resource.
const AltSvc = "Alt-Svc"

// AltUsed header field is used to indicate which alternative service was selected and why.
const AltUsed = "Alt-Used"

// Authorization header field is used to contain credentials for authenticating the client with the server.
const Authorization = "Authorization"

// CacheControl header field is used to specify directives for caching mechanisms in both requests and responses.
const CacheControl = "Cache-Control"

// ClearSiteData header field is used to instruct the user agent to clear the browsing context's data.
const ClearSiteData = "Clear-Site-Data"

// Connection header field is used to control options for the current connection.
const Connection = "Connection"

// ContentDPR header field is used to specify the ratio of physical pixels to CSS pixels for the resource.
const ContentDPR = "Content-DPR"

// ContentDisposition header field is used to suggest a default filename for the data if the user decides to save it to a file.
const ContentDisposition = "Content-Disposition"

// ContentEncoding header field is used to specify the encoding transformations that have been applied to the resource.
const ContentEncoding = "Content-Encoding"

// ContentLanguage header field is used to describe the natural language(s) of the intended audience for the representation.
const ContentLanguage = "Content-Language"

// ContentLength header field is used to indicate the size of the response body in octets (8-bit bytes).
const ContentLength = "Content-Length"

// ContentLocation header field is used to provide a URI for the source of the representation.
const ContentLocation = "Content-Location"

// ContentMD5 header field is used as an integrity check of the entity body.
const ContentMD5 = "Content-MD5"

// ContentRange header field is used to indicate where in a full body message a partial message belongs.
const ContentRange = "Content-Range"

// ContentSecurityPolicy header field is used to define a Content Security Policy (CSP) that should be applied to the response.
const ContentSecurityPolicy = "Content-Security-Policy"

// ContentSecurityPolicyReportOnly header field is used to define a Content Security Policy (CSP) for the user agent to enforce.
const ContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"

// ContentType header field is used to indicate the media type of the resource.
const ContentType = "Content-Type"

// Cookie header field is used to send cookies from the server to the user agent.
const Cookie = "Cookie"

// CorrelationID header field is used to uniquely identify a request in a distributed system.
const CorrelationID = "Correlation-ID"

// CriticalCH header field is used to indicate which client hints are critical for the server to deliver an effective response.
const CriticalCH = "Critical-CH"

// CrossOriginEmbedderPolicy header field is used to specify which state the user agent should apply to cross-origin requests initiated by the resource.
const CrossOriginEmbedderPolicy = "Cross-Origin-Embedder-Policy"

// CrossOriginOpenerPolicy header field is used to specify which state the user agent should apply to cross-origin windows.
const CrossOriginOpenerPolicy = "Cross-Origin-Opener-Policy"

// CrossOriginResourcePolicy header field is used to specify which state the user agent should apply to a cross-origin request for the resource.
const CrossOriginResourcePolicy = "Cross-Origin-Resource-Policy"

// DNT (Do Not Track) header field is used to inform websites that the user does not want to be tracked.
const DNT = "DNT"

// DPR (Device Pixel Ratio) header field is used to indicate the ratio of physical pixels to CSS pixels for the current display device.
const DPR = "DPR"

// Date header field is used to represent the date and time at which the message was sent.
const Date = "Date"

// DeltaBase header field is used to indicate the delta encoding base resource URI.
const DeltaBase = "Delta-Base"

// DeviceMemory header field is used to indicate the approximate amount of RAM the device has available.
const DeviceMemory = "Device-Memory"

// Digest header field is used to indicate the digest algorithm and value for the resource.
const Digest = "Digest"

// Downlink header field is used to indicate the effective network bandwidth in megabits per second.
const Downlink = "Downlink"

// ECT (Effective Connection Type) header field is used to indicate the effective network type and its maximum downlink speed.
const ECT = "ECT"

// ETag header field is used to provide the current entity tag for the requested resource.
const ETag = "ETag"

// EarlyData header field is used to indicate that the request should be handled as early data.
const EarlyData = "Early-Data"

// Expect header field is used to indicate certain requirements that the server must fulfill to create an HTTP response.
const Expect = "Expect"

// ExpectCT header field is used to indicate that the server must support the Expect-CT header field.
const ExpectCT = "Expect-CT"

// Expires header field is used to specify the date and time after which the response is considered stale.
const Expires = "Expires"

// Forwarded header field is used to capture the information of the originating client and any intermediate proxies or gateways.
const Forwarded = "Forwarded"

// From header field is used to indicate an Internet email address for a human user who controls the requesting user agent.
const From = "From"

// FrontEndHTTPS header field is used to indicate that the client connected via HTTPS.
const FrontEndHTTPS = "Front-End-Https"

// HTTP2Settings header field is used to convey the HTTP/2 settings for a peer.
const HTTP2Settings = "HTTP2-Settings"

// Host header field is used to specify the domain name of the server and the TCP port number on which the server is listening.
const Host = "Host"

// IM header field is used to indicate the instance-manipulations that have been applied to the response.
const IM = "IM"

// IfMatch header field is used to make a request method conditional on the current existence or value of an entity.
const IfMatch = "If-Match"

// IfModifiedSince header field is used to make a request method conditional on the modification date of the resource.
const IfModifiedSince = "If-Modified-Since"

// IfNoneMatch header field is used to make a request method conditional on the absence or presence of a current representation of the target resource.
const IfNoneMatch = "If-None-Match"

// IfRange header field is used to make a range request that is conditional on the state of the target resource.
const IfRange = "If-Range"

// IfUnmodifiedSince header field is used to make a request method conditional on the absence or presence and modification date of a current representation of the target resource.
const IfUnmodifiedSince = "If-Unmodified-Since"

// KeepAlive header field is used to allow the sender to hint about how the connection might be used.
const KeepAlive = "Keep-Alive"

// LargeAllocation header field is used to indicate that the response is a large allocation of resources.
const LargeAllocation = "Large-Allocation"

// LastModified header field is used to indicate the date and time at which the origin server believes the resource was last modified.
const LastModified = "Last-Modified"

// Link header field is used to convey one or more links in the HTTP header.
const Link = "Link"

// Location header field is used in the responses from an HTTP server to redirect the recipient to a different URL.
const Location = "Location"

// MaxForwards header field is used to limit the number of times that the request is forwarded by proxies or gateways.
const MaxForwards = "Max-Forwards"

// NEL (Network Error Logging) header field is used to send reports of network errors from the document to a receiver.
const NEL = "NEL"

// Origin header field is used to indicate the origin of the resource.
const Origin = "Origin"

// P3P (Platform for Privacy Preferences) header field is used to indicate the privacy policy of the server.
const P3P = "P3P"

// PermissionsPolicy header field is used to enable an API to allow or deny the use of features that may allow for access to device capabilities or user data.
const PermissionsPolicy = "Permissions-Policy"

// Pragma header field is used to include implementation-specific directives that might apply to any recipient along the request/response chain.
const Pragma = "Pragma"

// Prefer header field is used to indicate the request's preferences regarding specific behaviors, such as return representations or server processing.
const Prefer = "Prefer"

// PreferenceApplied header field is used to indicate the request's preferences that have been applied by the server.
const PreferenceApplied = "Preference-Applied"

// Priority header field is used to allow clients and servers to signal priority hints for requests and responses.
const Priority = "Priority"

// ProxyAuthenticate header field is used to challenge the authorization of the client before a proxy can be set up.
const ProxyAuthenticate = "Proxy-Authenticate"

// ProxyAuthenticationInfo header field is used to provide information such as next tokens for Digest authentication or additional parameters.
const ProxyAuthenticationInfo = "ProxyAuthenticationInfo"

// ProxyAuthorization header field is used to provide authentication information for proxies that require authentication.
const ProxyAuthorization = "Proxy-Authorization"

// ProxyConnection header field is used to specify options for the connection.
const ProxyConnection = "Proxy-Connection"

// PublicKeyPins header field is used to associate a specific cryptographic public key with a certain web server.
const PublicKeyPins = "Public-Key-Pins"

// PublicKeyPinsReportOnly header field is used to associate a specific cryptographic public key with a certain web server.
const PublicKeyPinsReportOnly = "Public-Key-PinsReportOnly"

// RTT (Round-Trip Time) header field is used to indicate the round-trip time of the connection.
const RTT = "RTT"

// Range header field is used to request only part of an entity in the response.
const Range = "Range"

// Referer header field specifies the address of the previous web page from which a link to the currently requested page was followed.
const Referer = "Referer"

// ReferrerPolicy header field controls how much referrer information (sent via the Referer header) should be included with requests.
const ReferrerPolicy = "Referrer-Policy"

// Refresh header field is used to specify a delay before the browser should reload the current resource.
const Refresh = "Refresh"

// ReplayNonce header field is used to provide a cryptographic nonce that clients must use in subsequent signed requests to prevent replay attacks.
const ReplayNonce = "Replay-Nonce"

// ReportTo header field is used to specify a URI to which the user agent sends reports about various issues.
const ReportTo = "Report-To"

// ReportingEndpoints header field is used to define endpoints where reports (like CSP, network errors, etc.) should be sent.
const ReportingEndpoints = "Reporting-Endpoints"

// RetryAfter header field indicates how long the user agent should wait before making a follow-up request.
const RetryAfter = "Retry-After"

// SaveData header field is used to indicate that the user's data saver is enabled.
const SaveData = "Save-Data"

// SecCHPrefersColorScheme header field is used to indicate the user's preference for a light or dark color scheme.
const SecCHPrefersColorScheme = "Sec-CH-Prefers-Color-Scheme"

// SecCHPrefersReducedMotion header field is used to indicate the user's preference for reduced motion.
const SecCHPrefersReducedMotion = "Sec-CH-Prefers-Reduced-Motion"

// SecCHPrefersReducedTransparency header field is used to indicate the user's preference for reduced transparency.
const SecCHPrefersReducedTransparency = "Sec-CH-Prefers-Reduced-Transparency"

// SecCHUA header field is used to indicate the user agent string.
const SecCHUA = "Sec-CH-UA"

// SecCHUAArch header field is used to indicate the architecture of the user agent.
const SecCHUAArch = "Sec-CH-UA-Arch"

// SecCHUABitness header field is used to indicate the bitness of the user agent.
const SecCHUABitness = "Sec-CH-UA-Bitness"

// SecCHUAFullVersion header field is used to indicate the full version of the user agent.
const SecCHUAFullVersion = "Sec-CH-UA-Full-Version"

// SecCHUAFullVersionList header field is used to indicate a list of full versions of the user agent.
const SecCHUAFullVersionList = "Sec-CH-UA-Full-Version-List"

// SecCHUAMobile header field is used to indicate whether the user agent is a mobile device.
const SecCHUAMobile = "Sec-CH-UA-Mobile"

// SecCHUAModel header field is used to indicate the model of the user agent device.
const SecCHUAModel = "Sec-CH-UA-Model"

// SecCHUAPlatform header field is used to indicate the platform of the user agent.
const SecCHUAPlatform = "Sec-CH-UA-Platform"

// SecCHUAPlatformVersion header field is used to indicate the version of the platform of the user agent.
const SecCHUAPlatformVersion = "Sec-CH-UA-Platform-Version"

// SecCHUAWoW64 header field is ued to indicate whether the user agent is a 32-bit app running on a 64-bit Windows OS (WoW64 = Windows 32-bit on Windows 64-bit).
const SecCHUAWoW64 = "Sec-CH-UA-WoW64"

// SecFetchDest header field is used to indicate the destination of the fetch request.
const SecFetchDest = "Sec-Fetch-Dest"

// SecFetchMode header field is used to indicate the mode of the fetch request.
const SecFetchMode = "Sec-Fetch-Mode"

// SecFetchSite header field is used to indicate the site of the fetch request.
const SecFetchSite = "Sec-Fetch-Site"

// SecFetchUser header field is used to indicate the user of the fetch request.
const SecFetchUser = "Sec-Fetch-User"

// SecGPC header field is used to indicate the privacy preferences of the user.
const SecGPC = "Sec-GPC"

// SecPurpose header field is used to indicate the purpose of the request.
const SecPurpose = "Sec-Purpose"

// SecWebSocketAccept header field is used in the handshake to indicate the accept value.
const SecWebSocketAccept = "Sec-WebSocket-Accept"

// SecWebSocketExtensions header field is used by the client to request optional protocol-level extensions, and the server responds with the accepted extensions.
const SecWebSocketExtensions = "Sec-WebSocket-Extensions"

// SecWebSocketKey header field is used to generate the Sec-WebSocket-Accept header for validation.
const SecWebSocketKey = "Sec-WebSocket-Key"

// SecWebSocketProtocol header field is used by the client to specify one or more subprotocols it wants to use
const SecWebSocketProtocol = "Sec-WebSocket-Protocol"

// SecWebSocketVersion header field is by the client to specify the WebSocket protocol version it supports.
const SecWebSocketVersion = "Sec-WebSocket-Version"

// Server header field is used to provide information about the software used by the origin server.
const Server = "Server"

// ServerTiming header field is used to communicate one or more metrics and descriptions for the given request-response cycle.
const ServerTiming = "Server-Timing"

// ServiceWorkerNavigationPreload header field is used to indicate the navigation preload state of the service worker.
const ServiceWorkerNavigationPreload = "Service-Worker-Navigation-Preload"

// SetCookie header field is used to send cookies from the server to the user agent.
const SetCookie = "Set-Cookie"

// SourceMap header field is used to indicate the source map for the requested resource.
const SourceMap = "SourceMap"

// Status header field is used to indicate the status of the response.
const Status = "Status"

// StrictTransportSecurity header field is used to enable the browser to enforce the use of HTTPS.
const StrictTransportSecurity = "Strict-Transport-Security"

// SupportsLoadingMode header field is used to opt-in to using various higher-risk loading modes.
const SupportsLoadingMode = "Supports-Loading-Mode"

// TE header field is used to indicate the transfer codings that are acceptable to the client.
const TE = "TE"

// TimingAllowOrigin header field is used to specify origins that are allowed to see values of attributes retrieved via features of the Resource Timing API.
const TimingAllowOrigin = "Timing-Allow-Origin"

// TK header field is used to communicate the tracking status requested by the user.
const TK = "Tk"

// Trailer header field is used to indicate that the given set of header fields is present in the trailer of a message encoded with chunked transfer-coding.
const Trailer = "Trailer"

// TransferEncoding header field is used to specify the transfer coding of the response.
const TransferEncoding = "Transfer-Encoding"

// Upgrade header field is used to specify additional communication options for the client.
const Upgrade = "Upgrade"

// UpgradeInsecureRequests header field is used to instruct user agents to treat all of a site's insecure URLs (HTTP) as though they have been replaced with secure URLs (HTTPS).
const UpgradeInsecureRequests = "Upgrade-Insecure-Requests"

// Urgency header field is used with HTTP resource prioritization (e.g., HTTP/3 or priority hints) to indicate the relative priority of a resource.
const Urgency = "Urgency"

// UserAgent header field is used to provide information about the user agent (client) making the request.
const UserAgent = "User-Agent"

// VariantKey field is used to describe the specific request parameters used when selecting a variant of a resource.
const VariantKey = "Variant-Key"

// Vary header field is used to indicate the set of request-header fields that fully determines, while the response is fresh, whether a cache is permitted to use the response to reply to a subsequent request without revalidation.
const Vary = "Vary"

// Via header field is used to indicate the network path taken by the request message.
const Via = "Via"

// ViewportWidth header field is used to specify the layout width of the viewport.
const ViewportWidth = "Viewport-Width"

// WWWAuthenticate header field is used to indicate the authentication method(s) and realm(s) acceptable to the recipient.
const WWWAuthenticate = "WWW-Authenticate"

// WantDigest header field is used to indicate that the client supports header field digest values and which algorithm the client prefers.
const WantDigest = "Want-Digest"

// Warning header field is used to carry additional information about the status or transformation of a message that might not be reflected in the message.
const Warning = "Warning"

// Width header field is used to specify the intended display width of the resource in CSS pixels.
const Width = "Width"

// XATTDeviceID header field is used to uniquely identify a device in the network.
const XATTDeviceID = "X-ATT-DeviceId"

// XContentDuration header field is used to specify the duration of the resource's content.
const XContentDuration = "X-Content-Duration"

// XContentSecurityPolicy header field is used to define a Content Security Policy (CSP) that should be applied to the response.
const XContentSecurityPolicy = "X-Content-Security-Policy"

// XContentTypeOptions header field is used to prevent browsers from interpreting files as a different MIME type.
const XContentTypeOptions = "X-Content-Type-Options"

// XCorrelationID header field is used to uniquely identify a request in a distributed system.
const XCorrelationID = "X-Correlation-ID"

// XCSRFToken header field is used to provide anti-CSRF (Cross-Site Request Forgery) tokens.
const XCSRFToken = "X-Csrf-Token"

// XDNSPrefetchControl header field is used to control DNS prefetching.
const XDNSPrefetchControl = "X-DNS-Prefetch-Control"

// XForwardedFor header field is used to identify the originating IP address of a client connecting to a web server through an HTTP proxy or a load balancer.
const XForwardedFor = "X-Forwarded-For"

// XForwardedHost header field is used to identify the original host requested by the client in the Host HTTP request header.
const XForwardedHost = "X-Forwarded-Host"

// XForwardedProto header field is used to indicate the original protocol (HTTP or HTTPS) that a client used to connect to your proxy or load balancer.
const XForwardedProto = "X-Forwarded-Proto"

// XFrameOptions header field is used to control whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed>, <object>, or <applet>.
const XFrameOptions = "X-Frame-Options"

// XHTTPMethodOverride header field is used to override the method specified in the request line with the method given in the header field.
const XHTTPMethodOverride = "X-HTTP-Method-Override"

// XPermittedCrossDomainPolicies header field is used mainly by Adobe products (Flash, PDF readers, etc.).
const XPermittedCrossDomainPolicies = "X-Permitted-Cross-Domain-Policies"

// XPoweredBy header field is used to indicate the technology (e.g., server framework, language) powering a website.
const XPoweredBy = "X-Powered-By"

// XRedirectBy header field is used to indicate the entity responsible for the redirection in the response.
const XRedirectBy = "X-Redirect-By"

// XRequestID header field is used to uniquely identify a request.
const XRequestID = "X-Request-ID"

// XRequestedWith header field is used to indicate the type of request (e.g., XMLHTTPRequest) made by the user agent.
const XRequestedWith = "X-Requested-With"

// XRobotsTag header field is used to control how search engines index a page.
const XRobotsTag = "X-Robots-Tag"

// XUACompatible header field is used to control the version of Internet Explorer (IE) that a web page should be rendered as.
const XUACompatible = "X-UA-Compatible"

// XUIDH header field is used to enable a service provider to uniquely identify a subscriber.
const XUIDH = "X-UIDH"

// XWapProfile header field is used to provide a link to a WAP (Wireless Application Protocol) profile document.
const XWapProfile = "X-Wap-Profile"

// XWebKitCSP header field is used to specify a Content Security Policy (CSP) for a web page.
const XWebKitCSP = "X-WebKit-CSP"

// XXSSProtection header field is used to enable or disable the Cross-site Scripting (XSS) filter in the user agent.
const XXSSProtection = "X-XSS-Protection"

// Header represents an HTTP header.
type Header struct {
	Experimental bool     // Experimental indicates whether the header is an experimental HTTP header.
	Name         string   // Name represents the name of the header.
	Request      bool     // Request indicates whether the header is applicable for HTTP requests.
	Response     bool     // Response indicates whether the header is applicable for HTTP responses.
	Standard     bool     // Standard indicates whether the header is a standard HTTP header.
	Values       []string // Values contains the associated values of the header.
}

// NewHeaders creates a new http.Header instance from a collection of Header structs.
// It takes a variadic number of *Header pointers as input, where each Header contains
// information about an HTTP header including its name and associated values. The function
// creates an http.Header instance and populates it with the provided headers' names as keys
// and their associated values as slices of strings.
//
//	// Create a new Header instance.
//	header1 := goheader.Header{
//	  Name: "Content-Type",
//	  Values: []string{"application/json"}}
//
//	// Create another Header instance.
//	header2 := goheader.Header{
//	  Name: "Authorization",
//	  Values: []string{"Bearer Token"}}
//
//	headers := goheader.NewHeaders(header1, header2)
//	fmt.Println(headers) // Output: map[Content-Type:[application/json] Authorization:[Bearer Token]]
func NewHeaders(headers ...*Header) http.Header {
	HTTPHeader := http.Header{}
	for _, header := range headers {
		HTTPHeader[header.Name] = header.Values
	}
	return HTTPHeader
}

// AIMValue represents one A-IM token with optional quality and extensions.
type AIMValue struct {
	Token      string   // The instance manipulation name (e.g., "gzip", "vcdiff")
	Quality    float64  // Optional quality factor (0.0 - 1.0). Ignored if <= 0.
	Extensions []string // Optional extensions, e.g., custom parameters.
}

// String renders a single A-IM value.
func (v AIMValue) String() string {
	result := v.Token
	if v.Quality > 0 {
		result += fmt.Sprintf(";q=%.1f", v.Quality)
	}
	if len(v.Extensions) > 0 {
		result += ";" + strings.Join(v.Extensions, ";")
	}
	return result
}

// AIMConfig defines the configuration for the A-IM header.
type AIMConfig struct {
	Values []AIMValue
}

// String renders the full A-IM header value from the config.
func (cfg AIMConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAIMHeader creates a new A-IM header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/A-IM
//
// Example usage:
//
//	cfg := goheader.AIMConfig{
//	    Values: []goheader.AIMValue{
//	        {Token: "gzip", Quality: 1.0},
//	        {Token: "vcdiff", Quality: 0.5, Extensions: []string{"custom=1"}},
//	    },
//	}
//	header := goheader.NewAIMHeader(cfg)
//	fmt.Println(header.Name)   // A-IM
//	fmt.Println(header.Values) // ["gzip;q=1.0, vcdiff;q=0.5;custom=1"]
func NewAIMHeader(cfg AIMConfig) Header {
	return Header{
		Experimental: false,
		Name:         AIM,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptValue represents one media type in the Accept header.
type AcceptValue struct {
	MediaType string            // e.g., "application/json"
	Quality   float64           // Optional quality factor (0.0 - 1.0). Ignored if <= 0.
	Params    map[string]string // Optional parameters, e.g., charset=utf-8
}

// String renders a single Accept value.
func (v AcceptValue) String() string {
	if v.MediaType == "" {
		v.MediaType = "*/*" // Default to wildcard if none provided
	}

	result := v.MediaType

	if len(v.Params) > 0 {
		var params []string
		for k, val := range v.Params {
			params = append(params, fmt.Sprintf("%s=%s", k, val))
		}
		result += ";" + strings.Join(params, ";")
	}

	if v.Quality > 0 && v.Quality < 1 {
		result += fmt.Sprintf(";q=%.1f", v.Quality)
	}

	return result
}

// AcceptConfig defines the configuration for the Accept header.
type AcceptConfig struct {
	Values []AcceptValue
}

// String renders the full Accept header value from the config.
func (cfg AcceptConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptHeader creates a new Accept header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept
//
// Example usage:
//
//	cfg := goheader.AcceptConfig{
//	    Values: []goheader.AcceptValue{
//	        {MediaType: "application/json", Quality: 1.0},
//	        {MediaType: "text/html", Quality: 0.8, Params: map[string]string{"charset": "utf-8"}},
//	    },
//	}
//	header := goheader.NewAcceptHeader(cfg)
//	fmt.Println(header.Name)   // Accept
//	fmt.Println(header.Values) // ["application/json;q=1.0, text/html;charset=utf-8;q=0.8"]
func NewAcceptHeader(cfg AcceptConfig) Header {
	return Header{
		Experimental: false,
		Name:         Accept,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptCHValue represents one token in the Accept-CH header.
type AcceptCHValue struct {
	Token      string   // The client hint token, e.g., "DPR", "Width"
	Extensions []string // Optional future-proof extensions, rarely used
}

// String renders a single Accept-CH value.
func (v AcceptCHValue) String() string {
	if len(v.Extensions) > 0 {
		return v.Token + ";" + strings.Join(v.Extensions, ";")
	}
	return v.Token
}

// AcceptCHConfig defines the configuration for the Accept-CH header.
type AcceptCHConfig struct {
	Values []AcceptCHValue
}

// String renders the full Accept-CH header value from the config.
func (cfg AcceptCHConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptCHHeader creates a new Accept-CH header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-CH
//
// Example usage:
//
//	cfg := goheader.AcceptCHConfig{
//	    Values: []goheader.AcceptCHValue{
//	        {Token: "DPR"},
//	        {Token: "Viewport-Width"},
//	    },
//	}
//	header := goheader.NewAcceptCHHeader(cfg)
//	fmt.Println(header.Name)   // Accept-CH
//	fmt.Println(header.Values) // ["DPR, Viewport-Width"]
func NewAcceptCHHeader(cfg AcceptCHConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptCH,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptCHLifetimeConfig defines the configuration for the Accept-CH-Lifetime header.
type AcceptCHLifetimeConfig struct {
	Lifetime int // Lifetime in seconds
}

// String renders the Accept-CH-Lifetime header value.
func (cfg AcceptCHLifetimeConfig) String() string {
	return fmt.Sprintf("%d", cfg.Lifetime)
}

// NewAcceptCHLifetimeHeader creates a new Accept-CH-Lifetime header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-CH-Lifetime
//
// Example usage:
//
//	cfg := goheader.AcceptCHLifetimeConfig{Lifetime: 86400}
//	header := goheader.NewAcceptCHLifetimeHeader(cfg)
//	fmt.Println(header.Name)   // Accept-CH-Lifetime
//	fmt.Println(header.Values) // ["86400"]
func NewAcceptCHLifetimeHeader(cfg AcceptCHLifetimeConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptCHLifetime,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptCharsetValue represents one charset entry in the Accept-Charset header.
type AcceptCharsetValue struct {
	Charset string  // e.g., "utf-8"
	Quality float64 // Optional quality factor (0.0 - 1.0). Ignored if <= 0.
}

// String renders a single Accept-Charset value.
func (v AcceptCharsetValue) String() string {
	if v.Charset == "" {
		v.Charset = "*" // Default to wildcard if none provided
	}

	result := v.Charset
	if v.Quality > 0 && v.Quality < 1 {
		result += fmt.Sprintf(";q=%.1f", v.Quality)
	}
	return result
}

// AcceptCharsetConfig defines the configuration for the Accept-Charset header.
type AcceptCharsetConfig struct {
	Values []AcceptCharsetValue
}

// String renders the full Accept-Charset header value from the config.
func (cfg AcceptCharsetConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptCharsetHeader creates a new Accept-Charset header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Charset
//
// Example usage:
//
//	cfg := goheader.AcceptCharsetConfig{
//	    Values: []goheader.AcceptCharsetValue{
//	        {Charset: "utf-8", Quality: 1.0},
//	        {Charset: "iso-8859-1", Quality: 0.5},
//	    },
//	}
//	header := goheader.NewAcceptCharsetHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Charset
//	fmt.Println(header.Values) // ["utf-8;q=1.0, iso-8859-1;q=0.5"]
func NewAcceptCharsetHeader(cfg AcceptCharsetConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptCharset,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptDatetimeConfig defines the configuration for the Accept-Datetime header.
type AcceptDatetimeConfig struct {
	Datetime time.Time
}

// String renders the Accept-Datetime header value as an RFC 7231 HTTP-date.
func (cfg AcceptDatetimeConfig) String() string {
	// RFC1123 is the correct format for HTTP-date (RFC 7231 section 7.1.1.1)
	return cfg.Datetime.UTC().Format(time.RFC1123)
}

// NewAcceptDatetimeHeader creates a new Accept-Datetime header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Datetime
//
// Example usage:
//
//	cfg := goheader.AcceptDatetimeConfig{
//	    Datetime: time.Date(2023, 5, 1, 12, 30, 0, 0, time.UTC),
//	}
//	header := goheader.NewAcceptDatetimeHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Datetime
//	fmt.Println(header.Values) // ["Mon, 01 May 2023 12:30:00 GMT"]
func NewAcceptDatetimeHeader(cfg AcceptDatetimeConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptDatetime,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptEncodingValue represents one entry in the Accept-Encoding header.
type AcceptEncodingValue struct {
	Encoding string  // e.g., "gzip", "br", "deflate"
	Quality  float64 // Optional quality factor (0.0 - 1.0). Ignored if <= 0.
}

// String renders a single Accept-Encoding value.
func (v AcceptEncodingValue) String() string {
	if v.Encoding == "" {
		v.Encoding = "identity" // Default per RFC 7231 section 5.3.4
	}

	result := v.Encoding
	if v.Quality > 0 && v.Quality < 1 {
		result += fmt.Sprintf(";q=%.1f", v.Quality)
	}
	return result
}

// AcceptEncodingConfig defines the configuration for the Accept-Encoding header.
type AcceptEncodingConfig struct {
	Values []AcceptEncodingValue
}

// String renders the full Accept-Encoding header value from the config.
func (cfg AcceptEncodingConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptEncodingHeader creates a new Accept-Encoding header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
//
// Example usage:
//
//	cfg := goheader.AcceptEncodingConfig{
//	    Values: []goheader.AcceptEncodingValue{
//	        {Encoding: "gzip", Quality: 1.0},
//	        {Encoding: "br", Quality: 0.8},
//	    },
//	}
//	header := goheader.NewAcceptEncodingHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Encoding
//	fmt.Println(header.Values) // ["gzip;q=1.0, br;q=0.8"]
func NewAcceptEncodingHeader(cfg AcceptEncodingConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptEncoding,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptLanguageValue represents one language entry in the Accept-Language header.
type AcceptLanguageValue struct {
	Language string  // e.g., "en-US", "fr", "de"
	Quality  float64 // Optional quality factor (0.0 - 1.0). Ignored if <= 0.
}

// String renders a single Accept-Language value.
func (v AcceptLanguageValue) String() string {
	if v.Language == "" {
		v.Language = "*" // Default wildcard if none provided
	}

	result := v.Language
	if v.Quality > 0 && v.Quality < 1 {
		result += fmt.Sprintf(";q=%.1f", v.Quality)
	}
	return result
}

// AcceptLanguageConfig defines the configuration for the Accept-Language header.
type AcceptLanguageConfig struct {
	Values []AcceptLanguageValue
}

// String renders the full Accept-Language header value from the config.
func (cfg AcceptLanguageConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptLanguageHeader creates a new Accept-Language header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
//
// Example usage:
//
//	cfg := goheader.AcceptLanguageConfig{
//	    Values: []goheader.AcceptLanguageValue{
//	        {Language: "en-US", Quality: 1.0},
//	        {Language: "fr", Quality: 0.8},
//	    },
//	}
//	header := goheader.NewAcceptLanguageHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Language
//	fmt.Println(header.Values) // ["en-US;q=1.0, fr;q=0.8"]
func NewAcceptLanguageHeader(cfg AcceptLanguageConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptLanguage,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptPatchValue represents one entry in the Accept-Patch header.
type AcceptPatchValue struct {
	MediaType string            // e.g., "application/json-patch+json"
	Params    map[string]string // Optional parameters like charset=utf-8
}

// String renders a single Accept-Patch value.
func (v AcceptPatchValue) String() string {
	result := v.MediaType
	if len(v.Params) > 0 {
		var params []string
		for k, val := range v.Params {
			params = append(params, fmt.Sprintf("%s=%s", k, val))
		}
		result += ";" + strings.Join(params, ";")
	}
	return result
}

// AcceptPatchConfig defines the configuration for the Accept-Patch header.
type AcceptPatchConfig struct {
	Values []AcceptPatchValue
}

// String renders the full Accept-Patch header value from the config.
func (cfg AcceptPatchConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptPatchHeader creates a new Accept-Patch header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Patch
//
// Example usage:
//
//	cfg := goheader.AcceptPatchConfig{
//	    Values: []goheader.AcceptPatchValue{
//	        {MediaType: "application/json-patch+json"},
//	        {MediaType: "application/merge-patch+json"},
//	    },
//	}
//	header := goheader.NewAcceptPatchHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Patch
//	fmt.Println(header.Values) // ["application/json-patch+json, application/merge-patch+json"]
func NewAcceptPatchHeader(cfg AcceptPatchConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptPatch,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptPostValue represents one entry in the Accept-Post header.
type AcceptPostValue struct {
	MediaType string            // e.g., "application/json"
	Params    map[string]string // Optional parameters like charset=utf-8
}

// String renders a single Accept-Post value.
func (v AcceptPostValue) String() string {
	result := v.MediaType
	if len(v.Params) > 0 {
		var params []string
		for k, val := range v.Params {
			params = append(params, fmt.Sprintf("%s=%s", k, val))
		}
		result += ";" + strings.Join(params, ";")
	}
	return result
}

// AcceptPostConfig defines the configuration for the Accept-Post header.
type AcceptPostConfig struct {
	Values []AcceptPostValue
}

// String renders the full Accept-Post header value from the config.
func (cfg AcceptPostConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptPostHeader creates a new Accept-Post header from the config.
// More information: https://www.w3.org/TR/ldp/#header-accept-post
//
// Example usage:
//
//	cfg := goheader.AcceptPostConfig{
//	    Values: []goheader.AcceptPostValue{
//	        {MediaType: "application/json"},
//	        {MediaType: "application/ld+json"},
//	    },
//	}
//	header := goheader.NewAcceptPostHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Post
//	fmt.Println(header.Values) // ["application/json, application/ld+json"]
func NewAcceptPostHeader(cfg AcceptPostConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptPost,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AcceptRangesValue represents one entry in the Accept-Ranges header.
type AcceptRangesValue struct {
	Unit string // e.g., "bytes", "none"
}

// String renders a single Accept-Ranges value.
func (v AcceptRangesValue) String() string {
	if v.Unit == "" {
		return "none" // Default to none if unspecified
	}
	return v.Unit
}

// AcceptRangesConfig defines the configuration for the Accept-Ranges header.
type AcceptRangesConfig struct {
	Values []AcceptRangesValue
}

// String renders the full Accept-Ranges header value from the config.
func (cfg AcceptRangesConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAcceptRangesHeader creates a new Accept-Ranges header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Ranges
//
// Example usage:
//
//	cfg := goheader.AcceptRangesConfig{
//	    Values: []goheader.AcceptRangesValue{
//	        {Unit: "bytes"},
//	    },
//	}
//	header := goheader.NewAcceptRangesHeader(cfg)
//	fmt.Println(header.Name)   // Accept-Ranges
//	fmt.Println(header.Values) // ["bytes"]
func NewAcceptRangesHeader(cfg AcceptRangesConfig) Header {
	return Header{
		Experimental: false,
		Name:         AcceptRanges,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlAllowCredentialsConfig defines the configuration for the Access-Control-Allow-Credentials header.
type AccessControlAllowCredentialsConfig struct {
	AllowCredentials bool // true = "true", false = "false"
}

// String renders the Access-Control-Allow-Credentials header value.
func (cfg AccessControlAllowCredentialsConfig) String() string {
	if cfg.AllowCredentials {
		return "true"
	}
	return "false"
}

// NewAccessControlAllowCredentialsHeader creates a new Access-Control-Allow-Credentials header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
//
// Example usage:
//
//	cfg := goheader.AccessControlAllowCredentialsConfig{AllowCredentials: true}
//	header := goheader.NewAccessControlAllowCredentialsHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Allow-Credentials
//	fmt.Println(header.Values) // ["true"]
func NewAccessControlAllowCredentialsHeader(cfg AccessControlAllowCredentialsConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlAllowCredentials,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlAllowHeadersValue represents one entry in the Access-Control-Allow-Headers header.
type AccessControlAllowHeadersValue struct {
	Header string // e.g., "Content-Type", "Authorization"
}

// String renders a single Access-Control-Allow-Headers value.
func (v AccessControlAllowHeadersValue) String() string {
	if v.Header == "" {
		return "*" // Default to wildcard if none provided
	}
	return v.Header
}

// AccessControlAllowHeadersConfig defines the configuration for the Access-Control-Allow-Headers header.
type AccessControlAllowHeadersConfig struct {
	Values []AccessControlAllowHeadersValue
}

// String renders the full Access-Control-Allow-Headers header value from the config.
func (cfg AccessControlAllowHeadersConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAccessControlAllowHeadersHeader creates a new Access-Control-Allow-Headers header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
//
// Example usage:
//
//	cfg := goheader.AccessControlAllowHeadersConfig{
//	    Values: []goheader.AccessControlAllowHeadersValue{
//	        {Header: "Content-Type"},
//	        {Header: "Authorization"},
//	    },
//	}
//	header := goheader.NewAccessControlAllowHeadersHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Allow-Headers
//	fmt.Println(header.Values) // ["Content-Type, Authorization"]
func NewAccessControlAllowHeadersHeader(cfg AccessControlAllowHeadersConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlAllowHeaders,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlAllowMethodsValue represents one method in the Access-Control-Allow-Methods header.
type AccessControlAllowMethodsValue struct {
	Method string // e.g., "GET", "POST", "PUT", "DELETE"
}

// String renders a single Access-Control-Allow-Methods value.
func (v AccessControlAllowMethodsValue) String() string {
	if v.Method == "" {
		return "*" // Default to wildcard if none provided
	}
	return v.Method
}

// AccessControlAllowMethodsConfig defines the configuration for the Access-Control-Allow-Methods header.
type AccessControlAllowMethodsConfig struct {
	Values []AccessControlAllowMethodsValue
}

// String renders the full Access-Control-Allow-Methods header value from the config.
func (cfg AccessControlAllowMethodsConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAccessControlAllowMethodsHeader creates a new Access-Control-Allow-Methods header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
//
// Example usage:
//
//	cfg := goheader.AccessControlAllowMethodsConfig{
//	    Values: []goheader.AccessControlAllowMethodsValue{
//	        {Method: "GET"},
//	        {Method: "POST"},
//	        {Method: "OPTIONS"},
//	    },
//	}
//	header := goheader.NewAccessControlAllowMethodsHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Allow-Methods
//	fmt.Println(header.Values) // ["GET, POST, OPTIONS"]
func NewAccessControlAllowMethodsHeader(cfg AccessControlAllowMethodsConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlAllowMethods,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlAllowOriginConfig defines the configuration for the Access-Control-Allow-Origin header.
type AccessControlAllowOriginConfig struct {
	Origin string // e.g., "https://example.com" or "*"
}

// String renders the Access-Control-Allow-Origin header value.
func (cfg AccessControlAllowOriginConfig) String() string {
	if cfg.Origin == "" {
		return "*" // Default to wildcard if none provided
	}
	return cfg.Origin
}

// NewAccessControlAllowOriginHeader creates a new Access-Control-Allow-Origin header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
//
// Example usage:
//
//	cfg := goheader.AccessControlAllowOriginConfig{Origin: "https://example.com"}
//	header := goheader.NewAccessControlAllowOriginHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Allow-Origin
//	fmt.Println(header.Values) // ["https://example.com"]
func NewAccessControlAllowOriginHeader(cfg AccessControlAllowOriginConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlAllowOrigin,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlExposeHeadersValue represents one entry in the Access-Control-Expose-Headers header.
type AccessControlExposeHeadersValue struct {
	Header string // e.g., "Content-Length", "X-Custom-Header"
}

// String renders a single Access-Control-Expose-Headers value.
func (v AccessControlExposeHeadersValue) String() string {
	if v.Header == "" {
		return "*" // Default to wildcard if none provided
	}
	return v.Header
}

// AccessControlExposeHeadersConfig defines the configuration for the Access-Control-Expose-Headers header.
type AccessControlExposeHeadersConfig struct {
	Values []AccessControlExposeHeadersValue
}

// String renders the full Access-Control-Expose-Headers header value from the config.
func (cfg AccessControlExposeHeadersConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAccessControlExposeHeadersHeader creates a new Access-Control-Expose-Headers header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
//
// Example usage:
//
//	cfg := goheader.AccessControlExposeHeadersConfig{
//	    Values: []goheader.AccessControlExposeHeadersValue{
//	        {Header: "Content-Length"},
//	        {Header: "X-Custom-Header"},
//	    },
//	}
//	header := goheader.NewAccessControlExposeHeadersHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Expose-Headers
//	fmt.Println(header.Values) // ["Content-Length, X-Custom-Header"]
func NewAccessControlExposeHeadersHeader(cfg AccessControlExposeHeadersConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlExposeHeaders,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlMaxAgeConfig defines the configuration for the Access-Control-Max-Age header.
type AccessControlMaxAgeConfig struct {
	Seconds int // Cache duration in seconds. -1 disables caching.
}

// String renders the Access-Control-Max-Age header value.
func (cfg AccessControlMaxAgeConfig) String() string {
	return fmt.Sprintf("%d", cfg.Seconds)
}

// NewAccessControlMaxAgeHeader creates a new Access-Control-Max-Age header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
//
// Example usage:
//
//	cfg := goheader.AccessControlMaxAgeConfig{Seconds: 600}
//	header := goheader.NewAccessControlMaxAgeHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Max-Age
//	fmt.Println(header.Values) // ["600"]
func NewAccessControlMaxAgeHeader(cfg AccessControlMaxAgeConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlMaxAge,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlRequestHeadersValue represents one header in the Access-Control-Request-Headers header.
type AccessControlRequestHeadersValue struct {
	Header string // e.g., "Content-Type", "Authorization"
}

// String renders a single Access-Control-Request-Headers value.
func (v AccessControlRequestHeadersValue) String() string {
	return v.Header
}

// AccessControlRequestHeadersConfig defines the configuration for the Access-Control-Request-Headers header.
type AccessControlRequestHeadersConfig struct {
	Values []AccessControlRequestHeadersValue
}

// String renders the full Access-Control-Request-Headers header value from the config.
func (cfg AccessControlRequestHeadersConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAccessControlRequestHeadersHeader creates a new Access-Control-Request-Headers header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Headers
//
// Example usage:
//
//	cfg := goheader.AccessControlRequestHeadersConfig{
//	    Values: []goheader.AccessControlRequestHeadersValue{
//	        {Header: "Content-Type"},
//	        {Header: "Authorization"},
//	    },
//	}
//	header := goheader.NewAccessControlRequestHeadersHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Request-Headers
//	fmt.Println(header.Values) // ["Content-Type, Authorization"]
func NewAccessControlRequestHeadersHeader(cfg AccessControlRequestHeadersConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlRequestHeaders,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AccessControlRequestMethodConfig defines the configuration for the Access-Control-Request-Method header.
type AccessControlRequestMethodConfig struct {
	Method string // e.g., "POST", "PUT", "DELETE"
}

// String renders the Access-Control-Request-Method header value.
func (cfg AccessControlRequestMethodConfig) String() string {
	return cfg.Method
}

// NewAccessControlRequestMethodHeader creates a new Access-Control-Request-Method header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Method
//
// Example usage:
//
//	cfg := goheader.AccessControlRequestMethodConfig{Method: "POST"}
//	header := goheader.NewAccessControlRequestMethodHeader(cfg)
//	fmt.Println(header.Name)   // Access-Control-Request-Method
//	fmt.Println(header.Values) // ["POST"]
func NewAccessControlRequestMethodHeader(cfg AccessControlRequestMethodConfig) Header {
	return Header{
		Experimental: false,
		Name:         AccessControlRequestMethod,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AgeConfig defines the configuration for the Age header.
type AgeConfig struct {
	Seconds int // Age in seconds since the resource was fetched from the origin.
}

// String renders the Age header value.
func (cfg AgeConfig) String() string {
	return fmt.Sprintf("%d", cfg.Seconds)
}

// NewAgeHeader creates a new Age header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age
//
// Example usage:
//
//	cfg := goheader.AgeConfig{Seconds: 120}
//	header := goheader.NewAgeHeader(cfg)
//	fmt.Println(header.Name)   // Age
//	fmt.Println(header.Values) // ["120"]
func NewAgeHeader(cfg AgeConfig) Header {
	return Header{
		Experimental: false,
		Name:         Age,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AllowValue represents one HTTP method in the Allow header.
type AllowValue struct {
	Method string // e.g., "GET", "POST", "PUT"
}

// String renders a single Allow value.
func (v AllowValue) String() string {
	return v.Method
}

// AllowConfig defines the configuration for the Allow header.
type AllowConfig struct {
	Values []AllowValue
}

// String renders the full Allow header value from the config.
func (cfg AllowConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAllowHeader creates a new Allow header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Allow
//
// Example usage:
//
//	cfg := goheader.AllowConfig{
//	    Values: []goheader.AllowValue{
//	        {Method: "GET"},
//	        {Method: "POST"},
//	    },
//	}
//	header := goheader.NewAllowHeader(cfg)
//	fmt.Println(header.Name)   // Allow
//	fmt.Println(header.Values) // ["GET, POST"]
func NewAllowHeader(cfg AllowConfig) Header {
	return Header{
		Experimental: false,
		Name:         Allow,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AltSvcValue represents one alternative service in the Alt-Svc header.
type AltSvcValue struct {
	Protocol string // e.g., "h3", "h2", "quic"
	Host     string // e.g., ":443" or "example.com:443"
	MaxAge   int    // ma parameter in seconds
	Persist  bool   // persist=1 if true
}

// String renders a single Alt-Svc value.
func (v AltSvcValue) String() string {
	params := []string{fmt.Sprintf("%q", v.Host)}

	if v.MaxAge > 0 {
		params = append(params, fmt.Sprintf("ma=%d", v.MaxAge))
	}
	if v.Persist {
		params = append(params, "persist=1")
	}

	return fmt.Sprintf("%s=%s", v.Protocol, strings.Join(params, "; "))
}

// AltSvcConfig defines the configuration for the Alt-Svc header.
type AltSvcConfig struct {
	Values []AltSvcValue
}

// String renders the full Alt-Svc header value from the config.
func (cfg AltSvcConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewAltSvcHeader creates a new Alt-Svc header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Svc
//
// Example usage:
//
//	cfg := goheader.AltSvcConfig{
//	    Values: []goheader.AltSvcValue{
//	        {Protocol: "h3", Host: ":443", MaxAge: 86400, Persist: true},
//	    },
//	}
//	header := goheader.NewAltSvcHeader(cfg)
//	fmt.Println(header.Name)   // Alt-Svc
//	fmt.Println(header.Values) // [h3=":443"; ma=86400; persist=1]
func NewAltSvcHeader(cfg AltSvcConfig) Header {
	return Header{
		Experimental: false,
		Name:         AltSvc,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AltUsedConfig defines the configuration for the Alt-Used header.
type AltUsedConfig struct {
	HostPort string // e.g., "alt.example.com:443"
}

// String renders the Alt-Used header value.
func (cfg AltUsedConfig) String() string {
	return cfg.HostPort
}

// NewAltUsedHeader creates a new Alt-Used header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Used
//
// Example usage:
//
//	cfg := goheader.AltUsedConfig{HostPort: "alt.example.com:443"}
//	header := goheader.NewAltUsedHeader(cfg)
//	fmt.Println(header.Name)   // Alt-Used
//	fmt.Println(header.Values) // ["alt.example.com:443"]
func NewAltUsedHeader(cfg AltUsedConfig) Header {
	return Header{
		Experimental: false,
		Name:         AltUsed,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// AuthorizationConfig defines the configuration for the Authorization header.
type AuthorizationConfig struct {
	Scheme      string // e.g., "Bearer", "Basic"
	Credentials string // e.g., "token123", "dXNlcjpwYXNz"
}

// String renders the Authorization header value.
func (cfg AuthorizationConfig) String() string {
	return fmt.Sprintf("%s %s", cfg.Scheme, cfg.Credentials)
}

// NewAuthorizationHeader creates a new Authorization header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
//
// Example usage:
//
//	cfg := goheader.AuthorizationConfig{
//	    Scheme:      "Bearer",
//	    Credentials: "token123",
//	}
//	header := goheader.NewAuthorizationHeader(cfg)
//	fmt.Println(header.Name)   // Authorization
//	fmt.Println(header.Values) // ["Bearer token123"]
func NewAuthorizationHeader(cfg AuthorizationConfig) Header {
	return Header{
		Experimental: false,
		Name:         Authorization,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CacheControlDirective represents one directive in the Cache-Control header.
type CacheControlDirective struct {
	Directive string // e.g., "max-age", "no-cache"
	Value     *int   // Optional value for the directive, nil if none
}

// String renders a single Cache-Control directive.
func (d CacheControlDirective) String() string {
	if d.Value != nil {
		return fmt.Sprintf("%s=%d", d.Directive, *d.Value)
	}
	return d.Directive
}

// CacheControlConfig defines the configuration for the Cache-Control header.
type CacheControlConfig struct {
	Directives []CacheControlDirective
}

// String renders the full Cache-Control header value from the config.
func (cfg CacheControlConfig) String() string {
	var parts []string
	for _, d := range cfg.Directives {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, ", ")
}

// NewCacheControlHeader creates a new Cache-Control header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
//
// Example usage:
//
//	maxAge := 3600
//	cfg := goheader.CacheControlConfig{
//	    Directives: []goheader.CacheControlDirective{
//	        {Directive: "max-age", Value: &maxAge},
//	        {Directive: "no-cache"},
//	    },
//	}
//	header := goheader.NewCacheControlHeader(cfg)
//	fmt.Println(header.Name)   // Cache-Control
//	fmt.Println(header.Values) // ["max-age=3600, no-cache"]
func NewCacheControlHeader(cfg CacheControlConfig) Header {
	return Header{
		Experimental: false,
		Name:         CacheControl,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ClearSiteDataDirective represents one directive in the Clear-Site-Data header.
type ClearSiteDataDirective struct {
	Directive string // e.g., "cache", "cookies", "storage", "executionContexts", "*"
}

// String renders a single Clear-Site-Data directive as a quoted string.
func (d ClearSiteDataDirective) String() string {
	return fmt.Sprintf("%q", d.Directive)
}

// ClearSiteDataConfig defines the configuration for the Clear-Site-Data header.
type ClearSiteDataConfig struct {
	Directives []ClearSiteDataDirective
}

// String renders the full Clear-Site-Data header value from the config.
func (cfg ClearSiteDataConfig) String() string {
	var parts []string
	for _, d := range cfg.Directives {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, ", ")
}

// NewClearSiteDataHeader creates a new Clear-Site-Data header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data
//
// Example usage:
//
//	cfg := goheader.ClearSiteDataConfig{
//	    Directives: []goheader.ClearSiteDataDirective{
//	        {Directive: "cache"},
//	        {Directive: "cookies"},
//	        {Directive: "storage"},
//	    },
//	}
//	header := goheader.NewClearSiteDataHeader(cfg)
//	fmt.Println(header.Name)   // Clear-Site-Data
//	fmt.Println(header.Values) // ["\"cache\", \"cookies\", \"storage\""]
func NewClearSiteDataHeader(cfg ClearSiteDataConfig) Header {
	return Header{
		Experimental: false,
		Name:         ClearSiteData,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ConnectionOption represents one option in the Connection header.
type ConnectionOption struct {
	Option string // e.g., "keep-alive", "close"
}

// String renders a single Connection option.
func (o ConnectionOption) String() string {
	return o.Option
}

// ConnectionConfig defines the configuration for the Connection header.
type ConnectionConfig struct {
	Options []ConnectionOption
}

// String renders the full Connection header value from the config.
func (cfg ConnectionConfig) String() string {
	var parts []string
	for _, o := range cfg.Options {
		parts = append(parts, o.String())
	}
	return strings.Join(parts, ", ")
}

// NewConnectionHeader creates a new Connection header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
//
// Example usage:
//
//	cfg := goheader.ConnectionConfig{
//	    Options: []goheader.ConnectionOption{
//	        {Option: "keep-alive"},
//	    },
//	}
//	header := goheader.NewConnectionHeader(cfg)
//	fmt.Println(header.Name)   // Connection
//	fmt.Println(header.Values) // ["keep-alive"]
func NewConnectionHeader(cfg ConnectionConfig) Header {
	return Header{
		Experimental: false,
		Name:         Connection,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentDPRConfig defines the configuration for the Content-DPR header.
type ContentDPRConfig struct {
	DPR float64 // Device Pixel Ratio for the image, e.g., 1.0, 2.0
}

// String renders the Content-DPR header value.
func (cfg ContentDPRConfig) String() string {
	return fmt.Sprintf("%.1f", cfg.DPR)
}

// NewContentDPRHeader creates a new Content-DPR header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-DPR
//
// Example usage:
//
//	cfg := goheader.ContentDPRConfig{DPR: 2.0}
//	header := goheader.NewContentDPRHeader(cfg)
//	fmt.Println(header.Name)   // Content-DPR
//	fmt.Println(header.Values) // ["2.0"]
func NewContentDPRHeader(cfg ContentDPRConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentDPR,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentDispositionConfig defines the configuration for the Content-Disposition header.
type ContentDispositionConfig struct {
	Type   string            // e.g., "inline", "attachment"
	Params map[string]string // optional parameters, e.g., filename="example.txt"
}

// String renders the Content-Disposition header value.
func (cfg ContentDispositionConfig) String() string {
	result := cfg.Type
	if len(cfg.Params) > 0 {
		var parts []string
		for k, v := range cfg.Params {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
		}
		result += "; " + strings.Join(parts, "; ")
	}
	return result
}

// NewContentDispositionHeader creates a new Content-Disposition header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition
//
// Example usage:
//
//	cfg := goheader.ContentDispositionConfig{
//	    Type: "attachment",
//	    Params: map[string]string{
//	        "filename": "example.txt",
//	    },
//	}
//	header := goheader.NewContentDispositionHeader(cfg)
//	fmt.Println(header.Name)   // Content-Disposition
//	fmt.Println(header.Values) // ["attachment; filename=\"example.txt\""]
func NewContentDispositionHeader(cfg ContentDispositionConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentDisposition,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentEncodingValue represents one encoding in the Content-Encoding header.
type ContentEncodingValue struct {
	Encoding string // e.g., "gzip", "br", "deflate", "identity"
}

// String renders a single Content-Encoding value.
func (v ContentEncodingValue) String() string {
	if v.Encoding == "" {
		return "identity"
	}
	return v.Encoding
}

// ContentEncodingConfig defines the configuration for the Content-Encoding header.
type ContentEncodingConfig struct {
	Values []ContentEncodingValue
}

// String renders the full Content-Encoding header value from the config.
func (cfg ContentEncodingConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewContentEncodingHeader creates a new Content-Encoding header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
//
// Example usage:
//
//	cfg := goheader.ContentEncodingConfig{
//	    Values: []goheader.ContentEncodingValue{
//	        {Encoding: "gzip"},
//	        {Encoding: "br"},
//	    },
//	}
//	header := goheader.NewContentEncodingHeader(cfg)
//	fmt.Println(header.Name)   // Content-Encoding
//	fmt.Println(header.Values) // ["gzip, br"]
func NewContentEncodingHeader(cfg ContentEncodingConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentEncoding,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentLanguageValue represents one language in the Content-Language header.
type ContentLanguageValue struct {
	Language string // e.g., "en", "fr", "de", "en-US"
}

// String renders a single Content-Language value.
func (v ContentLanguageValue) String() string {
	return v.Language
}

// ContentLanguageConfig defines the configuration for the Content-Language header.
type ContentLanguageConfig struct {
	Values []ContentLanguageValue
}

// String renders the full Content-Language header value from the config.
func (cfg ContentLanguageConfig) String() string {
	var parts []string
	for _, v := range cfg.Values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// NewContentLanguageHeader creates a new Content-Language header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Language
//
// Example usage:
//
//	cfg := goheader.ContentLanguageConfig{
//	    Values: []goheader.ContentLanguageValue{
//	        {Language: "en"},
//	        {Language: "fr"},
//	    },
//	}
//	header := goheader.NewContentLanguageHeader(cfg)
//	fmt.Println(header.Name)   // Content-Language
//	fmt.Println(header.Values) // ["en, fr"]
func NewContentLanguageHeader(cfg ContentLanguageConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentLanguage,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentLengthConfig defines the configuration for the Content-Length header.
type ContentLengthConfig struct {
	Bytes int // Size of the message body in bytes
}

// String renders the Content-Length header value.
func (cfg ContentLengthConfig) String() string {
	return fmt.Sprintf("%d", cfg.Bytes)
}

// NewContentLengthHeader creates a new Content-Length header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
//
// Example usage:
//
//	cfg := goheader.ContentLengthConfig{Bytes: 1024}
//	header := goheader.NewContentLengthHeader(cfg)
//	fmt.Println(header.Name)   // Content-Length
//	fmt.Println(header.Values) // ["1024"]
func NewContentLengthHeader(cfg ContentLengthConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentLength,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentLocationConfig defines the configuration for the Content-Location header.
type ContentLocationConfig struct {
	URL string // Canonical or direct URL for the resource
}

// String renders the Content-Location header value.
func (cfg ContentLocationConfig) String() string {
	return cfg.URL
}

// NewContentLocationHeader creates a new Content-Location header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Location
//
// Example usage:
//
//	cfg := goheader.ContentLocationConfig{URL: "https://example.com/data.json"}
//	header := goheader.NewContentLocationHeader(cfg)
//	fmt.Println(header.Name)   // Content-Location
//	fmt.Println(header.Values) // ["https://example.com/data.json"]
func NewContentLocationHeader(cfg ContentLocationConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentLocation,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentMD5Config defines the configuration for the Content-MD5 header.
type ContentMD5Config struct {
	Checksum string // Base64-encoded MD5 checksum
}

// String renders the Content-MD5 header value.
func (cfg ContentMD5Config) String() string {
	return cfg.Checksum
}

// NewContentMD5Header creates a new Content-MD5 header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-MD5
//
// Example usage:
//
//	cfg := goheader.ContentMD5Config{Checksum: "Q2hlY2sgSW50ZWdyaXR5IQ=="}
//	header := goheader.NewContentMD5Header(cfg)
//	fmt.Println(header.Name)   // Content-MD5
//	fmt.Println(header.Values) // ["Q2hlY2sgSW50ZWdyaXR5IQ=="]
func NewContentMD5Header(cfg ContentMD5Config) Header {
	return Header{
		Experimental: false,
		Name:         ContentMD5,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentRangeConfig defines the configuration for the Content-Range header.
type ContentRangeConfig struct {
	Unit  string // e.g., "bytes"
	Start int    // Start byte, or -1 if unknown
	End   int    // End byte, or -1 if unknown
	Size  int    // Total size, or -1 if unknown
}

// String renders the Content-Range header value.
func (cfg ContentRangeConfig) String() string {
	unit := cfg.Unit
	if unit == "" {
		unit = "bytes"
	}

	if cfg.Start < 0 || cfg.End < 0 {
		// unknown range, size known
		if cfg.Size >= 0 {
			return fmt.Sprintf("%s */%d", unit, cfg.Size)
		}
		// unknown everything
		return fmt.Sprintf("%s *", unit)
	}

	// full range
	if cfg.Size >= 0 {
		return fmt.Sprintf("%s %d-%d/%d", unit, cfg.Start, cfg.End, cfg.Size)
	}
	return fmt.Sprintf("%s %d-%d/*", unit, cfg.Start, cfg.End)
}

// NewContentRangeHeader creates a new Content-Range header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Range
//
// Example usage:
//
//	cfg := goheader.ContentRangeConfig{Unit: "bytes", Start: 0, End: 499, Size: 1234}
//	header := goheader.NewContentRangeHeader(cfg)
//	fmt.Println(header.Name)   // Content-Range
//	fmt.Println(header.Values) // ["bytes 0-499/1234"]
func NewContentRangeHeader(cfg ContentRangeConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentRange,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CSPDirective represents one directive in the Content-Security-Policy header.
type CSPDirective struct {
	Directive string   // e.g., "default-src", "script-src"
	Sources   []string // e.g., ["'self'", "https://apis.example.com"]
}

// String renders a single CSP directive.
func (d CSPDirective) String() string {
	if len(d.Sources) == 0 {
		return d.Directive
	}
	return d.Directive + " " + strings.Join(d.Sources, " ")
}

// ContentSecurityPolicyConfig defines the configuration for the CSP header.
type ContentSecurityPolicyConfig struct {
	Directives []CSPDirective
}

// String renders the full Content-Security-Policy header value from the config.
func (cfg ContentSecurityPolicyConfig) String() string {
	var parts []string
	for _, d := range cfg.Directives {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, "; ")
}

// NewContentSecurityPolicyHeader creates a new Content-Security-Policy header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
//
// Example usage:
//
//	cfg := goheader.ContentSecurityPolicyConfig{
//	    Directives: []goheader.CSPDirective{
//	        {Directive: "default-src", Sources: []string{"'self'"}},
//	        {Directive: "script-src", Sources: []string{"'self'", "https://apis.example.com"}},
//	    },
//	}
//	header := goheader.NewContentSecurityPolicyHeader(cfg)
//	fmt.Println(header.Name)   // Content-Security-Policy
//	fmt.Println(header.Values) // ["default-src 'self'; script-src 'self' https://apis.example.com"]
func NewContentSecurityPolicyHeader(cfg ContentSecurityPolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentSecurityPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentSecurityPolicyReportOnlyConfig defines the configuration for the CSPRO header.
type ContentSecurityPolicyReportOnlyConfig struct {
	Directives []CSPDirective
}

// String renders the full Content-Security-Policy-Report-Only header value from the config.
func (cfg ContentSecurityPolicyReportOnlyConfig) String() string {
	var parts []string
	for _, d := range cfg.Directives {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, "; ")
}

// NewContentSecurityPolicyReportOnlyHeader creates a new CSPRO header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
//
// Example usage:
//
//	cfg := goheader.ContentSecurityPolicyReportOnlyConfig{
//	    Directives: []goheader.CSPDirective{
//	        {Directive: "default-src", Sources: []string{"'self'"}},
//	        {Directive: "script-src", Sources: []string{"'self'", "https://apis.example.com"}},
//	    },
//	}
//	header := goheader.NewContentSecurityPolicyReportOnlyHeader(cfg)
//	fmt.Println(header.Name)   // Content-Security-Policy-Report-Only
//	fmt.Println(header.Values) // ["default-src 'self'; script-src 'self' https://apis.example.com"]
func NewContentSecurityPolicyReportOnlyHeader(cfg ContentSecurityPolicyReportOnlyConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentSecurityPolicyReportOnly,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ContentTypeConfig defines the configuration for the Content-Type header.
type ContentTypeConfig struct {
	MediaType string            // e.g., "application/json", "text/html"
	Params    map[string]string // e.g., {"charset": "UTF-8"}
}

// String renders the Content-Type header value.
func (cfg ContentTypeConfig) String() string {
	result := cfg.MediaType
	if len(cfg.Params) > 0 {
		var params []string
		for k, v := range cfg.Params {
			params = append(params, fmt.Sprintf("%s=%s", k, v))
		}
		result += "; " + strings.Join(params, "; ")
	}
	return result
}

// NewContentTypeHeader creates a new Content-Type header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type
//
// Example usage:
//
//	cfg := goheader.ContentTypeConfig{
//	    MediaType: "application/json",
//	    Params:    map[string]string{"charset": "UTF-8"},
//	}
//	header := goheader.NewContentTypeHeader(cfg)
//	fmt.Println(header.Name)   // Content-Type
//	fmt.Println(header.Values) // ["application/json; charset=UTF-8"]
func NewContentTypeHeader(cfg ContentTypeConfig) Header {
	return Header{
		Experimental: false,
		Name:         ContentType,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CookieValue represents one cookie in the Cookie header.
type CookieValue struct {
	Name  string // e.g., "sessionId"
	Value string // e.g., "abc123"
}

// String renders a single cookie as name=value.
func (c CookieValue) String() string {
	return c.Name + "=" + c.Value
}

// CookieConfig defines the configuration for the Cookie header.
type CookieConfig struct {
	Cookies []CookieValue
}

// String renders the full Cookie header value from the config.
func (cfg CookieConfig) String() string {
	var parts []string
	for _, c := range cfg.Cookies {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "; ")
}

// NewCookieHeader creates a new Cookie header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cookie
//
// Example usage:
//
//	cfg := goheader.CookieConfig{
//	    Cookies: []goheader.CookieValue{
//	        {Name: "sessionId", Value: "abc123"},
//	        {Name: "theme", Value: "dark"},
//	    },
//	}
//	header := goheader.NewCookieHeader(cfg)
//	fmt.Println(header.Name)   // Cookie
//	fmt.Println(header.Values) // ["sessionId=abc123; theme=dark"]
func NewCookieHeader(cfg CookieConfig) Header {
	return Header{
		Experimental: false,
		Name:         Cookie,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CorrelationIDConfig defines the configuration for the Correlation-ID header.
type CorrelationIDConfig struct {
	ID string // Unique correlation ID, often a UUID
}

// String renders the Correlation-ID header value.
func (cfg CorrelationIDConfig) String() string {
	return cfg.ID
}

// NewCorrelationIDHeader creates a new Correlation-ID header from the config.
// Although not a standard HTTP header, it's widely used in distributed tracing.
//
// Example usage:
//
//	cfg := goheader.CorrelationIDConfig{ID: "123e4567-e89b-12d3-a456-426614174000"}
//	header := goheader.NewCorrelationIDHeader(cfg)
//	fmt.Println(header.Name)   // Correlation-ID
//	fmt.Println(header.Values) // ["123e4567-e89b-12d3-a456-426614174000"]
func NewCorrelationIDHeader(cfg CorrelationIDConfig) Header {
	return Header{
		Experimental: true, // Not part of the HTTP standard
		Name:         CorrelationID,
		Request:      true,
		Response:     true,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// CriticalCHConfig defines the configuration for the Critical-CH header.
type CriticalCHConfig struct {
	Hints []string // e.g., ["DPR", "Width", "Viewport-Width"]
}

// String renders the Critical-CH header value.
func (cfg CriticalCHConfig) String() string {
	return strings.Join(cfg.Hints, ", ")
}

// NewCriticalCHHeader creates a new Critical-CH header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Critical-CH
//
// Example usage:
//
//	cfg := goheader.CriticalCHConfig{Hints: []string{"DPR", "Width", "Viewport-Width"}}
//	header := goheader.NewCriticalCHHeader(cfg)
//	fmt.Println(header.Name)   // Critical-CH
//	fmt.Println(header.Values) // ["DPR, Width, Viewport-Width"]
func NewCriticalCHHeader(cfg CriticalCHConfig) Header {
	return Header{
		Experimental: false,
		Name:         CriticalCH,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CrossOriginEmbedderPolicyConfig defines the configuration for the COEP header.
type CrossOriginEmbedderPolicyConfig struct {
	Policy string // e.g., "unsafe-none", "require-corp"
}

// String renders the Cross-Origin-Embedder-Policy header value.
func (cfg CrossOriginEmbedderPolicyConfig) String() string {
	return cfg.Policy
}

// NewCrossOriginEmbedderPolicyHeader creates a new Cross-Origin-Embedder-Policy header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
//
// Example usage:
//
//	cfg := goheader.CrossOriginEmbedderPolicyConfig{Policy: "require-corp"}
//	header := goheader.NewCrossOriginEmbedderPolicyHeader(cfg)
//	fmt.Println(header.Name)   // Cross-Origin-Embedder-Policy
//	fmt.Println(header.Values) // ["require-corp"]
func NewCrossOriginEmbedderPolicyHeader(cfg CrossOriginEmbedderPolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         CrossOriginEmbedderPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CrossOriginOpenerPolicyConfig defines the configuration for the COOP header.
type CrossOriginOpenerPolicyConfig struct {
	Policy string // e.g., "unsafe-none", "same-origin", "same-origin-allow-popups"
}

// String renders the Cross-Origin-Opener-Policy header value.
func (cfg CrossOriginOpenerPolicyConfig) String() string {
	return cfg.Policy
}

// NewCrossOriginOpenerPolicyHeader creates a new Cross-Origin-Opener-Policy header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
//
// Example usage:
//
//	cfg := goheader.CrossOriginOpenerPolicyConfig{Policy: "same-origin"}
//	header := goheader.NewCrossOriginOpenerPolicyHeader(cfg)
//	fmt.Println(header.Name)   // Cross-Origin-Opener-Policy
//	fmt.Println(header.Values) // ["same-origin"]
func NewCrossOriginOpenerPolicyHeader(cfg CrossOriginOpenerPolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         CrossOriginOpenerPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// CrossOriginResourcePolicyConfig defines the configuration for the CORP header.
type CrossOriginResourcePolicyConfig struct {
	Policy string // e.g., "same-site", "same-origin", "cross-origin"
}

// String renders the Cross-Origin-Resource-Policy header value.
func (cfg CrossOriginResourcePolicyConfig) String() string {
	return cfg.Policy
}

// NewCrossOriginResourcePolicyHeader creates a new Cross-Origin-Resource-Policy header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
//
// Example usage:
//
//	cfg := goheader.CrossOriginResourcePolicyConfig{Policy: "same-origin"}
//	header := goheader.NewCrossOriginResourcePolicyHeader(cfg)
//	fmt.Println(header.Name)   // Cross-Origin-Resource-Policy
//	fmt.Println(header.Values) // ["same-origin"]
func NewCrossOriginResourcePolicyHeader(cfg CrossOriginResourcePolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         CrossOriginResourcePolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DNTConfig defines the configuration for the DNT header.
type DNTConfig struct {
	Value string // "0", "1", or "null"
}

// String renders the DNT header value.
func (cfg DNTConfig) String() string {
	return cfg.Value
}

// NewDNTHeader creates a new DNT header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/DNT
//
// Example usage:
//
//	cfg := goheader.DNTConfig{Value: "1"}
//	header := goheader.NewDNTHeader(cfg)
//	fmt.Println(header.Name)   // DNT
//	fmt.Println(header.Values) // ["1"]
func NewDNTHeader(cfg DNTConfig) Header {
	return Header{
		Experimental: false,
		Name:         DNT,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DPRConfig defines the configuration for the DPR header.
type DPRConfig struct {
	Value float64 // Device Pixel Ratio, e.g., 1.0, 2.0
}

// String renders the DPR header value.
func (cfg DPRConfig) String() string {
	return fmt.Sprintf("%.1f", cfg.Value)
}

// NewDPRHeader creates a new DPR header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/DPR
//
// Example usage:
//
//	cfg := goheader.DPRConfig{Value: 2.0}
//	header := goheader.NewDPRHeader(cfg)
//	fmt.Println(header.Name)   // DPR
//	fmt.Println(header.Values) // ["2.0"]
func NewDPRHeader(cfg DPRConfig) Header {
	return Header{
		Experimental: false,
		Name:         DPR,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DateConfig defines the configuration for the Date header.
type DateConfig struct {
	Time time.Time // Date/time for the header, will be rendered in IMF-fixdate format
}

// String renders the Date header value in RFC 7231 IMF-fixdate format.
func (cfg DateConfig) String() string {
	return cfg.Time.UTC().Format(time.RFC1123)
}

// NewDateHeader creates a new Date header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date
//
// Example usage:
//
//	cfg := goheader.DateConfig{Time: time.Now()}
//	header := goheader.NewDateHeader(cfg)
//	fmt.Println(header.Name)   // Date
//	fmt.Println(header.Values) // ["Mon, 02 Jan 2006 15:04:05 GMT"]
func NewDateHeader(cfg DateConfig) Header {
	return Header{
		Experimental: false,
		Name:         Date,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DeltaBaseConfig defines the configuration for the Delta-Base header.
type DeltaBaseConfig struct {
	ETag string // The ETag of the base resource
}

// String renders the Delta-Base header value.
func (cfg DeltaBaseConfig) String() string {
	return cfg.ETag
}

// NewDeltaBaseHeader creates a new Delta-Base header from the config.
// More information: https://datatracker.ietf.org/doc/html/rfc3229#section-10.5
//
// Example usage:
//
//	cfg := goheader.DeltaBaseConfig{ETag: "\"abc123etag\""}
//	header := goheader.NewDeltaBaseHeader(cfg)
//	fmt.Println(header.Name)   // Delta-Base
//	fmt.Println(header.Values) // ["\"abc123etag\""]
func NewDeltaBaseHeader(cfg DeltaBaseConfig) Header {
	return Header{
		Experimental: false,
		Name:         DeltaBase,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DeviceMemoryConfig defines the configuration for the Device-Memory header.
type DeviceMemoryConfig struct {
	GB float64 // Approximate device memory in GB
}

// String renders the Device-Memory header value.
func (cfg DeviceMemoryConfig) String() string {
	return fmt.Sprintf("%.2g", cfg.GB)
}

// NewDeviceMemoryHeader creates a new Device-Memory header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Device-Memory
//
// Example usage:
//
//	cfg := goheader.DeviceMemoryConfig{GB: 4}
//	header := goheader.NewDeviceMemoryHeader(cfg)
//	fmt.Println(header.Name)   // Device-Memory
//	fmt.Println(header.Values) // ["4"]
func NewDeviceMemoryHeader(cfg DeviceMemoryConfig) Header {
	return Header{
		Experimental: false,
		Name:         DeviceMemory,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DigestValue represents one algorithm/hash pair for the Digest header.
type DigestValue struct {
	Algorithm string // e.g., "SHA-256"
	Hash      string // e.g., "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
}

// String renders a single Digest value.
func (d DigestValue) String() string {
	return d.Algorithm + "=" + d.Hash
}

// DigestConfig defines the configuration for the Digest header.
type DigestConfig struct {
	Values []DigestValue
}

// String renders the full Digest header value from the config.
func (cfg DigestConfig) String() string {
	var parts []string
	for _, d := range cfg.Values {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, ", ")
}

// NewDigestHeader creates a new Digest header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Digest
//
// Example usage:
//
//	cfg := goheader.DigestConfig{
//	    Values: []goheader.DigestValue{
//	        {Algorithm: "SHA-256", Hash: "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
//	    },
//	}
//	header := goheader.NewDigestHeader(cfg)
//	fmt.Println(header.Name)   // Digest
//	fmt.Println(header.Values) // ["SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="]
func NewDigestHeader(cfg DigestConfig) Header {
	return Header{
		Experimental: false,
		Name:         Digest,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// DownlinkConfig defines the configuration for the Downlink header.
type DownlinkConfig struct {
	Mbps float64 // Approximate downlink speed in Mbps
}

// String renders the Downlink header value.
func (cfg DownlinkConfig) String() string {
	return fmt.Sprintf("%.1f", cfg.Mbps)
}

// NewDownlinkHeader creates a new Downlink header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Downlink
//
// Example usage:
//
//	cfg := goheader.DownlinkConfig{Mbps: 10.2}
//	header := goheader.NewDownlinkHeader(cfg)
//	fmt.Println(header.Name)   // Downlink
//	fmt.Println(header.Values) // ["10.2"]
func NewDownlinkHeader(cfg DownlinkConfig) Header {
	return Header{
		Experimental: false,
		Name:         Downlink,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ECTConfig defines the configuration for the ECT header.
type ECTConfig struct {
	Type string // e.g., "slow-2g", "2g", "3g", "4g"
}

// String renders the ECT header value.
func (cfg ECTConfig) String() string {
	return cfg.Type
}

// NewECTHeader creates a new ECT header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ECT
//
// Example usage:
//
//	cfg := goheader.ECTConfig{Type: "4g"}
//	header := goheader.NewECTHeader(cfg)
//	fmt.Println(header.Name)   // ECT
//	fmt.Println(header.Values) // ["4g"]
func NewECTHeader(cfg ECTConfig) Header {
	return Header{
		Experimental: false,
		Name:         ECT,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ETagConfig defines the configuration for the ETag header.
type ETagConfig struct {
	Value string // e.g., "\"abc123\"" or "W/\"weak123\""
}

// String renders the ETag header value.
func (cfg ETagConfig) String() string {
	return cfg.Value
}

// NewETagHeader creates a new ETag header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag
//
// Example usage:
//
//	cfg := goheader.ETagConfig{Value: "\"abc123\""}
//	header := goheader.NewETagHeader(cfg)
//	fmt.Println(header.Name)   // ETag
//	fmt.Println(header.Values) // ["\"abc123\""]
func NewETagHeader(cfg ETagConfig) Header {
	return Header{
		Experimental: false,
		Name:         ETag,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// EarlyDataConfig defines the configuration for the Early-Data header.
type EarlyDataConfig struct {
	Value string // "1" or "0"
}

// String renders the Early-Data header value.
func (cfg EarlyDataConfig) String() string {
	return cfg.Value
}

// NewEarlyDataHeader creates a new Early-Data header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Early-Data
//
// Example usage:
//
//	cfg := goheader.EarlyDataConfig{Value: "1"}
//	header := goheader.NewEarlyDataHeader(cfg)
//	fmt.Println(header.Name)   // Early-Data
//	fmt.Println(header.Values) // ["1"]
func NewEarlyDataHeader(cfg EarlyDataConfig) Header {
	return Header{
		Experimental: false,
		Name:         EarlyData,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ExpectConfig defines the configuration for the Expect header.
type ExpectConfig struct {
	Directives []string // e.g., ["100-continue"]
}

// String renders the Expect header value.
func (cfg ExpectConfig) String() string {
	return strings.Join(cfg.Directives, ", ")
}

// NewExpectHeader creates a new Expect header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect
//
// Example usage:
//
//	cfg := goheader.ExpectConfig{Directives: []string{"100-continue"}}
//	header := goheader.NewExpectHeader(cfg)
//	fmt.Println(header.Name)   // Expect
//	fmt.Println(header.Values) // ["100-continue"]
func NewExpectHeader(cfg ExpectConfig) Header {
	return Header{
		Experimental: false,
		Name:         Expect,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ExpectCTConfig defines the configuration for the Expect-CT header.
type ExpectCTConfig struct {
	MaxAge    int    // in seconds, e.g., 86400
	Enforce   bool   // true for enforcement, false for report-only
	ReportURI string // optional report URI
}

// String renders the Expect-CT header value.
func (cfg ExpectCTConfig) String() string {
	var parts []string
	if cfg.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("max-age=%d", cfg.MaxAge))
	}
	if cfg.Enforce {
		parts = append(parts, "enforce")
	}
	if cfg.ReportURI != "" {
		parts = append(parts, fmt.Sprintf(`report-uri="%s"`, cfg.ReportURI))
	}
	return strings.Join(parts, ", ")
}

// NewExpectCTHeader creates a new Expect-CT header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT
//
// Example usage:
//
//	cfg := goheader.ExpectCTConfig{MaxAge: 86400, Enforce: true, ReportURI: "https://example.com/report"}
//	header := goheader.NewExpectCTHeader(cfg)
//	fmt.Println(header.Name)   // Expect-CT
//	fmt.Println(header.Values) // ["max-age=86400, enforce, report-uri=\"https://example.com/report\""]
func NewExpectCTHeader(cfg ExpectCTConfig) Header {
	return Header{
		Experimental: false,
		Name:         ExpectCT,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ExpiresConfig defines the configuration for the Expires header.
type ExpiresConfig struct {
	Time time.Time // Expiration date/time in IMF-fixdate format
}

// String renders the Expires header value in RFC 7231 IMF-fixdate format.
func (cfg ExpiresConfig) String() string {
	return cfg.Time.UTC().Format(time.RFC1123)
}

// NewExpiresHeader creates a new Expires header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires
//
// Example usage:
//
//	cfg := goheader.ExpiresConfig{Time: time.Now().Add(24 * time.Hour)}
//	header := goheader.NewExpiresHeader(cfg)
//	fmt.Println(header.Name)   // Expires
//	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
func NewExpiresHeader(cfg ExpiresConfig) Header {
	return Header{
		Experimental: false,
		Name:         Expires,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ForwardedConfig defines the configuration for the Forwarded header.
type ForwardedConfig struct {
	For   string // Client IP address
	By    string // Proxy IP address
	Proto string // Protocol, e.g., "http" or "https"
	Host  string // Original host
}

// String renders the Forwarded header value.
func (cfg ForwardedConfig) String() string {
	var parts []string
	if cfg.For != "" {
		parts = append(parts, fmt.Sprintf("for=%s", cfg.For))
	}
	if cfg.By != "" {
		parts = append(parts, fmt.Sprintf("by=%s", cfg.By))
	}
	if cfg.Proto != "" {
		parts = append(parts, fmt.Sprintf("proto=%s", cfg.Proto))
	}
	if cfg.Host != "" {
		parts = append(parts, fmt.Sprintf("host=%s", cfg.Host))
	}
	return strings.Join(parts, "; ")
}

// NewForwardedHeader creates a new Forwarded header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
//
// Example usage:
//
//	cfg := goheader.ForwardedConfig{For: "192.0.2.43", Proto: "https", By: "203.0.113.43", Host: "example.com"}
//	header := goheader.NewForwardedHeader(cfg)
//	fmt.Println(header.Name)   // Forwarded
//	fmt.Println(header.Values) // ["for=192.0.2.43; by=203.0.113.43; proto=https; host=example.com"]
func NewForwardedHeader(cfg ForwardedConfig) Header {
	return Header{
		Experimental: false,
		Name:         Forwarded,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// FromConfig defines the configuration for the From header.
type FromConfig struct {
	Email string // Email address of the client or user
}

// String renders the From header value.
func (cfg FromConfig) String() string {
	return cfg.Email
}

// NewFromHeader creates a new From header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/From
//
// Example usage:
//
//	cfg := goheader.FromConfig{Email: "user@example.com"}
//	header := goheader.NewFromHeader(cfg)
//	fmt.Println(header.Name)   // From
//	fmt.Println(header.Values) // ["user@example.com"]
func NewFromHeader(cfg FromConfig) Header {
	return Header{
		Experimental: false,
		Name:         From,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// FrontEndHTTPSConfig defines the configuration for the Front-End-HTTPs header.
type FrontEndHTTPSConfig struct {
	Enabled bool // true = "on", false = "off"
}

// String renders the Front-End-HTTPs header value.
func (cfg FrontEndHTTPSConfig) String() string {
	if cfg.Enabled {
		return "on"
	}
	return "off"
}

// NewFrontEndHTTPSHeader creates a new Front-End-HTTPs header from the config.
// Note: This is a non-standard header used primarily by proxies and load balancers.
//
// Example usage:
//
//	cfg := goheader.FrontEndHTTPSConfig{Enabled: true}
//	header := goheader.NewFrontEndHTTPsHeader(cfg)
//	fmt.Println(header.Name)   // Front-End-HTTPs
//	fmt.Println(header.Values) // ["on"]
func NewFrontEndHTTPSHeader(cfg FrontEndHTTPSConfig) Header {
	return Header{
		Experimental: true,
		Name:         FrontEndHTTPS,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// HTTP2SettingsConfig defines the configuration for the HTTP2-Settings header.
type HTTP2SettingsConfig struct {
	Settings string // Base64-encoded HTTP/2 SETTINGS payload
}

// String renders the HTTP2-Settings header value.
func (cfg HTTP2SettingsConfig) String() string {
	return cfg.Settings
}

// NewHTTP2SettingsHeader creates a new HTTP2-Settings header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/HTTP2-Settings
//
// Example usage:
//
//	cfg := goheader.HTTP2SettingsConfig{Settings: "AAMAAABkAAQAAP__"}
//	header := goheader.NewHTTP2SettingsHeader(cfg)
//	fmt.Println(header.Name)   // HTTP2-Settings
//	fmt.Println(header.Values) // ["AAMAAABkAAQAAP__"]
func NewHTTP2SettingsHeader(cfg HTTP2SettingsConfig) Header {
	return Header{
		Experimental: false,
		Name:         HTTP2Settings,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// HostConfig defines the configuration for the Host header.
type HostConfig struct {
	Host string // e.g., "example.com" or "example.com:8080"
}

// String renders the Host header value.
func (cfg HostConfig) String() string {
	return cfg.Host
}

// NewHostHeader creates a new Host header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host
//
// Example usage:
//
//	cfg := goheader.HostConfig{Host: "example.com:8080"}
//	header := goheader.NewHostHeader(cfg)
//	fmt.Println(header.Name)   // Host
//	fmt.Println(header.Values) // ["example.com:8080"]
func NewHostHeader(cfg HostConfig) Header {
	return Header{
		Experimental: false,
		Name:         Host,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// IMConfig defines the configuration for the IM header.
type IMConfig struct {
	Values []string // e.g., ["vcdiff", "gzip"]
}

// String renders the IM header value.
func (cfg IMConfig) String() string {
	return strings.Join(cfg.Values, ", ")
}

// NewIMHeader creates a new IM header from the config.
// More information: https://datatracker.ietf.org/doc/html/rfc3229#section-10.5.3
//
// Example usage:
//
//	cfg := goheader.IMConfig{Values: []string{"vcdiff", "gzip"}}
//	header := goheader.NewIMHeader(cfg)
//	fmt.Println(header.Name)   // IM
//	fmt.Println(header.Values) // ["vcdiff, gzip"]
func NewIMHeader(cfg IMConfig) Header {
	return Header{
		Experimental: false,
		Name:         IM,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// IfMatchConfig defines the configuration for the If-Match header.
type IfMatchConfig struct {
	ETags []string // e.g., []{"\"abc123\"", "\"xyz456\""} or []{"*"}
}

// String renders the If-Match header value.
func (cfg IfMatchConfig) String() string {
	return strings.Join(cfg.ETags, ", ")
}

// NewIfMatchHeader creates a new If-Match header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match
//
// Example usage:
//
//	cfg := goheader.IfMatchConfig{ETags: []string{"\"abc123\"", "\"xyz456\""}}
//	header := goheader.NewIfMatchHeader(cfg)
//	fmt.Println(header.Name)   // If-Match
//	fmt.Println(header.Values) // ["\"abc123\", \"xyz456\""]
func NewIfMatchHeader(cfg IfMatchConfig) Header {
	return Header{
		Experimental: false,
		Name:         IfMatch,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// IfModifiedSinceConfig defines the configuration for the If-Modified-Since header.
type IfModifiedSinceConfig struct {
	Time time.Time // Time cutoff for resource modification
}

// String renders the If-Modified-Since header value in RFC 7231 IMF-fixdate format.
func (cfg IfModifiedSinceConfig) String() string {
	return cfg.Time.UTC().Format(time.RFC1123)
}

// NewIfModifiedSinceHeader creates a new If-Modified-Since header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since
//
// Example usage:
//
//	cfg := goheader.IfModifiedSinceConfig{Time: time.Now().Add(-24 * time.Hour)}
//	header := goheader.NewIfModifiedSinceHeader(cfg)
//	fmt.Println(header.Name)   // If-Modified-Since
//	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
func NewIfModifiedSinceHeader(cfg IfModifiedSinceConfig) Header {
	return Header{
		Experimental: false,
		Name:         IfModifiedSince,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// IfNoneMatchConfig defines the configuration for the If-None-Match header.
type IfNoneMatchConfig struct {
	ETags []string // e.g., []{"\"abc123\"", "\"xyz456\""} or []{"*"}
}

// String renders the If-None-Match header value.
func (cfg IfNoneMatchConfig) String() string {
	return strings.Join(cfg.ETags, ", ")
}

// NewIfNoneMatchHeader creates a new If-None-Match header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
//
// Example usage:
//
//	cfg := goheader.IfNoneMatchConfig{ETags: []string{"\"abc123\"", "\"xyz456\""}}
//	header := goheader.NewIfNoneMatchHeader(cfg)
//	fmt.Println(header.Name)   // If-None-Match
//	fmt.Println(header.Values) // ["\"abc123\", \"xyz456\""]
func NewIfNoneMatchHeader(cfg IfNoneMatchConfig) Header {
	return Header{
		Experimental: false,
		Name:         IfNoneMatch,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// IfRangeConfig defines the configuration for the If-Range header.
// Either ETag or Date should be set. If both are set, ETag takes precedence.
type IfRangeConfig struct {
	ETag string    // e.g., "\"abc123\""
	Date time.Time // e.g., time.Now().Add(-24 * time.Hour)
}

// String renders the If-Range header value.
func (cfg IfRangeConfig) String() string {
	if cfg.ETag != "" {
		return cfg.ETag
	}
	if !cfg.Date.IsZero() {
		return cfg.Date.UTC().Format(time.RFC1123)
	}
	return ""
}

// NewIfRangeHeader creates a new If-Range header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Range
//
// Example usage:
//
//	cfg := goheader.IfRangeConfig{ETag: "\"abc123\""}
//	header := goheader.NewIfRangeHeader(cfg)
//	fmt.Println(header.Name)   // If-Range
//	fmt.Println(header.Values) // ["\"abc123\""]
func NewIfRangeHeader(cfg IfRangeConfig) Header {
	return Header{
		Experimental: false,
		Name:         IfRange,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// IfUnmodifiedSinceConfig defines the configuration for the If-Unmodified-Since header.
type IfUnmodifiedSinceConfig struct {
	Time time.Time // Time cutoff for resource modification
}

// String renders the If-Unmodified-Since header value in RFC 7231 IMF-fixdate format.
func (cfg IfUnmodifiedSinceConfig) String() string {
	return cfg.Time.UTC().Format(time.RFC1123)
}

// NewIfUnmodifiedSinceHeader creates a new If-Unmodified-Since header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Unmodified-Since
//
// Example usage:
//
//	cfg := goheader.IfUnmodifiedSinceConfig{Time: time.Now().Add(-24 * time.Hour)}
//	header := goheader.NewIfUnmodifiedSinceHeader(cfg)
//	fmt.Println(header.Name)   // If-Unmodified-Since
//	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
func NewIfUnmodifiedSinceHeader(cfg IfUnmodifiedSinceConfig) Header {
	return Header{
		Experimental: false,
		Name:         IfUnmodifiedSince,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// KeepAliveConfig defines the configuration for the Keep-Alive header.
type KeepAliveConfig struct {
	Timeout int // timeout in seconds
	Max     int // max requests
}

// String renders the Keep-Alive header value.
func (cfg KeepAliveConfig) String() string {
	var parts []string
	if cfg.Timeout > 0 {
		parts = append(parts, fmt.Sprintf("timeout=%d", cfg.Timeout))
	}
	if cfg.Max > 0 {
		parts = append(parts, fmt.Sprintf("max=%d", cfg.Max))
	}
	return strings.Join(parts, ", ")
}

// NewKeepAliveHeader creates a new Keep-Alive header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
//
// Example usage:
//
//	cfg := goheader.KeepAliveConfig{Timeout: 5, Max: 1000}
//	header := goheader.NewKeepAliveHeader(cfg)
//	fmt.Println(header.Name)   // Keep-Alive
//	fmt.Println(header.Values) // ["timeout=5, max=1000"]
func NewKeepAliveHeader(cfg KeepAliveConfig) Header {
	return Header{
		Experimental: false,
		Name:         KeepAlive,
		Request:      true,
		Response:     true,
		Standard:     false, // This is a non-standard but commonly used header
		Values:       []string{cfg.String()},
	}
}

// LargeAllocationConfig defines the configuration for the Large-Allocation header.
type LargeAllocationConfig struct {
	Size int // Requested memory allocation in MB, 0 for none
}

// String renders the Large-Allocation header value.
func (cfg LargeAllocationConfig) String() string {
	return fmt.Sprintf("%d", cfg.Size)
}

// NewLargeAllocationHeader creates a new Large-Allocation header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Large-Allocation
//
// Example usage:
//
//	cfg := goheader.LargeAllocationConfig{Size: 5000}
//	header := goheader.NewLargeAllocationHeader(cfg)
//	fmt.Println(header.Name)   // Large-Allocation
//	fmt.Println(header.Values) // ["5000"]
func NewLargeAllocationHeader(cfg LargeAllocationConfig) Header {
	return Header{
		Experimental: false,
		Name:         LargeAllocation,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard but supported in some browsers
		Values:       []string{cfg.String()},
	}
}

// LastModifiedConfig defines the configuration for the Last-Modified header.
type LastModifiedConfig struct {
	Time time.Time // Date/time when the resource was last modified
}

// String renders the Last-Modified header value in RFC 7231 IMF-fixdate format.
func (cfg LastModifiedConfig) String() string {
	return cfg.Time.UTC().Format(time.RFC1123)
}

// NewLastModifiedHeader creates a new Last-Modified header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified
//
// Example usage:
//
//	cfg := goheader.LastModifiedConfig{Time: time.Now().Add(-48 * time.Hour)}
//	header := goheader.NewLastModifiedHeader(cfg)
//	fmt.Println(header.Name)   // Last-Modified
//	fmt.Println(header.Values) // ["Wed, 21 Oct 2015 07:28:00 GMT"]
func NewLastModifiedHeader(cfg LastModifiedConfig) Header {
	return Header{
		Experimental: false,
		Name:         LastModified,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// LinkEntry defines a single link in the Link header.
type LinkEntry struct {
	URL        string            // Required: URL for the link
	Attributes map[string]string // Optional: key-value attributes like rel, type, title
}

// String renders a LinkEntry to a properly formatted string.
func (e LinkEntry) String() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("<%s>", e.URL))
	for k, v := range e.Attributes {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
	}
	return strings.Join(parts, "; ")
}

// LinkConfig defines the configuration for the Link header.
type LinkConfig struct {
	Links []LinkEntry // Multiple link entries
}

// String renders the Link header value.
func (cfg LinkConfig) String() string {
	var entries []string
	for _, link := range cfg.Links {
		entries = append(entries, link.String())
	}
	return strings.Join(entries, ", ")
}

// NewLinkHeader creates a new Link header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
//
// Example usage:
//
//	cfg := goheader.LinkConfig{
//	    Links: []goheader.LinkEntry{
//	        {URL: "https://example.com/page2", Attributes: map[string]string{"rel": "next"}},
//	        {URL: "https://example.com/page1", Attributes: map[string]string{"rel": "prev"}},
//	    },
//	}
//	header := goheader.NewLinkHeader(cfg)
//	fmt.Println(header.Name)   // Link
//	fmt.Println(header.Values) // ["<https://example.com/page2>; rel=\"next\", <https://example.com/page1>; rel=\"prev\""]
func NewLinkHeader(cfg LinkConfig) Header {
	return Header{
		Experimental: false,
		Name:         Link,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// LocationConfig defines the configuration for the Location header.
type LocationConfig struct {
	URL string // The URL of the new or moved resource
}

// String renders the Location header value.
func (cfg LocationConfig) String() string {
	return cfg.URL
}

// NewLocationHeader creates a new Location header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Location
//
// Example usage:
//
//	cfg := goheader.LocationConfig{URL: "https://example.com/newpage"}
//	header := goheader.NewLocationHeader(cfg)
//	fmt.Println(header.Name)   // Location
//	fmt.Println(header.Values) // ["https://example.com/newpage"]
func NewLocationHeader(cfg LocationConfig) Header {
	return Header{
		Experimental: false,
		Name:         Location,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// MaxForwardsConfig defines the configuration for the Max-Forwards header.
type MaxForwardsConfig struct {
	Count int // Number of allowed forwards/hops
}

// String renders the Max-Forwards header value.
func (cfg MaxForwardsConfig) String() string {
	return fmt.Sprintf("%d", cfg.Count)
}

// NewMaxForwardsHeader creates a new Max-Forwards header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Max-Forwards
//
// Example usage:
//
//	cfg := goheader.MaxForwardsConfig{Count: 5}
//	header := goheader.NewMaxForwardsHeader(cfg)
//	fmt.Println(header.Name)   // Max-Forwards
//	fmt.Println(header.Values) // ["5"]
func NewMaxForwardsHeader(cfg MaxForwardsConfig) Header {
	return Header{
		Experimental: false,
		Name:         MaxForwards,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// NELConfig defines the configuration for the NEL header.
type NELConfig struct {
	Policy string // JSON policy string
}

// String renders the NEL header value.
func (cfg NELConfig) String() string {
	return cfg.Policy
}

// NewNELHeader creates a new NEL header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/NEL
//
// Example usage:
//
//	cfg := goheader.NELConfig{Policy: `{"report_to": "endpoint-1", "max_age": 2592000, "include_subdomains": true}`}
//	header := goheader.NewNELHeader(cfg)
//	fmt.Println(header.Name)   // NEL
//	fmt.Println(header.Values) // [`{"report_to": "endpoint-1", "max_age": 2592000, "include_subdomains": true}`]
func NewNELHeader(cfg NELConfig) Header {
	return Header{
		Experimental: false,
		Name:         NEL,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// OriginConfig defines the configuration for the Origin header.
type OriginConfig struct {
	URL string // Origin URL (scheme + host + optional port)
}

// String renders the Origin header value.
func (cfg OriginConfig) String() string {
	return cfg.URL
}

// NewOriginHeader creates a new Origin header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
//
// Example usage:
//
//	cfg := goheader.OriginConfig{URL: "https://example.com"}
//	header := goheader.NewOriginHeader(cfg)
//	fmt.Println(header.Name)   // Origin
//	fmt.Println(header.Values) // ["https://example.com"]
func NewOriginHeader(cfg OriginConfig) Header {
	return Header{
		Experimental: false,
		Name:         Origin,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// P3PConfig defines the configuration for the P3P header.
type P3PConfig struct {
	Policy string // Compact privacy policy string
}

// String renders the P3P header value.
func (cfg P3PConfig) String() string {
	return cfg.Policy
}

// NewP3PHeader creates a new P3P header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/P3P
//
// Example usage:
//
//	cfg := goheader.P3PConfig{Policy: `CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"`}
//	header := goheader.NewP3PHeader(cfg)
//	fmt.Println(header.Name)   // P3P
//	fmt.Println(header.Values) // [`CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"`]
func NewP3PHeader(cfg P3PConfig) Header {
	return Header{
		Experimental: false,
		Name:         P3P,
		Request:      false,
		Response:     true,
		Standard:     false, // Deprecated
		Values:       []string{cfg.String()},
	}
}

// PermissionsPolicyConfig defines the configuration for the Permissions-Policy header.
type PermissionsPolicyConfig struct {
	Directives map[string][]string // feature -> allowed origins (e.g., "self", "*", etc.)
}

// String renders the Permissions-Policy header value.
func (cfg PermissionsPolicyConfig) String() string {
	var parts []string
	for feature, origins := range cfg.Directives {
		if len(origins) == 0 {
			parts = append(parts, fmt.Sprintf("%s=()", feature))
		} else {
			parts = append(parts, fmt.Sprintf("%s=(%s)", feature, strings.Join(origins, " ")))
		}
	}
	return strings.Join(parts, ", ")
}

// NewPermissionsPolicyHeader creates a new Permissions-Policy header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
//
// Example usage:
//
//	cfg := goheader.PermissionsPolicyConfig{
//	    Directives: map[string][]string{
//	        "geolocation": {"self"},
//	        "microphone":  {},
//	    },
//	}
//	header := goheader.NewPermissionsPolicyHeader(cfg)
//	fmt.Println(header.Name)   // Permissions-Policy
//	fmt.Println(header.Values) // ["geolocation=(self), microphone=()"]
func NewPermissionsPolicyHeader(cfg PermissionsPolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         PermissionsPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// PragmaConfig defines the configuration for the Pragma header.
type PragmaConfig struct {
	Directives []string // e.g., ["no-cache"]
}

// String renders the Pragma header value.
func (cfg PragmaConfig) String() string {
	return strings.Join(cfg.Directives, ", ")
}

// NewPragmaHeader creates a new Pragma header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma
//
// Example usage:
//
//	cfg := goheader.PragmaConfig{Directives: []string{"no-cache"}}
//	header := goheader.NewPragmaHeader(cfg)
//	fmt.Println(header.Name)   // Pragma
//	fmt.Println(header.Values) // ["no-cache"]
func NewPragmaHeader(cfg PragmaConfig) Header {
	return Header{
		Experimental: false,
		Name:         Pragma,
		Request:      true,
		Response:     true,
		Standard:     false, // Legacy header, kept for backward compatibility
		Values:       []string{cfg.String()},
	}
}

// PreferConfig defines the configuration for the Prefer header.
type PreferConfig struct {
	Directives []string // e.g., ["return=minimal", "wait=10"]
}

// String renders the Prefer header value.
func (cfg PreferConfig) String() string {
	return strings.Join(cfg.Directives, ", ")
}

// NewPreferHeader creates a new Prefer header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Prefer
//
// Example usage:
//
//	cfg := goheader.PreferConfig{Directives: []string{"return=minimal", "wait=10"}}
//	header := goheader.NewPreferHeader(cfg)
//	fmt.Println(header.Name)   // Prefer
//	fmt.Println(header.Values) // ["return=minimal, wait=10"]
func NewPreferHeader(cfg PreferConfig) Header {
	return Header{
		Experimental: false,
		Name:         Prefer,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// PreferenceAppliedConfig defines the configuration for the Preference-Applied header.
type PreferenceAppliedConfig struct {
	Directives []string // e.g., ["return=minimal"]
}

// String renders the Preference-Applied header value.
func (cfg PreferenceAppliedConfig) String() string {
	return strings.Join(cfg.Directives, ", ")
}

// NewPreferenceAppliedHeader creates a new Preference-Applied header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Preference-Applied
//
// Example usage:
//
//	cfg := goheader.PreferenceAppliedConfig{Directives: []string{"return=minimal"}}
//	header := goheader.NewPreferenceAppliedHeader(cfg)
//	fmt.Println(header.Name)   // Preference-Applied
//	fmt.Println(header.Values) // ["return=minimal"]
func NewPreferenceAppliedHeader(cfg PreferenceAppliedConfig) Header {
	return Header{
		Experimental: false,
		Name:         PreferenceApplied,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// PriorityConfig defines the configuration for the Priority header.
type PriorityConfig struct {
	Urgency     int  // 0-7, lower = higher priority
	Incremental bool // true = incremental rendering
}

// String renders the Priority header value.
func (cfg PriorityConfig) String() string {
	var parts []string
	if cfg.Urgency >= 0 {
		parts = append(parts, fmt.Sprintf("u=%d", cfg.Urgency))
	}
	if cfg.Incremental {
		parts = append(parts, "i")
	}
	return strings.Join(parts, ", ")
}

// NewPriorityHeader creates a new Priority header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Priority
//
// Example usage:
//
//	cfg := goheader.PriorityConfig{Urgency: 3, Incremental: true}
//	header := goheader.NewPriorityHeader(cfg)
//	fmt.Println(header.Name)   // Priority
//	fmt.Println(header.Values) // ["u=3, i"]
func NewPriorityHeader(cfg PriorityConfig) Header {
	return Header{
		Experimental: false,
		Name:         Priority,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ProxyAuthenticateConfig defines the configuration for the Proxy-Authenticate header.
type ProxyAuthenticateConfig struct {
	Schemes []string // e.g., ["Basic realm=\"Access to internal site\""]
}

// String renders the Proxy-Authenticate header value.
func (cfg ProxyAuthenticateConfig) String() string {
	return strings.Join(cfg.Schemes, ", ")
}

// NewProxyAuthenticateHeader creates a new Proxy-Authenticate header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate
//
// Example usage:
//
//	cfg := goheader.ProxyAuthenticateConfig{Schemes: []string{"Basic realm=\"Access to internal site\""}}
//	header := goheader.NewProxyAuthenticateHeader(cfg)
//	fmt.Println(header.Name)   // Proxy-Authenticate
//	fmt.Println(header.Values) // ["Basic realm=\"Access to internal site\""]
func NewProxyAuthenticateHeader(cfg ProxyAuthenticateConfig) Header {
	return Header{
		Experimental: false,
		Name:         ProxyAuthenticate,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ProxyAuthenticationInfoConfig defines the configuration for the Proxy-Authentication-Info header.
type ProxyAuthenticationInfoConfig struct {
	Params map[string]string // e.g., {"nextnonce": "abc123", "qop": "auth"}
}

// String renders the Proxy-Authentication-Info header value.
func (cfg ProxyAuthenticationInfoConfig) String() string {
	var parts []string
	for k, v := range cfg.Params {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
	}
	return strings.Join(parts, ", ")
}

// NewProxyAuthenticationInfoHeader creates a new Proxy-Authentication-Info header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authentication-Info
//
// Example usage:
//
//	cfg := goheader.ProxyAuthenticationInfoConfig{Params: map[string]string{"nextnonce": "abc123", "qop": "auth"}}
//	header := goheader.NewProxyAuthenticationInfoHeader(cfg)
//	fmt.Println(header.Name)   // Proxy-Authentication-Info
//	fmt.Println(header.Values) // ["nextnonce=\"abc123\", qop=\"auth\""]
func NewProxyAuthenticationInfoHeader(cfg ProxyAuthenticationInfoConfig) Header {
	return Header{
		Experimental: false,
		Name:         ProxyAuthenticationInfo,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ProxyAuthorizationConfig defines the configuration for the Proxy-Authorization header.
type ProxyAuthorizationConfig struct {
	Credentials string // e.g., "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
}

// String renders the Proxy-Authorization header value.
func (cfg ProxyAuthorizationConfig) String() string {
	return cfg.Credentials
}

// NewProxyAuthorizationHeader creates a new Proxy-Authorization header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
//
// Example usage:
//
//	cfg := goheader.ProxyAuthorizationConfig{Credentials: "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}
//	header := goheader.NewProxyAuthorizationHeader(cfg)
//	fmt.Println(header.Name)   // Proxy-Authorization
//	fmt.Println(header.Values) // ["Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]
func NewProxyAuthorizationHeader(cfg ProxyAuthorizationConfig) Header {
	return Header{
		Experimental: false,
		Name:         ProxyAuthorization,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ProxyConnectionConfig defines the configuration for the Proxy-Connection header.
type ProxyConnectionConfig struct {
	Directives []string // e.g., ["keep-alive"]
}

// String renders the Proxy-Connection header value.
func (cfg ProxyConnectionConfig) String() string {
	return strings.Join(cfg.Directives, ", ")
}

// NewProxyConnectionHeader creates a new Proxy-Connection header from the config.
// Note: This is a non-standard header historically used by some proxies.
//
// Example usage:
//
//	cfg := goheader.ProxyConnectionConfig{Directives: []string{"keep-alive"}}
//	header := goheader.NewProxyConnectionHeader(cfg)
//	fmt.Println(header.Name)   // Proxy-Connection
//	fmt.Println(header.Values) // ["keep-alive"]
func NewProxyConnectionHeader(cfg ProxyConnectionConfig) Header {
	return Header{
		Experimental: true,
		Name:         ProxyConnection,
		Request:      true,
		Response:     true,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// PublicKeyPinsConfig defines the configuration for the Public-Key-Pins header.
type PublicKeyPinsConfig struct {
	Pins              []string // e.g., []{"base64+primary==", "base64+backup=="}
	MaxAge            int      // in seconds
	IncludeSubDomains bool     // whether to include subdomains
	ReportURI         string   // optional URI for reporting
}

// String renders the Public-Key-Pins header value.
func (cfg PublicKeyPinsConfig) String() string {
	var parts []string
	for _, pin := range cfg.Pins {
		parts = append(parts, fmt.Sprintf(`pin-sha256="%s"`, pin))
	}
	if cfg.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("max-age=%d", cfg.MaxAge))
	}
	if cfg.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}
	if cfg.ReportURI != "" {
		parts = append(parts, fmt.Sprintf(`report-uri="%s"`, cfg.ReportURI))
	}
	return strings.Join(parts, "; ")
}

// NewPublicKeyPinsHeader creates a new Public-Key-Pins header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins
//
// Example usage:
//
//	cfg := goheader.PublicKeyPinsConfig{
//	    Pins: []string{"base64+primary==", "base64+backup=="},
//	    MaxAge: 5184000,
//	    IncludeSubDomains: true,
//	    ReportURI: "https://example.com/hpkp-report",
//	}
//	header := goheader.NewPublicKeyPinsHeader(cfg)
//	fmt.Println(header.Name)   // Public-Key-Pins
//	fmt.Println(header.Values) // ["pin-sha256=\"base64+primary==\"; pin-sha256=\"base64+backup==\"; max-age=5184000; includeSubDomains; report-uri=\"https://example.com/hpkp-report\""]
func NewPublicKeyPinsHeader(cfg PublicKeyPinsConfig) Header {
	return Header{
		Experimental: false,
		Name:         PublicKeyPins,
		Request:      false,
		Response:     true,
		Standard:     false, // Deprecated
		Values:       []string{cfg.String()},
	}
}

// PublicKeyPinsReportOnlyConfig defines the configuration for the Public-Key-Pins-Report-Only header.
type PublicKeyPinsReportOnlyConfig struct {
	Pins              []string // e.g., []{"base64+primary==", "base64+backup=="}
	MaxAge            int      // in seconds
	IncludeSubDomains bool     // whether to include subdomains
	ReportURI         string   // optional URI for reporting
}

// String renders the Public-Key-Pins-Report-Only header value.
func (cfg PublicKeyPinsReportOnlyConfig) String() string {
	var parts []string
	for _, pin := range cfg.Pins {
		parts = append(parts, fmt.Sprintf(`pin-sha256="%s"`, pin))
	}
	if cfg.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("max-age=%d", cfg.MaxAge))
	}
	if cfg.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}
	if cfg.ReportURI != "" {
		parts = append(parts, fmt.Sprintf(`report-uri="%s"`, cfg.ReportURI))
	}
	return strings.Join(parts, "; ")
}

// NewPublicKeyPinsReportOnlyHeader creates a new Public-Key-Pins-Report-Only header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins-Report-Only
//
// Example usage:
//
//	cfg := goheader.PublicKeyPinsReportOnlyConfig{
//	    Pins: []string{"base64+primary==", "base64+backup=="},
//	    MaxAge: 5184000,
//	    IncludeSubDomains: true,
//	    ReportURI: "https://example.com/hpkp-report",
//	}
//	header := goheader.NewPublicKeyPinsReportOnlyHeader(cfg)
//	fmt.Println(header.Name)   // Public-Key-Pins-Report-Only
//	fmt.Println(header.Values) // ["pin-sha256=\"base64+primary==\"; pin-sha256=\"base64+backup==\"; max-age=5184000; includeSubDomains; report-uri=\"https://example.com/hpkp-report\""]
func NewPublicKeyPinsReportOnlyHeader(cfg PublicKeyPinsReportOnlyConfig) Header {
	return Header{
		Experimental: false,
		Name:         PublicKeyPinsReportOnly,
		Request:      false,
		Response:     true,
		Standard:     false, // Deprecated
		Values:       []string{cfg.String()},
	}
}

// RTTConfig defines the configuration for the RTT header.
type RTTConfig struct {
	Milliseconds int // e.g., 150
}

// String renders the RTT header value.
func (cfg RTTConfig) String() string {
	return fmt.Sprintf("%d", cfg.Milliseconds)
}

// NewRTTHeader creates a new RTT header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/RTT
//
// Example usage:
//
//	cfg := goheader.RTTConfig{Milliseconds: 150}
//	header := goheader.NewRTTHeader(cfg)
//	fmt.Println(header.Name)   // RTT
//	fmt.Println(header.Values) // ["150"]
func NewRTTHeader(cfg RTTConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still experimental
		Name:         RTT,
		Request:      true,
		Response:     false,
		Standard:     false, // Not yet a fully standardised header
		Values:       []string{cfg.String()},
	}
}

// RangeConfig defines the configuration for the Range header.
type RangeConfig struct {
	Unit   string     // e.g., "bytes"
	Ranges [][2]int64 // slice of [start, end] pairs
}

// String renders the Range header value.
func (cfg RangeConfig) String() string {
	var parts []string
	for _, r := range cfg.Ranges {
		if r[1] >= 0 {
			parts = append(parts, fmt.Sprintf("%d-%d", r[0], r[1]))
		} else {
			// Suffix range: start-
			parts = append(parts, fmt.Sprintf("%d-", r[0]))
		}
	}
	return fmt.Sprintf("%s=%s", cfg.Unit, strings.Join(parts, ","))
}

// NewRangeHeader creates a new Range header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
//
// Example usage:
//
//	cfg := goheader.RangeConfig{
//	    Unit:   "bytes",
//	    Ranges: [][2]int64{{200, 1000}, {1500, -1}}, // -1 means open-ended
//	}
//	header := goheader.NewRangeHeader(cfg)
//	fmt.Println(header.Name)   // Range
//	fmt.Println(header.Values) // ["bytes=200-1000,1500-"]
func NewRangeHeader(cfg RangeConfig) Header {
	return Header{
		Experimental: false,
		Name:         Range,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// RefererConfig defines the configuration for the Referer header.
type RefererConfig struct {
	URL string // e.g., "https://example.com/page"
}

// String renders the Referer header value.
func (cfg RefererConfig) String() string {
	return cfg.URL
}

// NewRefererHeader creates a new Referer header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
//
// Example usage:
//
//	cfg := goheader.RefererConfig{URL: "https://example.com/page"}
//	header := goheader.NewRefererHeader(cfg)
//	fmt.Println(header.Name)   // Referer
//	fmt.Println(header.Values) // ["https://example.com/page"]
func NewRefererHeader(cfg RefererConfig) Header {
	return Header{
		Experimental: false,
		Name:         Referer,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ReferrerPolicyConfig defines the configuration for the Referrer-Policy header.
type ReferrerPolicyConfig struct {
	Policy string // e.g., "strict-origin-when-cross-origin"
}

// String renders the Referrer-Policy header value.
func (cfg ReferrerPolicyConfig) String() string {
	return cfg.Policy
}

// NewReferrerPolicyHeader creates a new Referrer-Policy header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
//
// Example usage:
//
//	cfg := goheader.ReferrerPolicyConfig{Policy: "strict-origin-when-cross-origin"}
//	header := goheader.NewReferrerPolicyHeader(cfg)
//	fmt.Println(header.Name)   // Referrer-Policy
//	fmt.Println(header.Values) // ["strict-origin-when-cross-origin"]
func NewReferrerPolicyHeader(cfg ReferrerPolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         ReferrerPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// RefreshConfig defines the configuration for the Refresh header.
type RefreshConfig struct {
	DelaySeconds int    // e.g., 5
	RedirectURL  string // optional URL
}

// String renders the Refresh header value.
func (cfg RefreshConfig) String() string {
	if cfg.RedirectURL != "" {
		return fmt.Sprintf("%d; url=%s", cfg.DelaySeconds, cfg.RedirectURL)
	}
	return fmt.Sprintf("%d", cfg.DelaySeconds)
}

// NewRefreshHeader creates a new Refresh header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Refresh
//
// Example usage:
//
//	cfg := goheader.RefreshConfig{DelaySeconds: 5, RedirectURL: "https://example.com/new-page"}
//	header := goheader.NewRefreshHeader(cfg)
//	fmt.Println(header.Name)   // Refresh
//	fmt.Println(header.Values) // ["5; url=https://example.com/new-page"]
func NewRefreshHeader(cfg RefreshConfig) Header {
	return Header{
		Experimental: true, // Non-standard header
		Name:         Refresh,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// ReplayNonceConfig defines the configuration for the Replay-Nonce header.
type ReplayNonceConfig struct {
	Nonce string // e.g., "abc123XYZ"
}

// String renders the Replay-Nonce header value.
func (cfg ReplayNonceConfig) String() string {
	return cfg.Nonce
}

// NewReplayNonceHeader creates a new Replay-Nonce header from the config.
// More information: https://datatracker.ietf.org/doc/html/rfc8555#section-6.5
//
// Example usage:
//
//	cfg := goheader.ReplayNonceConfig{Nonce: "abc123XYZ"}
//	header := goheader.NewReplayNonceHeader(cfg)
//	fmt.Println(header.Name)   // Replay-Nonce
//	fmt.Println(header.Values) // ["abc123XYZ"]
func NewReplayNonceHeader(cfg ReplayNonceConfig) Header {
	return Header{
		Experimental: false,
		Name:         ReplayNonce,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ReportToConfig defines the configuration for the Report-To header.
type ReportToConfig struct {
	Group             string   // e.g., "csp-endpoint"
	MaxAge            int      // in seconds
	Endpoints         []string // endpoint URLs
	IncludeSubdomains bool     // whether to include subdomains
}

// ReportToPayload is used internally for JSON marshalling.
type ReportToPayload struct {
	Group     string `json:"group"`
	MaxAge    int    `json:"max_age"`
	Endpoints []struct {
		URL string `json:"url"`
	} `json:"endpoints"`
	IncludeSubdomains bool `json:"include_subdomains,omitempty"`
}

// String renders the Report-To header value.
func (cfg ReportToConfig) String() string {
	payload := ReportToPayload{
		Group:             cfg.Group,
		MaxAge:            cfg.MaxAge,
		IncludeSubdomains: cfg.IncludeSubdomains,
	}
	for _, url := range cfg.Endpoints {
		payload.Endpoints = append(payload.Endpoints, struct {
			URL string `json:"url"`
		}{URL: url})
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(data)
}

// NewReportToHeader creates a new Report-To header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Report-To
//
// Example usage:
//
//	cfg := goheader.ReportToConfig{
//	    Group: "csp-endpoint",
//	    MaxAge: 10886400,
//	    Endpoints: []string{"https://example.com/csp-reports"},
//	    IncludeSubdomains: true,
//	}
//	header := goheader.NewReportToHeader(cfg)
//	fmt.Println(header.Name)   // Report-To
//	fmt.Println(header.Values) // ['{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://example.com/csp-reports"}],"include_subdomains":true}']
func NewReportToHeader(cfg ReportToConfig) Header {
	return Header{
		Experimental: false,
		Name:         ReportTo,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ReportingEndpointsConfig defines the configuration for the Reporting-Endpoints header.
type ReportingEndpointsConfig struct {
	Endpoints map[string]string // e.g., {"default": "https://example.com/reports", "csp": "https://example.com/csp-reports"}
}

// String renders the Reporting-Endpoints header value.
func (cfg ReportingEndpointsConfig) String() string {
	var parts []string
	for name, url := range cfg.Endpoints {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, name, url))
	}
	return strings.Join(parts, ", ")
}

// NewReportingEndpointsHeader creates a new Reporting-Endpoints header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints
//
// Example usage:
//
//	cfg := goheader.ReportingEndpointsConfig{
//	    Endpoints: map[string]string{
//	        "default": "https://example.com/reports",
//	        "csp":     "https://example.com/csp-reports",
//	    },
//	}
//	header := goheader.NewReportingEndpointsHeader(cfg)
//	fmt.Println(header.Name)   // Reporting-Endpoints
//	fmt.Println(header.Values) // ["default=\"https://example.com/reports\", csp=\"https://example.com/csp-reports\""]
func NewReportingEndpointsHeader(cfg ReportingEndpointsConfig) Header {
	return Header{
		Experimental: false,
		Name:         ReportingEndpoints,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// RetryAfterConfig defines the configuration for the Retry-After header.
type RetryAfterConfig struct {
	Seconds int    // e.g., 120
	Date    string // e.g., "Wed, 21 Oct 2015 07:28:00 GMT"
}

// String renders the Retry-After header value.
func (cfg RetryAfterConfig) String() string {
	if cfg.Seconds > 0 {
		return fmt.Sprintf("%d", cfg.Seconds)
	}
	return cfg.Date
}

// NewRetryAfterHeader creates a new Retry-After header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
//
// Example usage:
//
//	cfg := goheader.RetryAfterConfig{Seconds: 120}
//	header := goheader.NewRetryAfterHeader(cfg)
//	fmt.Println(header.Name)   // Retry-After
//	fmt.Println(header.Values) // ["120"]
func NewRetryAfterHeader(cfg RetryAfterConfig) Header {
	return Header{
		Experimental: false,
		Name:         RetryAfter,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SaveDataConfig defines the configuration for the Save-Data header.
type SaveDataConfig struct {
	Enabled bool // true = "on", false = ""
}

// String renders the Save-Data header value.
func (cfg SaveDataConfig) String() string {
	if cfg.Enabled {
		return "on"
	}
	return ""
}

// NewSaveDataHeader creates a new Save-Data header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Save-Data
//
// Example usage:
//
//	cfg := goheader.SaveDataConfig{Enabled: true}
//	header := goheader.NewSaveDataHeader(cfg)
//	fmt.Println(header.Name)   // Save-Data
//	fmt.Println(header.Values) // ["on"]
func NewSaveDataHeader(cfg SaveDataConfig) Header {
	return Header{
		Experimental: false,
		Name:         SaveData,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecCHPrefersColorSchemeConfig defines the configuration for the Sec-CH-Prefers-Color-Scheme header.
type SecCHPrefersColorSchemeConfig struct {
	Preference string // "light", "dark", or "no-preference"
}

// String renders the Sec-CH-Prefers-Color-Scheme header value.
func (cfg SecCHPrefersColorSchemeConfig) String() string {
	return cfg.Preference
}

// NewSecCHPrefersColorSchemeHeader creates a new Sec-CH-Prefers-Color-Scheme header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-Prefers-Color-Scheme
//
// Example usage:
//
//	cfg := goheader.SecCHPrefersColorSchemeConfig{Preference: "dark"}
//	header := goheader.NewSecCHPrefersColorSchemeHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-Prefers-Color-Scheme
//	fmt.Println(header.Values) // ["dark"]
func NewSecCHPrefersColorSchemeHeader(cfg SecCHPrefersColorSchemeConfig) Header {
	return Header{
		Experimental: true, // Client hints are still evolving
		Name:         SecCHPrefersColorScheme,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHPrefersReducedMotionConfig defines the configuration for the Sec-CH-Prefers-Reduced-Motion header.
type SecCHPrefersReducedMotionConfig struct {
	Preference string // "reduce" or "no-preference"
}

// String renders the Sec-CH-Prefers-Reduced-Motion header value.
func (cfg SecCHPrefersReducedMotionConfig) String() string {
	return cfg.Preference
}

// NewSecCHPrefersReducedMotionHeader creates a new Sec-CH-Prefers-Reduced-Motion header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-Prefers-Reduced-Motion
//
// Example usage:
//
//	cfg := goheader.SecCHPrefersReducedMotionConfig{Preference: "reduce"}
//	header := goheader.NewSecCHPrefersReducedMotionHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-Prefers-Reduced-Motion
//	fmt.Println(header.Values) // ["reduce"]
func NewSecCHPrefersReducedMotionHeader(cfg SecCHPrefersReducedMotionConfig) Header {
	return Header{
		Experimental: true, // Client hints are still evolving
		Name:         SecCHPrefersReducedMotion,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHPrefersReducedTransparencyConfig defines the configuration for the Sec-CH-Prefers-Reduced-Transparency header.
type SecCHPrefersReducedTransparencyConfig struct {
	Preference string // "reduce" or "no-preference"
}

// String renders the Sec-CH-Prefers-Reduced-Transparency header value.
func (cfg SecCHPrefersReducedTransparencyConfig) String() string {
	return cfg.Preference
}

// NewSecCHPrefersReducedTransparencyHeader creates a new Sec-CH-Prefers-Reduced-Transparency header from the config.
// More information: https://wicg.github.io/client-hints-infrastructure/#prefers-reduced-transparency
//
// Example usage:
//
//	cfg := goheader.SecCHPrefersReducedTransparencyConfig{Preference: "reduce"}
//	header := goheader.NewSecCHPrefersReducedTransparencyHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-Prefers-Reduced-Transparency
//	fmt.Println(header.Values) // ["reduce"]
func NewSecCHPrefersReducedTransparencyHeader(cfg SecCHPrefersReducedTransparencyConfig) Header {
	return Header{
		Experimental: true, // Client hints are still evolving
		Name:         SecCHPrefersReducedTransparency,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAConfig defines the configuration for the Sec-CH-UA header.
type SecCHUAConfig struct {
	Brands map[string]string // e.g., {"Chromium": "112", "Google Chrome": "112"}
}

// String renders the Sec-CH-UA header value.
func (cfg SecCHUAConfig) String() string {
	var parts []string
	for brand, version := range cfg.Brands {
		parts = append(parts, fmt.Sprintf(`"%s";v="%s"`, brand, version))
	}
	return strings.Join(parts, ", ")
}

// NewSecCHUAHeader creates a new Sec-CH-UA header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA
//
// Example usage:
//
//	cfg := goheader.SecCHUAConfig{Brands: map[string]string{
//	    "Chromium":      "112",
//	    "Google Chrome": "112",
//	}}
//	header := goheader.NewSecCHUAHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA
//	fmt.Println(header.Values) // ["\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\""]
func NewSecCHUAHeader(cfg SecCHUAConfig) Header {
	return Header{
		Experimental: true, // Client Hints are evolving
		Name:         SecCHUA,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAArchConfig defines the configuration for the Sec-CH-UA-Arch header.
type SecCHUAArchConfig struct {
	Architecture string // e.g., "x86", "arm", "arm64"
}

// String renders the Sec-CH-UA-Arch header value.
func (cfg SecCHUAArchConfig) String() string {
	return `"` + cfg.Architecture + `"`
}

// NewSecCHUAArchHeader creates a new Sec-CH-UA-Arch header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Arch
//
// Example usage:
//
//	cfg := goheader.SecCHUAArchConfig{Architecture: "x86"}
//	header := goheader.NewSecCHUAArchHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Arch
//	fmt.Println(header.Values) // ["\"x86\""]
func NewSecCHUAArchHeader(cfg SecCHUAArchConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAArch,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUABitnessConfig defines the configuration for the Sec-CH-UA-Bitness header.
type SecCHUABitnessConfig struct {
	Bitness string // e.g., "32", "64"
}

// String renders the Sec-CH-UA-Bitness header value.
func (cfg SecCHUABitnessConfig) String() string {
	return `"` + cfg.Bitness + `"`
}

// NewSecCHUABitnessHeader creates a new Sec-CH-UA-Bitness header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Bitness
//
// Example usage:
//
//	cfg := goheader.SecCHUABitnessConfig{Bitness: "64"}
//	header := goheader.NewSecCHUABitnessHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Bitness
//	fmt.Println(header.Values) // ["\"64\""]
func NewSecCHUABitnessHeader(cfg SecCHUABitnessConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUABitness,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAFullVersionConfig defines the configuration for the Sec-CH-UA-Full-Version header.
type SecCHUAFullVersionConfig struct {
	Brands map[string]string // e.g., {"Chromium": "112.0.5615.137"}
}

// String renders the Sec-CH-UA-Full-Version header value.
func (cfg SecCHUAFullVersionConfig) String() string {
	var parts []string
	for brand, version := range cfg.Brands {
		parts = append(parts, fmt.Sprintf(`"%s";v="%s"`, brand, version))
	}
	return strings.Join(parts, ", ")
}

// NewSecCHUAFullVersionHeader creates a new Sec-CH-UA-Full-Version header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Full-Version
//
// Example usage:
//
//	cfg := goheader.SecCHUAFullVersionConfig{
//	    Brands: map[string]string{"Chromium": "112.0.5615.137"},
//	}
//	header := goheader.NewSecCHUAFullVersionHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Full-Version
//	fmt.Println(header.Values) // ["\"Chromium\";v=\"112.0.5615.137\""]
func NewSecCHUAFullVersionHeader(cfg SecCHUAFullVersionConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAFullVersion,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAFullVersionListConfig defines the configuration for the Sec-CH-UA-Full-Version-List header.
type SecCHUAFullVersionListConfig struct {
	Brands map[string]string // e.g., {"Chromium": "112.0.5615.137", "Google Chrome": "112.0.5615.137"}
}

// String renders the Sec-CH-UA-Full-Version-List header value.
func (cfg SecCHUAFullVersionListConfig) String() string {
	var parts []string
	for brand, version := range cfg.Brands {
		parts = append(parts, fmt.Sprintf(`"%s";v="%s"`, brand, version))
	}
	return strings.Join(parts, ", ")
}

// NewSecCHUAFullVersionListHeader creates a new Sec-CH-UA-Full-Version-List header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Full-Version-List
//
// Example usage:
//
//	cfg := goheader.SecCHUAFullVersionListConfig{
//	    Brands: map[string]string{
//	        "Chromium":      "112.0.5615.137",
//	        "Google Chrome": "112.0.5615.137",
//	    },
//	}
//	header := goheader.NewSecCHUAFullVersionListHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Full-Version-List
//	fmt.Println(header.Values) // ["\"Chromium\";v=\"112.0.5615.137\", \"Google Chrome\";v=\"112.0.5615.137\""]
func NewSecCHUAFullVersionListHeader(cfg SecCHUAFullVersionListConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAFullVersionList,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAMobileConfig defines the configuration for the Sec-CH-UA-Mobile header.
type SecCHUAMobileConfig struct {
	IsMobile bool // true = ?1, false = ?0
}

// String renders the Sec-CH-UA-Mobile header value.
func (cfg SecCHUAMobileConfig) String() string {
	if cfg.IsMobile {
		return "?1"
	}
	return "?0"
}

// NewSecCHUAMobileHeader creates a new Sec-CH-UA-Mobile header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Mobile
//
// Example usage:
//
//	cfg := goheader.SecCHUAMobileConfig{IsMobile: true}
//	header := goheader.NewSecCHUAMobileHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Mobile
//	fmt.Println(header.Values) // ["?1"]
func NewSecCHUAMobileHeader(cfg SecCHUAMobileConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAMobile,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAModelConfig defines the configuration for the Sec-CH-UA-Model header.
type SecCHUAModelConfig struct {
	Model string // e.g., "Pixel 6"
}

// String renders the Sec-CH-UA-Model header value.
func (cfg SecCHUAModelConfig) String() string {
	return `"` + cfg.Model + `"`
}

// NewSecCHUAModelHeader creates a new Sec-CH-UA-Model header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Model
//
// Example usage:
//
//	cfg := goheader.SecCHUAModelConfig{Model: "Pixel 6"}
//	header := goheader.NewSecCHUAModelHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Model
//	fmt.Println(header.Values) // ["\"Pixel 6\""]
func NewSecCHUAModelHeader(cfg SecCHUAModelConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAModel,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAPlatformConfig defines the configuration for the Sec-CH-UA-Platform header.
type SecCHUAPlatformConfig struct {
	Platform string // e.g., "Windows", "Android", "iOS"
}

// String renders the Sec-CH-UA-Platform header value.
func (cfg SecCHUAPlatformConfig) String() string {
	return `"` + cfg.Platform + `"`
}

// NewSecCHUAPlatformHeader creates a new Sec-CH-UA-Platform header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Platform
//
// Example usage:
//
//	cfg := goheader.SecCHUAPlatformConfig{Platform: "Windows"}
//	header := goheader.NewSecCHUAPlatformHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Platform
//	fmt.Println(header.Values) // ["\"Windows\""]
func NewSecCHUAPlatformHeader(cfg SecCHUAPlatformConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAPlatform,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAPlatformVersionConfig defines the configuration for the Sec-CH-UA-Platform-Version header.
type SecCHUAPlatformVersionConfig struct {
	Version string // e.g., "15.4"
}

// String renders the Sec-CH-UA-Platform-Version header value.
func (cfg SecCHUAPlatformVersionConfig) String() string {
	return `"` + cfg.Version + `"`
}

// NewSecCHUAPlatformVersionHeader creates a new Sec-CH-UA-Platform-Version header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Platform-Version
//
// Example usage:
//
//	cfg := goheader.SecCHUAPlatformVersionConfig{Version: "15.4"}
//	header := goheader.NewSecCHUAPlatformVersionHeader(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-Platform-Version
//	fmt.Println(header.Values) // ["\"15.4\""]
func NewSecCHUAPlatformVersionHeader(cfg SecCHUAPlatformVersionConfig) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAPlatformVersion,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecCHUAWoW64Config defines the configuration for the Sec-CH-UA-WoW64 header.
type SecCHUAWoW64Config struct {
	WoW64 bool // true = ?1, false = ?0
}

// String renders the Sec-CH-UA-WoW64 header value.
func (cfg SecCHUAWoW64Config) String() string {
	if cfg.WoW64 {
		return "?1"
	}
	return "?0"
}

// NewSecCHUAWoW64Header creates a new Sec-CH-UA-WoW64 header from the config.
// More information: https://wicg.github.io/ua-client-hints/#sec-ch-ua-wow64
//
// Example usage:
//
//	cfg := goheader.SecCHUAWoW64Config{WoW64: true}
//	header := goheader.NewSecCHUAWoW64Header(cfg)
//	fmt.Println(header.Name)   // Sec-CH-UA-WoW64
//	fmt.Println(header.Values) // ["?1"]
func NewSecCHUAWoW64Header(cfg SecCHUAWoW64Config) Header {
	return Header{
		Experimental: true, // Client Hints are still evolving
		Name:         SecCHUAWoW64,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecFetchDestConfig defines the configuration for the Sec-Fetch-Dest header.
type SecFetchDestConfig struct {
	Destination string // e.g., "script", "image", "document"
}

// String renders the Sec-Fetch-Dest header value.
func (cfg SecFetchDestConfig) String() string {
	return cfg.Destination
}

// NewSecFetchDestHeader creates a new Sec-Fetch-Dest header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest
//
// Example usage:
//
//	cfg := goheader.SecFetchDestConfig{Destination: "script"}
//	header := goheader.NewSecFetchDestHeader(cfg)
//	fmt.Println(header.Name)   // Sec-Fetch-Dest
//	fmt.Println(header.Values) // ["script"]
func NewSecFetchDestHeader(cfg SecFetchDestConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchDest,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecFetchModeConfig defines the configuration for the Sec-Fetch-Mode header.
type SecFetchModeConfig struct {
	Mode string // e.g., "cors", "no-cors", "navigate"
}

// String renders the Sec-Fetch-Mode header value.
func (cfg SecFetchModeConfig) String() string {
	return cfg.Mode
}

// NewSecFetchModeHeader creates a new Sec-Fetch-Mode header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode
//
// Example usage:
//
//	cfg := goheader.SecFetchModeConfig{Mode: "cors"}
//	header := goheader.NewSecFetchModeHeader(cfg)
//	fmt.Println(header.Name)   // Sec-Fetch-Mode
//	fmt.Println(header.Values) // ["cors"]
func NewSecFetchModeHeader(cfg SecFetchModeConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchMode,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecFetchSiteConfig defines the configuration for the Sec-Fetch-Site header.
type SecFetchSiteConfig struct {
	Site string // e.g., "same-origin", "cross-site"
}

// String renders the Sec-Fetch-Site header value.
func (cfg SecFetchSiteConfig) String() string {
	return cfg.Site
}

// NewSecFetchSiteHeader creates a new Sec-Fetch-Site header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
//
// Example usage:
//
//	cfg := goheader.SecFetchSiteConfig{Site: "same-origin"}
//	header := goheader.NewSecFetchSiteHeader(cfg)
//	fmt.Println(header.Name)   // Sec-Fetch-Site
//	fmt.Println(header.Values) // ["same-origin"]
func NewSecFetchSiteHeader(cfg SecFetchSiteConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchSite,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecFetchUserConfig defines the configuration for the Sec-Fetch-User header.
type SecFetchUserConfig struct {
	Activated bool // true = ?1, false = header omitted
}

// String renders the Sec-Fetch-User header value.
func (cfg SecFetchUserConfig) String() string {
	if cfg.Activated {
		return "?1"
	}
	return ""
}

// NewSecFetchUserHeader creates a new Sec-Fetch-User header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-User
//
// Example usage:
//
//	cfg := goheader.SecFetchUserConfig{Activated: true}
//	header := goheader.NewSecFetchUserHeader(cfg)
//	fmt.Println(header.Name)   // Sec-Fetch-User
//	fmt.Println(header.Values) // ["?1"]
func NewSecFetchUserHeader(cfg SecFetchUserConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchUser,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecGPCConfig defines the configuration for the Sec-GPC header.
type SecGPCConfig struct {
	Enabled bool // true = 1, false = header omitted
}

// String renders the Sec-GPC header value.
func (cfg SecGPCConfig) String() string {
	if cfg.Enabled {
		return "1"
	}
	return ""
}

// NewSecGPCHeader creates a new Sec-GPC header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-GPC
//
// Example usage:
//
//	cfg := goheader.SecGPCConfig{Enabled: true}
//	header := goheader.NewSecGPCHeader(cfg)
//	fmt.Println(header.Name)   // Sec-GPC
//	fmt.Println(header.Values) // ["1"]
func NewSecGPCHeader(cfg SecGPCConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecGPC,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecPurposeConfig defines the configuration for the Sec-Purpose header.
type SecPurposeConfig struct {
	Purpose string // e.g., "prefetch"
}

// String renders the Sec-Purpose header value.
func (cfg SecPurposeConfig) String() string {
	return cfg.Purpose
}

// NewSecPurposeHeader creates a new Sec-Purpose header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Purpose
//
// Example usage:
//
//	cfg := goheader.SecPurposeConfig{Purpose: "prefetch"}
//	header := goheader.NewSecPurposeHeader(cfg)
//	fmt.Println(header.Name)   // Sec-Purpose
//	fmt.Println(header.Values) // ["prefetch"]
func NewSecPurposeHeader(cfg SecPurposeConfig) Header {
	return Header{
		Experimental: true, // still relatively new
		Name:         SecPurpose,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// SecWebSocketAcceptConfig defines the configuration for the Sec-WebSocket-Accept header.
type SecWebSocketAcceptConfig struct {
	Token string // The computed Sec-WebSocket-Accept token
}

// String renders the Sec-WebSocket-Accept header value.
func (cfg SecWebSocketAcceptConfig) String() string {
	return cfg.Token
}

// NewSecWebSocketAcceptHeader creates a new Sec-WebSocket-Accept header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Accept
//
// Example usage:
//
//	cfg := goheader.SecWebSocketAcceptConfig{Token: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}
//	header := goheader.NewSecWebSocketAcceptHeader(cfg)
//	fmt.Println(header.Name)   // Sec-WebSocket-Accept
//	fmt.Println(header.Values) // ["s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]
func NewSecWebSocketAcceptHeader(cfg SecWebSocketAcceptConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecWebSocketAccept,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecWebSocketExtensionsConfig defines the configuration for the Sec-WebSocket-Extensions header.
type SecWebSocketExtensionsConfig struct {
	Extensions []string // e.g., []string{"permessage-deflate", "client_max_window_bits"}
}

// String renders the Sec-WebSocket-Extensions header value.
func (cfg SecWebSocketExtensionsConfig) String() string {
	return strings.Join(cfg.Extensions, ", ")
}

// NewSecWebSocketExtensionsHeader creates a new Sec-WebSocket-Extensions header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Extensions
//
// Example usage:
//
//	cfg := goheader.SecWebSocketExtensionsConfig{
//	    Extensions: []string{"permessage-deflate", "client_max_window_bits"},
//	}
//	header := goheader.NewSecWebSocketExtensionsHeader(cfg)
//	fmt.Println(header.Name)   // Sec-WebSocket-Extensions
//	fmt.Println(header.Values) // ["permessage-deflate, client_max_window_bits"]
func NewSecWebSocketExtensionsHeader(cfg SecWebSocketExtensionsConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecWebSocketExtensions,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecWebSocketKeyConfig defines the configuration for the Sec-WebSocket-Key header.
type SecWebSocketKeyConfig struct {
	Key string // base64-encoded random nonce, e.g., "dGhlIHNhbXBsZSBub25jZQ=="
}

// String renders the Sec-WebSocket-Key header value.
func (cfg SecWebSocketKeyConfig) String() string {
	return cfg.Key
}

// NewSecWebSocketKeyHeader creates a new Sec-WebSocket-Key header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Key
//
// Example usage:
//
//	cfg := goheader.SecWebSocketKeyConfig{Key: "dGhlIHNhbXBsZSBub25jZQ=="}
//	header := goheader.NewSecWebSocketKeyHeader(cfg)
//	fmt.Println(header.Name)   // Sec-WebSocket-Key
//	fmt.Println(header.Values) // ["dGhlIHNhbXBsZSBub25jZQ=="]
func NewSecWebSocketKeyHeader(cfg SecWebSocketKeyConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecWebSocketKey,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecWebSocketProtocolConfig defines the configuration for the Sec-WebSocket-Protocol header.
type SecWebSocketProtocolConfig struct {
	Protocols []string // e.g., []string{"chat", "superchat"}
}

// String renders the Sec-WebSocket-Protocol header value.
func (cfg SecWebSocketProtocolConfig) String() string {
	return strings.Join(cfg.Protocols, ", ")
}

// NewSecWebSocketProtocolHeader creates a new Sec-WebSocket-Protocol header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Protocol
//
// Example usage:
//
//	cfg := goheader.SecWebSocketProtocolConfig{Protocols: []string{"chat", "superchat"}}
//	header := goheader.NewSecWebSocketProtocolHeader(cfg)
//	fmt.Println(header.Name)   // Sec-WebSocket-Protocol
//	fmt.Println(header.Values) // ["chat, superchat"]
func NewSecWebSocketProtocolHeader(cfg SecWebSocketProtocolConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecWebSocketProtocol,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SecWebSocketVersionConfig defines the configuration for the Sec-WebSocket-Version header.
type SecWebSocketVersionConfig struct {
	Version string // e.g., "13"
}

// String renders the Sec-WebSocket-Version header value.
func (cfg SecWebSocketVersionConfig) String() string {
	return cfg.Version
}

// NewSecWebSocketVersionHeader creates a new Sec-WebSocket-Version header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Version
//
// Example usage:
//
//	cfg := goheader.SecWebSocketVersionConfig{Version: "13"}
//	header := goheader.NewSecWebSocketVersionHeader(cfg)
//	fmt.Println(header.Name)   // Sec-WebSocket-Version
//	fmt.Println(header.Values) // ["13"]
func NewSecWebSocketVersionHeader(cfg SecWebSocketVersionConfig) Header {
	return Header{
		Experimental: false,
		Name:         SecWebSocketVersion,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ServerConfig defines the configuration for the Server header.
type ServerConfig struct {
	Info string // e.g., "Apache/2.4.1 (Unix)"
}

// String renders the Server header value.
func (cfg ServerConfig) String() string {
	return cfg.Info
}

// NewServerHeader creates a new Server header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server
//
// Example usage:
//
//	cfg := goheader.ServerConfig{Info: "Apache/2.4.1 (Unix)"}
//	header := goheader.NewServerHeader(cfg)
//	fmt.Println(header.Name)   // Server
//	fmt.Println(header.Values) // ["Apache/2.4.1 (Unix)"]
func NewServerHeader(cfg ServerConfig) Header {
	return Header{
		Experimental: false,
		Name:         Server,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ServerTimingMetric represents a single metric in the Server-Timing header.
type ServerTimingMetric struct {
	Name     string  // e.g., "db"
	Duration float64 // e.g., 53.0
	Desc     string  // Optional description, e.g., "Database query time"
}

// ServerTimingConfig defines the configuration for the Server-Timing header.
type ServerTimingConfig struct {
	Metrics []ServerTimingMetric
}

// String renders the Server-Timing header value.
func (cfg ServerTimingConfig) String() string {
	var parts []string
	for _, m := range cfg.Metrics {
		metric := m.Name
		if m.Duration > 0 {
			metric += fmt.Sprintf(";dur=%.2f", m.Duration)
		}
		if m.Desc != "" {
			metric += fmt.Sprintf(`;desc="%s"`, m.Desc)
		}
		parts = append(parts, metric)
	}
	return strings.Join(parts, ", ")
}

// NewServerTimingHeader creates a new Server-Timing header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing
//
// Example usage:
//
//	cfg := goheader.ServerTimingConfig{
//	    Metrics: []goheader.ServerTimingMetric{
//	        {Name: "db", Duration: 53, Desc: "Database query"},
//	        {Name: "app", Duration: 47.2},
//	    },
//	}
//	header := goheader.NewServerTimingHeader(cfg)
//	fmt.Println(header.Name)   // Server-Timing
//	fmt.Println(header.Values) // ["db;dur=53.00;desc=\"Database query\", app;dur=47.20"]
func NewServerTimingHeader(cfg ServerTimingConfig) Header {
	return Header{
		Experimental: false,
		Name:         ServerTiming,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ServiceWorkerNavigationPreloadConfig defines the configuration for the Service-Worker-Navigation-Preload header.
type ServiceWorkerNavigationPreloadConfig struct {
	Enabled bool // true = "true", false = "false"
}

// String renders the Service-Worker-Navigation-Preload header value.
func (cfg ServiceWorkerNavigationPreloadConfig) String() string {
	if cfg.Enabled {
		return "true"
	}
	return "false"
}

// NewServiceWorkerNavigationPreloadHeader creates a new Service-Worker-Navigation-Preload header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Service-Worker-Navigation-Preload
//
// Example usage:
//
//	cfg := goheader.ServiceWorkerNavigationPreloadConfig{Enabled: true}
//	header := goheader.NewServiceWorkerNavigationPreloadHeader(cfg)
//	fmt.Println(header.Name)   // Service-Worker-Navigation-Preload
//	fmt.Println(header.Values) // ["true"]
func NewServiceWorkerNavigationPreloadHeader(cfg ServiceWorkerNavigationPreloadConfig) Header {
	return Header{
		Experimental: false,
		Name:         ServiceWorkerNavigationPreload,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SetCookieConfig defines the configuration for the Set-Cookie header.
type SetCookieConfig struct {
	Name     string     // e.g., "sessionId"
	Value    string     // e.g., "abc123"
	Expires  *time.Time // Optional expiration date
	MaxAge   int        // Optional Max-Age in seconds
	Domain   string     // Optional Domain
	Path     string     // Optional Path
	Secure   bool       // Secure flag
	HTTPOnly bool       // HTTPOnly flag
	SameSite string     // Optional: "Strict", "Lax", "None"
}

// String renders the Set-Cookie header value.
func (cfg SetCookieConfig) String() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%s=%s", cfg.Name, cfg.Value))

	if cfg.Expires != nil {
		parts = append(parts, "Expires="+cfg.Expires.UTC().Format(time.RFC1123))
	}
	if cfg.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("Max-Age=%d", cfg.MaxAge))
	}
	if cfg.Domain != "" {
		parts = append(parts, "Domain="+cfg.Domain)
	}
	if cfg.Path != "" {
		parts = append(parts, "Path="+cfg.Path)
	}
	if cfg.Secure {
		parts = append(parts, "Secure")
	}
	if cfg.HTTPOnly {
		parts = append(parts, "HTTPOnly")
	}
	if cfg.SameSite != "" {
		parts = append(parts, "SameSite="+cfg.SameSite)
	}

	return strings.Join(parts, "; ")
}

// NewSetCookieHeader creates a new Set-Cookie header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
//
// Example usage:
//
//	expires := time.Now().Add(24 * time.Hour)
//	cfg := goheader.SetCookieConfig{
//	    Name: "sessionId", Value: "abc123", Expires: &expires,
//	    Path: "/", Secure: true, HTTPOnly: true, SameSite: "Strict",
//	}
//	header := goheader.NewSetCookieHeader(cfg)
//	fmt.Println(header.Name)   // Set-Cookie
//	fmt.Println(header.Values) // ["sessionId=abc123; Expires=...; Path=/; Secure; HTTPOnly; SameSite=Strict"]
func NewSetCookieHeader(cfg SetCookieConfig) Header {
	return Header{
		Experimental: false,
		Name:         SetCookie,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SourceMapConfig defines the configuration for the SourceMap header.
type SourceMapConfig struct {
	URL string // URL or path to the source map file
}

// String renders the SourceMap header value.
func (cfg SourceMapConfig) String() string {
	return cfg.URL
}

// NewSourceMapHeader creates a new SourceMap header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/SourceMap
//
// Example usage:
//
//	cfg := goheader.SourceMapConfig{URL: "/path/to/file.js.map"}
//	header := goheader.NewSourceMapHeader(cfg)
//	fmt.Println(header.Name)   // SourceMap
//	fmt.Println(header.Values) // ["/path/to/file.js.map"]
func NewSourceMapHeader(cfg SourceMapConfig) Header {
	return Header{
		Experimental: false,
		Name:         SourceMap,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// StatusConfig defines the configuration for the Status header.
type StatusConfig struct {
	Code   int    // e.g., 200
	Reason string // e.g., "OK"
}

// String renders the Status header value.
func (cfg StatusConfig) String() string {
	if cfg.Reason != "" {
		return fmt.Sprintf("%d %s", cfg.Code, cfg.Reason)
	}
	return fmt.Sprintf("%d", cfg.Code)
}

// NewStatusHeader creates a new Status header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Status
//
// Example usage:
//
//	cfg := goheader.StatusConfig{Code: 200, Reason: "OK"}
//	header := goheader.NewStatusHeader(cfg)
//	fmt.Println(header.Name)   // Status
//	fmt.Println(header.Values) // ["200 OK"]
func NewStatusHeader(cfg StatusConfig) Header {
	return Header{
		Experimental: false,
		Name:         Status,
		Request:      false,
		Response:     true,
		Standard:     false, // Legacy / non-standard header
		Values:       []string{cfg.String()},
	}
}

// StrictTransportSecurityConfig defines the configuration for the Strict-Transport-Security header.
type StrictTransportSecurityConfig struct {
	MaxAge            int  // Required: number of seconds the browser should remember to only use HTTPS
	IncludeSubDomains bool // Optional: apply to all subdomains
	Preload           bool // Optional: request inclusion in browsers' preload lists
}

// String renders the Strict-Transport-Security header value.
func (cfg StrictTransportSecurityConfig) String() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("max-age=%d", cfg.MaxAge))
	if cfg.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}
	if cfg.Preload {
		parts = append(parts, "preload")
	}
	return strings.Join(parts, "; ")
}

// NewStrictTransportSecurityHeader creates a new Strict-Transport-Security header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
//
// Example usage:
//
//	cfg := goheader.StrictTransportSecurityConfig{
//	    MaxAge: 31536000, IncludeSubDomains: true, Preload: true,
//	}
//	header := goheader.NewStrictTransportSecurityHeader(cfg)
//	fmt.Println(header.Name)   // Strict-Transport-Security
//	fmt.Println(header.Values) // ["max-age=31536000; includeSubDomains; preload"]
func NewStrictTransportSecurityHeader(cfg StrictTransportSecurityConfig) Header {
	return Header{
		Experimental: false,
		Name:         StrictTransportSecurity,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// SupportsLoadingModeConfig defines the configuration for the Supports-Loading-Mode header.
type SupportsLoadingModeConfig struct {
	Mode string // e.g., "credentialed-prerender"
}

// String renders the Supports-Loading-Mode header value.
func (cfg SupportsLoadingModeConfig) String() string {
	return cfg.Mode
}

// NewSupportsLoadingModeHeader creates a new Supports-Loading-Mode header from the config.
// More information: https://wicg.github.io/priority-hints/#supports-loading-mode
//
// Example usage:
//
//	cfg := goheader.SupportsLoadingModeConfig{Mode: "credentialed-prerender"}
//	header := goheader.NewSupportsLoadingModeHeader(cfg)
//	fmt.Println(header.Name)   // Supports-Loading-Mode
//	fmt.Println(header.Values) // ["credentialed-prerender"]
func NewSupportsLoadingModeHeader(cfg SupportsLoadingModeConfig) Header {
	return Header{
		Experimental: true,
		Name:         SupportsLoadingMode,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// TEConfig defines the configuration for the TE header.
type TEConfig struct {
	Encodings []string // e.g., []string{"trailers", "deflate"}
}

// String renders the TE header value.
func (cfg TEConfig) String() string {
	return strings.Join(cfg.Encodings, ", ")
}

// NewTEHeader creates a new TE header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/TE
//
// Example usage:
//
//	cfg := goheader.TEConfig{Encodings: []string{"trailers", "deflate"}}
//	header := goheader.NewTEHeader(cfg)
//	fmt.Println(header.Name)   // TE
//	fmt.Println(header.Values) // ["trailers, deflate"]
func NewTEHeader(cfg TEConfig) Header {
	return Header{
		Experimental: false,
		Name:         TE,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// TKConfig defines the configuration for the TK header.
type TKConfig struct {
	Status string // e.g., "!", "G", "N", "T", "C", "P", "D"
}

// String renders the TK header value.
func (cfg TKConfig) String() string {
	return cfg.Status
}

// NewTKHeader creates a new TK header from the config.
// More information: https://www.w3.org/TR/tracking-dnt/#response-header-field
//
// Example usage:
//
//	cfg := goheader.TKConfig{Status: "!"}
//	header := goheader.NewTKHeader(cfg)
//	fmt.Println(header.Name)   // TK
//	fmt.Println(header.Values) // ["!"]
func NewTKHeader(cfg TKConfig) Header {
	return Header{
		Experimental: false,
		Name:         TK,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// TimingAllowOriginConfig defines the configuration for the Timing-Allow-Origin header.
type TimingAllowOriginConfig struct {
	Origins []string // e.g., []string{"https://example.com", "https://cdn.example.com"} or []string{"*"}
}

// String renders the Timing-Allow-Origin header value.
func (cfg TimingAllowOriginConfig) String() string {
	return strings.Join(cfg.Origins, ", ")
}

// NewTimingAllowOriginHeader creates a new Timing-Allow-Origin header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Timing-Allow-Origin
//
// Example usage:
//
//	cfg := goheader.TimingAllowOriginConfig{
//	    Origins: []string{"https://example.com", "https://cdn.example.com"},
//	}
//	header := goheader.NewTimingAllowOriginHeader(cfg)
//	fmt.Println(header.Name)   // Timing-Allow-Origin
//	fmt.Println(header.Values) // ["https://example.com, https://cdn.example.com"]
func NewTimingAllowOriginHeader(cfg TimingAllowOriginConfig) Header {
	return Header{
		Experimental: false,
		Name:         TimingAllowOrigin,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// TrailerConfig defines the configuration for the Trailer header.
type TrailerConfig struct {
	Fields []string // e.g., []string{"Expires", "Content-MD5"}
}

// String renders the Trailer header value.
func (cfg TrailerConfig) String() string {
	return strings.Join(cfg.Fields, ", ")
}

// NewTrailerHeader creates a new Trailer header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
//
// Example usage:
//
//	cfg := goheader.TrailerConfig{Fields: []string{"Expires", "Content-MD5"}}
//	header := goheader.NewTrailerHeader(cfg)
//	fmt.Println(header.Name)   // Trailer
//	fmt.Println(header.Values) // ["Expires, Content-MD5"]
func NewTrailerHeader(cfg TrailerConfig) Header {
	return Header{
		Experimental: false,
		Name:         Trailer,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// TransferEncodingConfig defines the configuration for the Transfer-Encoding header.
type TransferEncodingConfig struct {
	Encodings []string // e.g., []string{"chunked", "gzip"}
}

// String renders the Transfer-Encoding header value.
func (cfg TransferEncodingConfig) String() string {
	return strings.Join(cfg.Encodings, ", ")
}

// NewTransferEncodingHeader creates a new Transfer-Encoding header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
//
// Example usage:
//
//	cfg := goheader.TransferEncodingConfig{Encodings: []string{"chunked"}}
//	header := goheader.NewTransferEncodingHeader(cfg)
//	fmt.Println(header.Name)   // Transfer-Encoding
//	fmt.Println(header.Values) // ["chunked"]
func NewTransferEncodingHeader(cfg TransferEncodingConfig) Header {
	return Header{
		Experimental: false,
		Name:         TransferEncoding,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// UpgradeConfig defines the configuration for the Upgrade header.
type UpgradeConfig struct {
	Protocols []string // e.g., []string{"websocket", "h2c"}
}

// String renders the Upgrade header value.
func (cfg UpgradeConfig) String() string {
	return strings.Join(cfg.Protocols, ", ")
}

// NewUpgradeHeader creates a new Upgrade header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade
//
// Example usage:
//
//	cfg := goheader.UpgradeConfig{Protocols: []string{"websocket"}}
//	header := goheader.NewUpgradeHeader(cfg)
//	fmt.Println(header.Name)   // Upgrade
//	fmt.Println(header.Values) // ["websocket"]
func NewUpgradeHeader(cfg UpgradeConfig) Header {
	return Header{
		Experimental: false,
		Name:         Upgrade,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// UpgradeInsecureRequestsConfig defines the configuration for the Upgrade-Insecure-Requests header.
type UpgradeInsecureRequestsConfig struct {
	PreferSecure bool // true means send "1", false means no preference
}

// String renders the Upgrade-Insecure-Requests header value.
func (cfg UpgradeInsecureRequestsConfig) String() string {
	if cfg.PreferSecure {
		return "1"
	}
	return ""
}

// NewUpgradeInsecureRequestsHeader creates a new Upgrade-Insecure-Requests header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade-Insecure-Requests
//
// Example usage:
//
//	cfg := goheader.UpgradeInsecureRequestsConfig{PreferSecure: true}
//	header := goheader.NewUpgradeInsecureRequestsHeader(cfg)
//	fmt.Println(header.Name)   // Upgrade-Insecure-Requests
//	fmt.Println(header.Values) // ["1"]
func NewUpgradeInsecureRequestsHeader(cfg UpgradeInsecureRequestsConfig) Header {
	return Header{
		Experimental: false,
		Name:         UpgradeInsecureRequests,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// UrgencyConfig defines the configuration for the Urgency header.
type UrgencyConfig struct {
	Level       int  // e.g., 0 (highest) to N (lower priority)
	Progressive bool // optional: whether progressive rendering is allowed
}

// String renders the Urgency header value.
func (cfg UrgencyConfig) String() string {
	parts := []string{fmt.Sprintf("%d", cfg.Level)}
	if cfg.Progressive {
		parts = append(parts, "progressive=?1")
	}
	return strings.Join(parts, "; ")
}

// NewUrgencyHeader creates a new Urgency header from the config.
// More information: https://www.rfc-editor.org/rfc/rfc9218.html
//
// Example usage:
//
//	cfg := goheader.UrgencyConfig{Level: 1, Progressive: true}
//	header := goheader.NewUrgencyHeader(cfg)
//	fmt.Println(header.Name)   // Urgency
//	fmt.Println(header.Values) // ["1; progressive=?1"]
func NewUrgencyHeader(cfg UrgencyConfig) Header {
	return Header{
		Experimental: true,
		Name:         Urgency,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       []string{cfg.String()},
	}
}

// UserAgentConfig defines the configuration for the User-Agent header.
type UserAgentConfig struct {
	Agent string // Full User-Agent string
}

// String renders the User-Agent header value.
func (cfg UserAgentConfig) String() string {
	return cfg.Agent
}

// NewUserAgentHeader creates a new User-Agent header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
//
// Example usage:
//
//	cfg := goheader.UserAgentConfig{Agent: "MyApp/1.0"}
//	header := goheader.NewUserAgentHeader(cfg)
//	fmt.Println(header.Name)   // User-Agent
//	fmt.Println(header.Values) // ["MyApp/1.0"]
func NewUserAgentHeader(cfg UserAgentConfig) Header {
	return Header{
		Experimental: false,
		Name:         UserAgent,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// VariantKeyConfig defines the configuration for the Variant-Key header.
type VariantKeyConfig struct {
	Keys []string // e.g., []string{"lang=en", "user=mobile"}
}

// String renders the Variant-Key header value.
func (cfg VariantKeyConfig) String() string {
	return strings.Join(cfg.Keys, "; ")
}

// NewVariantKeyHeader creates a new Variant-Key header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Variant-Key
//
// Example usage:
//
//	cfg := goheader.VariantKeyConfig{Keys: []string{"lang=en", "user=mobile"}}
//	header := goheader.NewVariantKeyHeader(cfg)
//	fmt.Println(header.Name)   // Variant-Key
//	fmt.Println(header.Values) // ["lang=en; user=mobile"]
func NewVariantKeyHeader(cfg VariantKeyConfig) Header {
	return Header{
		Experimental: false,
		Name:         VariantKey,
		Request:      false,
		Response:     true,
		Standard:     false, // Still experimental in some contexts
		Values:       []string{cfg.String()},
	}
}

// VaryConfig defines the configuration for the Vary header.
type VaryConfig struct {
	Headers []string // e.g., []string{"Accept-Encoding", "User-Agent"}
}

// String renders the Vary header value.
func (cfg VaryConfig) String() string {
	return strings.Join(cfg.Headers, ", ")
}

// NewVaryHeader creates a new Vary header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
//
// Example usage:
//
//	cfg := goheader.VaryConfig{Headers: []string{"Accept-Encoding", "User-Agent"}}
//	header := goheader.NewVaryHeader(cfg)
//	fmt.Println(header.Name)   // Vary
//	fmt.Println(header.Values) // ["Accept-Encoding, User-Agent"]
func NewVaryHeader(cfg VaryConfig) Header {
	return Header{
		Experimental: false,
		Name:         Vary,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ViaConfig defines the configuration for the Via header.
type ViaConfig struct {
	Entries []string // e.g., []string{"1.1 vegur", "2.0 proxy.example.com"}
}

// String renders the Via header value.
func (cfg ViaConfig) String() string {
	return strings.Join(cfg.Entries, ", ")
}

// NewViaHeader creates a new Via header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via
//
// Example usage:
//
//	cfg := goheader.ViaConfig{Entries: []string{"1.1 vegur"}}
//	header := goheader.NewViaHeader(cfg)
//	fmt.Println(header.Name)   // Via
//	fmt.Println(header.Values) // ["1.1 vegur"]
func NewViaHeader(cfg ViaConfig) Header {
	return Header{
		Experimental: false,
		Name:         Via,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// ViewportWidthConfig defines the configuration for the Viewport-Width header.
type ViewportWidthConfig struct {
	Width int // Width of the layout viewport in CSS pixels
}

// String renders the Viewport-Width header value.
func (cfg ViewportWidthConfig) String() string {
	if cfg.Width > 0 {
		return fmt.Sprintf("%d", cfg.Width)
	}
	return ""
}

// NewViewportWidthHeader creates a new Viewport-Width header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Viewport-Width
//
// Example usage:
//
//	cfg := goheader.ViewportWidthConfig{Width: 1080}
//	header := goheader.NewViewportWidthHeader(cfg)
//	fmt.Println(header.Name)   // Viewport-Width
//	fmt.Println(header.Values) // ["1080"]
func NewViewportWidthHeader(cfg ViewportWidthConfig) Header {
	return Header{
		Experimental: false,
		Name:         ViewportWidth,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// WWWAuthenticateConfig defines the configuration for the WWW-Authenticate header.
type WWWAuthenticateConfig struct {
	Schemes []string // e.g., []string{`Basic realm="Access"`, `Bearer realm="example", error="invalid_token"`}
}

// String renders the WWW-Authenticate header value.
func (cfg WWWAuthenticateConfig) String() string {
	return strings.Join(cfg.Schemes, ", ")
}

// NewWWWAuthenticateHeader creates a new WWW-Authenticate header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
//
// Example usage:
//
//	cfg := goheader.WWWAuthenticateConfig{
//	    Schemes: []string{`Basic realm="Access to the staging site"`, `Bearer realm="example", error="invalid_token"`},
//	}
//	header := goheader.NewWWWAuthenticateHeader(cfg)
//	fmt.Println(header.Name)   // WWW-Authenticate
//	fmt.Println(header.Values) // [`Basic realm="Access to the staging site", Bearer realm="example", error="invalid_token"`]
func NewWWWAuthenticateHeader(cfg WWWAuthenticateConfig) Header {
	return Header{
		Experimental: false,
		Name:         WWWAuthenticate,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// WantDigestConfig defines the configuration for the Want-Digest header.
type WantDigestConfig struct {
	Algorithms []string // e.g., []string{"SHA-256", "MD5;q=0.3"}
}

// String renders the Want-Digest header value.
func (cfg WantDigestConfig) String() string {
	return strings.Join(cfg.Algorithms, ", ")
}

// NewWantDigestHeader creates a new Want-Digest header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Want-Digest
//
// Example usage:
//
//	cfg := goheader.WantDigestConfig{Algorithms: []string{"SHA-256", "MD5;q=0.3"}}
//	header := goheader.NewWantDigestHeader(cfg)
//	fmt.Println(header.Name)   // Want-Digest
//	fmt.Println(header.Values) // ["SHA-256, MD5;q=0.3"]
func NewWantDigestHeader(cfg WantDigestConfig) Header {
	return Header{
		Experimental: false,
		Name:         WantDigest,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// WarningEntry represents a single Warning header entry.
type WarningEntry struct {
	Code  int        // Warning code (e.g., 110, 112)
	Agent string     // Agent generating the warning (can be "-" if unknown)
	Text  string     // Descriptive warning text
	Date  *time.Time // Optional date in IMF-fixdate format
}

// String renders a single Warning header entry.
func (w WarningEntry) String() string {
	agent := w.Agent
	if agent == "" {
		agent = "-"
	}
	if w.Date != nil {
		return fmt.Sprintf("%d %s %q %q", w.Code, agent, w.Text, w.Date.UTC().Format(time.RFC1123))
	}
	return fmt.Sprintf("%d %s %q", w.Code, agent, w.Text)
}

// WarningConfig defines the configuration for the Warning header.
type WarningConfig struct {
	Entries []WarningEntry
}

// String renders the Warning header value.
func (cfg WarningConfig) String() string {
	parts := []string{}
	for _, entry := range cfg.Entries {
		parts = append(parts, entry.String())
	}
	return strings.Join(parts, ", ")
}

// NewWarningHeader creates a new Warning header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Warning
//
// Example usage:
//
//	now := time.Now()
//	cfg := goheader.WarningConfig{
//	    Entries: []goheader.WarningEntry{
//	        {Code: 110, Agent: "-", Text: "Response is stale"},
//	        {Code: 112, Agent: "example.com:8080", Text: "Disconnected operation", Date: &now},
//	    },
//	}
//	header := goheader.NewWarningHeader(cfg)
//	fmt.Println(header.Name)   // Warning
//	fmt.Println(header.Values) // ['110 - "Response is stale", 112 example.com:8080 "Disconnected operation" "Mon, 15 Sep 2025 15:00:00 GMT"']
func NewWarningHeader(cfg WarningConfig) Header {
	return Header{
		Experimental: false,
		Name:         Warning,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// WidthConfig defines the configuration for the Width header.
type WidthConfig struct {
	Pixels int // The intended display width in physical pixels
}

// String renders the Width header value.
func (cfg WidthConfig) String() string {
	if cfg.Pixels > 0 {
		return fmt.Sprintf("%d", cfg.Pixels)
	}
	return ""
}

// NewWidthHeader creates a new Width header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Width
//
// Example usage:
//
//	cfg := goheader.WidthConfig{Pixels: 1920}
//	header := goheader.NewWidthHeader(cfg)
//	fmt.Println(header.Name)   // Width
//	fmt.Println(header.Values) // ["1920"]
func NewWidthHeader(cfg WidthConfig) Header {
	return Header{
		Experimental: false,
		Name:         Width,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// XATTDeviceIDConfig defines the configuration for the X-ATT-DeviceId header.
type XATTDeviceIDConfig struct {
	DeviceID string // e.g., "GT-P7320/P7320XXLPG"
}

// String renders the X-ATT-DeviceId header value.
func (cfg XATTDeviceIDConfig) String() string {
	return cfg.DeviceID
}

// NewXATTDeviceIDHeader creates a new X-ATT-DeviceId header from the config.
// Note: This is a non-standard header, historically used by AT&T devices.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-ATT-DeviceId
//
// Example usage:
//
//	cfg := goheader.XATTDeviceIDConfig{DeviceID: "GT-P7320/P7320XXLPG"}
//	header := goheader.NewXATTDeviceIDHeader(cfg)
//	fmt.Println(header.Name)   // X-ATT-DeviceId
//	fmt.Println(header.Values) // ["GT-P7320/P7320XXLPG"]
func NewXATTDeviceIDHeader(cfg XATTDeviceIDConfig) Header {
	return Header{
		Experimental: false,
		Name:         XATTDeviceID,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard / deprecated
		Values:       []string{cfg.String()},
	}
}

// XContentDurationConfig defines the configuration for the X-Content-Duration header.
type XContentDurationConfig struct {
	Seconds float64 // Duration of the media resource in seconds (can be fractional)
}

// String renders the X-Content-Duration header value.
func (cfg XContentDurationConfig) String() string {
	if cfg.Seconds > 0 {
		return fmt.Sprintf("%.3f", cfg.Seconds)
	}
	return ""
}

// NewXContentDurationHeader creates a new X-Content-Duration header from the config.
// Note: This is a non-standard header, mainly used in media servers.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Duration
//
// Example usage:
//
//	cfg := goheader.XContentDurationConfig{Seconds: 215.3}
//	header := goheader.NewXContentDurationHeader(cfg)
//	fmt.Println(header.Name)   // X-Content-Duration
//	fmt.Println(header.Values) // ["215.300"]
func NewXContentDurationHeader(cfg XContentDurationConfig) Header {
	values := []string{}
	if v := cfg.String(); v != "" {
		values = append(values, v)
	}

	return Header{
		Experimental: false,
		Name:         XContentDuration,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard
		Values:       values,
	}
}

// XContentSecurityPolicyConfig defines the configuration for the X-Content-Security-Policy header.
type XContentSecurityPolicyConfig struct {
	Policy string // e.g., "default-src 'self'; script-src example.com"
}

// String renders the X-Content-Security-Policy header value.
func (cfg XContentSecurityPolicyConfig) String() string {
	return cfg.Policy
}

// NewXContentSecurityPolicyHeader creates a new X-Content-Security-Policy header from the config.
// Note: This header is deprecated. Use Content-Security-Policy instead.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Security-Policy
//
// Example usage:
//
//	cfg := goheader.XContentSecurityPolicyConfig{
//	    Policy: "default-src 'self'; script-src example.com",
//	}
//	header := goheader.NewXContentSecurityPolicyHeader(cfg)
//	fmt.Println(header.Name)   // X-Content-Security-Policy
//	fmt.Println(header.Values) // ["default-src 'self'; script-src example.com"]
func NewXContentSecurityPolicyHeader(cfg XContentSecurityPolicyConfig) Header {
	return Header{
		Experimental: false,
		Name:         XContentSecurityPolicy,
		Request:      false,
		Response:     true,
		Standard:     false, // Deprecated / non-standard
		Values:       []string{cfg.String()},
	}
}

// XContentTypeOptionsConfig defines the configuration for the X-Content-Type-Options header.
type XContentTypeOptionsConfig struct {
	NoSniff bool // If true, sets the header to "nosniff"
}

// String renders the X-Content-Type-Options header value.
func (cfg XContentTypeOptionsConfig) String() string {
	if cfg.NoSniff {
		return "nosniff"
	}
	return ""
}

// NewXContentTypeOptionsHeader creates a new X-Content-Type-Options header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
//
// Example usage:
//
//	cfg := goheader.XContentTypeOptionsConfig{NoSniff: true}
//	header := goheader.NewXContentTypeOptionsHeader(cfg)
//	fmt.Println(header.Name)   // X-Content-Type-Options
//	fmt.Println(header.Values) // ["nosniff"]
func NewXContentTypeOptionsHeader(cfg XContentTypeOptionsConfig) Header {
	return Header{
		Experimental: false,
		Name:         XContentTypeOptions,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// XCorrelationIDConfig defines the configuration for the X-Correlation-ID header.
type XCorrelationIDConfig struct {
	ID string // A unique correlation ID (often a UUID)
}

// String renders the X-Correlation-ID header value.
func (cfg XCorrelationIDConfig) String() string {
	return cfg.ID
}

// NewXCorrelationIDHeader creates a new X-Correlation-ID header from the config.
// Note: This is a non-standard header, but widely used in distributed systems.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Correlation-ID
//
// Example usage:
//
//	cfg := goheader.XCorrelationIDConfig{ID: "123e4567-e89b-12d3-a456-426614174000"}
//	header := goheader.NewXCorrelationIDHeader(cfg)
//	fmt.Println(header.Name)   // X-Correlation-ID
//	fmt.Println(header.Values) // ["123e4567-e89b-12d3-a456-426614174000"]
func NewXCorrelationIDHeader(cfg XCorrelationIDConfig) Header {
	return Header{
		Experimental: false,
		Name:         XCorrelationID,
		Request:      true,
		Response:     true,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XCSRFTokenConfig defines the configuration for the X-Csrf-Token header.
type XCSRFTokenConfig struct {
	Token string // CSRF token value
}

// String renders the X-Csrf-Token header value.
func (cfg XCSRFTokenConfig) String() string {
	return cfg.Token
}

// NewXCSRFTokenHeader creates a new X-Csrf-Token header from the config.
// Note: This is a non-standard security header used in CSRF protection schemes.
// More information: https://owasp.org/www-community/attacks/csrf
//
// Example usage:
//
//	cfg := goheader.XCSRFTokenConfig{Token: "9f8b7c6d-1234-5678-abcd-9876543210ef"}
//	header := goheader.NewXCSRFTokenHeader(cfg)
//	fmt.Println(header.Name)   // X-Csrf-Token
//	fmt.Println(header.Values) // ["9f8b7c6d-1234-5678-abcd-9876543210ef"]
func NewXCSRFTokenHeader(cfg XCSRFTokenConfig) Header {
	return Header{
		Experimental: false,
		Name:         XCSRFToken,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XDNSPrefetchControlConfig defines the configuration for the X-DNS-Prefetch-Control header.
type XDNSPrefetchControlConfig struct {
	Enable bool // true = "on", false = "off"
}

// String renders the X-DNS-Prefetch-Control header value.
func (cfg XDNSPrefetchControlConfig) String() string {
	if cfg.Enable {
		return "on"
	}
	return "off"
}

// NewXDNSPrefetchControlHeader creates a new X-DNS-Prefetch-Control header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control
//
// Example usage:
//
//	cfg := goheader.XDNSPrefetchControlConfig{Enable: false}
//	header := goheader.NewXDNSPrefetchControlHeader(cfg)
//	fmt.Println(header.Name)   // X-DNS-Prefetch-Control
//	fmt.Println(header.Values) // ["off"]
func NewXDNSPrefetchControlHeader(cfg XDNSPrefetchControlConfig) Header {
	return Header{
		Experimental: false,
		Name:         XDNSPrefetchControl,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard but widely supported
		Values:       []string{cfg.String()},
	}
}

// XForwardedForConfig defines the configuration for the X-Forwarded-For header.
type XForwardedForConfig struct {
	IPs []string // List of IP addresses, client first then proxies
}

// String renders the X-Forwarded-For header value.
func (cfg XForwardedForConfig) String() string {
	return strings.Join(cfg.IPs, ", ")
}

// NewXForwardedForHeader creates a new X-Forwarded-For header from the config.
// Note: This is a non-standard header, but widely used in proxy/load balancer setups.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
//
// Example usage:
//
//	cfg := goheader.XForwardedForConfig{
//	    IPs: []string{"203.0.113.195", "70.41.3.18", "150.172.238.178"},
//	}
//	header := goheader.NewXForwardedForHeader(cfg)
//	fmt.Println(header.Name)   // X-Forwarded-For
//	fmt.Println(header.Values) // ["203.0.113.195, 70.41.3.18, 150.172.238.178"]
func NewXForwardedForHeader(cfg XForwardedForConfig) Header {
	return Header{
		Experimental: false,
		Name:         XForwardedFor,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard but widely supported
		Values:       []string{cfg.String()},
	}
}

// XForwardedHostConfig defines the configuration for the X-Forwarded-Host header.
type XForwardedHostConfig struct {
	Host string // Original Host requested by the client
}

// String renders the X-Forwarded-Host header value.
func (cfg XForwardedHostConfig) String() string {
	return cfg.Host
}

// NewXForwardedHostHeader creates a new X-Forwarded-Host header from the config.
// Note: This is a non-standard header, but widely used in proxy/load balancer setups.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host
//
// Example usage:
//
//	cfg := goheader.XForwardedHostConfig{Host: "example.com"}
//	header := goheader.NewXForwardedHostHeader(cfg)
//	fmt.Println(header.Name)   // X-Forwarded-Host
//	fmt.Println(header.Values) // ["example.com"]
func NewXForwardedHostHeader(cfg XForwardedHostConfig) Header {
	return Header{
		Experimental: false,
		Name:         XForwardedHost,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard but widely supported
		Values:       []string{cfg.String()},
	}
}

// XForwardedProtoConfig defines the configuration for the X-Forwarded-Proto header.
type XForwardedProtoConfig struct {
	Proto string // Original protocol, e.g., "http" or "https"
}

// String renders the X-Forwarded-Proto header value.
func (cfg XForwardedProtoConfig) String() string {
	return cfg.Proto
}

// NewXForwardedProtoHeader creates a new X-Forwarded-Proto header from the config.
// Note: This is a non-standard header, but widely used in proxy/load balancer setups.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto
//
// Example usage:
//
//	cfg := goheader.XForwardedProtoConfig{Proto: "https"}
//	header := goheader.NewXForwardedProtoHeader(cfg)
//	fmt.Println(header.Name)   // X-Forwarded-Proto
//	fmt.Println(header.Values) // ["https"]
func NewXForwardedProtoHeader(cfg XForwardedProtoConfig) Header {
	return Header{
		Experimental: false,
		Name:         XForwardedProto,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard but widely supported
		Values:       []string{cfg.String()},
	}
}

// XFrameOptionsConfig defines the configuration for the X-Frame-Options header.
type XFrameOptionsConfig struct {
	Option string // "DENY", "SAMEORIGIN", or "ALLOW-FROM"
	URI    string // Required if Option == "ALLOW-FROM"
}

// String renders the X-Frame-Options header value.
func (cfg XFrameOptionsConfig) String() string {
	if cfg.Option == "ALLOW-FROM" && cfg.URI != "" {
		return fmt.Sprintf("%s %s", cfg.Option, cfg.URI)
	}
	return cfg.Option
}

// NewXFrameOptionsHeader creates a new X-Frame-Options header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
//
// Example usage:
//
//	cfg := goheader.XFrameOptionsConfig{Option: "SAMEORIGIN"}
//	header := goheader.NewXFrameOptionsHeader(cfg)
//	fmt.Println(header.Name)   // X-Frame-Options
//	fmt.Println(header.Values) // ["SAMEORIGIN"]
func NewXFrameOptionsHeader(cfg XFrameOptionsConfig) Header {
	return Header{
		Experimental: false,
		Name:         XFrameOptions,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       []string{cfg.String()},
	}
}

// XHTTPMethodOverrideConfig defines the configuration for the X-HTTP-Method-Override header.
type XHTTPMethodOverrideConfig struct {
	Method string // The HTTP method to override with, e.g., "PUT", "DELETE", "PATCH"
}

// String renders the X-HTTP-Method-Override header value.
func (cfg XHTTPMethodOverrideConfig) String() string {
	return cfg.Method
}

// NewXHTTPMethodOverrideHeader creates a new X-HTTP-Method-Override header from the config.
// Note: This is a non-standard header, but widely supported in APIs.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-HTTP-Method-Override
//
// Example usage:
//
//	cfg := goheader.XHTTPMethodOverrideConfig{Method: "DELETE"}
//	header := goheader.NewXHTTPMethodOverrideHeader(cfg)
//	fmt.Println(header.Name)   // X-HTTP-Method-Override
//	fmt.Println(header.Values) // ["DELETE"]
func NewXHTTPMethodOverrideHeader(cfg XHTTPMethodOverrideConfig) Header {
	return Header{
		Experimental: false,
		Name:         XHTTPMethodOverride,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XPermittedCrossDomainPoliciesConfig defines the configuration for the X-Permitted-Cross-Domain-Policies header.
type XPermittedCrossDomainPoliciesConfig struct {
	Policy string // "none", "master-only", "by-content-type", "by-ftp-filename", or "all"
}

// String renders the X-Permitted-Cross-Domain-Policies header value.
func (cfg XPermittedCrossDomainPoliciesConfig) String() string {
	return cfg.Policy
}

// NewXPermittedCrossDomainPoliciesHeader creates a new X-Permitted-Cross-Domain-Policies header from the config.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies
//
// Example usage:
//
//	cfg := goheader.XPermittedCrossDomainPoliciesConfig{Policy: "none"}
//	header := goheader.NewXPermittedCrossDomainPoliciesHeader(cfg)
//	fmt.Println(header.Name)   // X-Permitted-Cross-Domain-Policies
//	fmt.Println(header.Values) // ["none"]
func NewXPermittedCrossDomainPoliciesHeader(cfg XPermittedCrossDomainPoliciesConfig) Header {
	return Header{
		Experimental: false,
		Name:         XPermittedCrossDomainPolicies,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard but widely supported in legacy Adobe ecosystem
		Values:       []string{cfg.String()},
	}
}

// XPoweredByConfig defines the configuration for the X-Powered-By header.
type XPoweredByConfig struct {
	Technology string // The technology or framework name (e.g., "Express", "PHP/7.4.21")
}

// String renders the X-Powered-By header value.
func (cfg XPoweredByConfig) String() string {
	return cfg.Technology
}

// NewXPoweredByHeader creates a new X-Powered-By header from the config.
// Note: This is a non-standard header. Use with caution, as it may leak information about your stack.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By
//
// Example usage:
//
//	cfg := goheader.XPoweredByConfig{Technology: "PHP/7.4.21"}
//	header := goheader.NewXPoweredByHeader(cfg)
//	fmt.Println(header.Name)   // X-Powered-By
//	fmt.Println(header.Values) // ["PHP/7.4.21"]
func NewXPoweredByHeader(cfg XPoweredByConfig) Header {
	return Header{
		Experimental: false,
		Name:         XPoweredBy,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XRedirectByConfig defines the configuration for the X-Redirect-By header.
type XRedirectByConfig struct {
	Source string // Component or system that triggered the redirect (e.g., "WordPress", "nginx", "load-balancer")
}

// String renders the X-Redirect-By header value.
func (cfg XRedirectByConfig) String() string {
	return cfg.Source
}

// NewXRedirectByHeader creates a new X-Redirect-By header from the config.
// Note: This is a non-standard header, mostly used for debugging and transparency.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Redirect-By
//
// Example usage:
//
//	cfg := goheader.XRedirectByConfig{Source: "WordPress"}
//	header := goheader.NewXRedirectByHeader(cfg)
//	fmt.Println(header.Name)   // X-Redirect-By
//	fmt.Println(header.Values) // ["WordPress"]
func NewXRedirectByHeader(cfg XRedirectByConfig) Header {
	return Header{
		Experimental: false,
		Name:         XRedirectBy,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XRequestIDConfig defines the configuration for the X-Request-ID header.
type XRequestIDConfig struct {
	ID string // A unique request ID, typically a UUID
}

// String renders the X-Request-ID header value.
func (cfg XRequestIDConfig) String() string {
	return cfg.ID
}

// NewXRequestIDHeader creates a new X-Request-ID header from the config.
// Note: This is a non-standard header, but widely adopted in APIs and distributed systems.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Request-ID
//
// Example usage:
//
//	cfg := goheader.XRequestIDConfig{ID: "123e4567-e89b-12d3-a456-426614174000"}
//	header := goheader.NewXRequestIDHeader(cfg)
//	fmt.Println(header.Name)   // X-Request-ID
//	fmt.Println(header.Values) // ["123e4567-e89b-12d3-a456-426614174000"]
func NewXRequestIDHeader(cfg XRequestIDConfig) Header {
	return Header{
		Experimental: false,
		Name:         XRequestID,
		Request:      true,
		Response:     true,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XRequestedWithConfig defines the configuration for the X-Requested-With header.
type XRequestedWithConfig struct {
	With string // Typically "XMLHTTPRequest", but could be other client identifiers
}

// String renders the X-Requested-With header value.
func (cfg XRequestedWithConfig) String() string {
	return cfg.With
}

// NewXRequestedWithHeader creates a new X-Requested-With header from the config.
// Note: This is a non-standard header, but historically common in AJAX applications.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Requested-With
//
// Example usage:
//
//	cfg := goheader.XRequestedWithConfig{With: "XMLHTTPRequest"}
//	header := goheader.NewXRequestedWithHeader(cfg)
//	fmt.Println(header.Name)   // X-Requested-With
//	fmt.Println(header.Values) // ["XMLHTTPRequest"]
func NewXRequestedWithHeader(cfg XRequestedWithConfig) Header {
	return Header{
		Experimental: false,
		Name:         XRequestedWith,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard
		Values:       []string{cfg.String()},
	}
}

// XRobotsTagConfig defines the configuration for the X-Robots-Tag header.
type XRobotsTagConfig struct {
	Directives []string // List of directives, e.g., ["noindex", "nofollow"]
}

// String renders the X-Robots-Tag header value.
func (cfg XRobotsTagConfig) String() string {
	return strings.Join(cfg.Directives, ", ")
}

// NewXRobotsTagHeader creates a new X-Robots-Tag header from the config.
// Note: This is a non-standard header, but widely used for SEO and indexing control.
// More information: https://developers.google.com/search/docs/crawling-indexing/using-robots-meta-tag
//
// Example usage:
//
//	cfg := goheader.XRobotsTagConfig{Directives: []string{"noindex", "nofollow"}}
//	header := goheader.NewXRobotsTagHeader(cfg)
//	fmt.Println(header.Name)   // X-Robots-Tag
//	fmt.Println(header.Values) // ["noindex, nofollow"]
func NewXRobotsTagHeader(cfg XRobotsTagConfig) Header {
	return Header{
		Experimental: false,
		Name:         XRobotsTag,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard but widely used
		Values:       []string{cfg.String()},
	}
}

// XUACompatibleConfig defines the configuration for the X-UA-Compatible header.
type XUACompatibleConfig struct {
	Mode string // Rendering mode, e.g., "IE=edge", "IE=9"
}

// String renders the X-UA-Compatible header value.
func (cfg XUACompatibleConfig) String() string {
	return cfg.Mode
}

// NewXUACompatibleHeader creates a new X-UA-Compatible header from the config.
// Note: This is a non-standard, legacy header, ignored by most modern browsers.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-UA-Compatible
//
// Example usage:
//
//	cfg := goheader.XUACompatibleConfig{Mode: "IE=edge"}
//	header := goheader.NewXUACompatibleHeader(cfg)
//	fmt.Println(header.Name)   // X-UA-Compatible
//	fmt.Println(header.Values) // ["IE=edge"]
func NewXUACompatibleHeader(cfg XUACompatibleConfig) Header {
	return Header{
		Experimental: false,
		Name:         XUACompatible,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard and legacy
		Values:       []string{cfg.String()},
	}
}

// XUIDHConfig defines the configuration for the X-UIDH header.
type XUIDHConfig struct {
	ID string // Unique identifier assigned by the ISP (deprecated, privacy concerns)
}

// String renders the X-UIDH header value.
func (cfg XUIDHConfig) String() string {
	return cfg.ID
}

// NewXUIDHHeader creates a new X-UIDH header from the config.
// Note: This is a deprecated, non-standard header associated with ISP tracking.
// More information: https://en.wikipedia.org/wiki/UIDH
//
// Example usage:
//
//	cfg := goheader.XUIDHConfig{ID: "1234567890abcdef"}
//	header := goheader.NewXUIDHHeader(cfg)
//	fmt.Println(header.Name)   // X-UIDH
//	fmt.Println(header.Values) // ["1234567890abcdef"]
func NewXUIDHHeader(cfg XUIDHConfig) Header {
	return Header{
		Experimental: false,
		Name:         XUIDH,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard and deprecated
		Values:       []string{cfg.String()},
	}
}

// XWapProfileConfig defines the configuration for the X-Wap-Profile header.
type XWapProfileConfig struct {
	URL string // URL pointing to the User Agent Profile (UAProf) document
}

// String renders the X-Wap-Profile header value.
func (cfg XWapProfileConfig) String() string {
	return cfg.URL
}

// NewXWapProfileHeader creates a new X-Wap-Profile header from the config.
// Note: This is a legacy, non-standard header from the early mobile web era.
// More information: https://en.wikipedia.org/wiki/UAProf
//
// Example usage:
//
//	cfg := goheader.XWapProfileConfig{URL: "http://wap.samsungmobile.com/uaprof/SGH-I777.xml"}
//	header := goheader.NewXWapProfileHeader(cfg)
//	fmt.Println(header.Name)   // X-Wap-Profile
//	fmt.Println(header.Values) // ["http://wap.samsungmobile.com/uaprof/SGH-I777.xml"]
func NewXWapProfileHeader(cfg XWapProfileConfig) Header {
	return Header{
		Experimental: false,
		Name:         XWapProfile,
		Request:      true,
		Response:     false,
		Standard:     false, // Non-standard and legacy
		Values:       []string{cfg.String()},
	}
}

// XWebKitCSPConfig defines the configuration for the X-WebKit-CSP header.
type XWebKitCSPConfig struct {
	Policy string // CSP policy string (e.g., "default-src 'self'; script-src 'self' https://apis.google.com")
}

// String renders the X-WebKit-CSP header value.
func (cfg XWebKitCSPConfig) String() string {
	return cfg.Policy
}

// NewXWebKitCSPHeader creates a new X-WebKit-CSP header from the config.
// Note: This is a deprecated, non-standard header. Use Content-Security-Policy instead.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
//
// Example usage:
//
//	cfg := goheader.XWebKitCSPConfig{Policy: "default-src 'self'; script-src 'self' https://apis.google.com"}
//	header := goheader.NewXWebKitCSPHeader(cfg)
//	fmt.Println(header.Name)   // X-WebKit-CSP
//	fmt.Println(header.Values) // ["default-src 'self'; script-src 'self' https://apis.google.com"]
func NewXWebKitCSPHeader(cfg XWebKitCSPConfig) Header {
	return Header{
		Experimental: false,
		Name:         XWebKitCSP,
		Request:      false,
		Response:     true,
		Standard:     false, // Non-standard and deprecated
		Values:       []string{cfg.String()},
	}
}

// XXSSProtectionConfig defines the configuration for the X-XSS-Protection header.
type XXSSProtectionConfig struct {
	Enabled bool   // true = "1", false = "0"
	Mode    string // Optional: "block" or "report=<URL>"
}

// String renders the X-XSS-Protection header value.
func (cfg XXSSProtectionConfig) String() string {
	if !cfg.Enabled {
		return "0"
	}
	if cfg.Mode != "" {
		return "1; mode=" + cfg.Mode
	}
	return "1"
}

// NewXXSSProtectionHeader creates a new X-XSS-Protection header from the config.
// Note: This header is deprecated. Modern browsers ignore it.
// More information: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
//
// Example usage:
//
//	cfg := goheader.XXSSProtectionConfig{Enabled: true, Mode: "block"}
//	header := goheader.NewXXSSProtectionHeader(cfg)
//	fmt.Println(header.Name)   // X-XSS-Protection
//	fmt.Println(header.Values) // ["1; mode=block"]
func NewXXSSProtectionHeader(cfg XXSSProtectionConfig) Header {
	return Header{
		Experimental: false,
		Name:         XXSSProtection,
		Request:      false,
		Response:     true,
		Standard:     false, // Deprecated
		Values:       []string{cfg.String()},
	}
}

// WriteHeaders writes the provided headers to the given http.ResponseWriter object.
// It maps the headers based on their names to the corresponding values and sets them
// in the http.ResponseWriter object's header. If a header with the same name already exists,
// its values will be updated with the new ones provided.
//
//	// Create a default handler.
//	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//		// Create a new set of goheader.Header instances.
//		headers := []goheader.Header{
//			goheader.NewContentLanguageHeader("en-AU"),
//			goheader.NewContentTypeHeader("application/json"),
//			goheader.NewCookieHeader("language=golang")}
//
//		// Add the headers to the http.ResponseWriter.
//		goheader.WriteHeaders(w, headers...)
//		// Write the HTTP status code.
//		w.WriteHeader(http.StatusOK)
//		// Write the HTTP response.
//		json.NewEncoder(w).Encode(w.Header()) // { "Content-Language": [ "en-AU" ], "Content-Type": [ "application/json" ], "Cookie": [ "language=golang" ] }
//	})
func WriteHeaders(writer interface{ Header() http.Header }, headers ...Header) {
	writerHeaders := writer.Header()
	for _, header := range headers {
		writerHeaders[header.Name] = header.Values
	}
}
