package goheader

import (
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

// ProxyAuthenticate header field is used to challenge the authorization of the client before a proxy can be set up.
const ProxyAuthenticate = "Proxy-Authenticate"

// ProxyAuthorization header field is used to provide authentication information for proxies that require authentication.
const ProxyAuthorization = "Proxy-Authorization"

// ProxyConnection header field is used to specify options for the connection.
const ProxyConnection = "Proxy-Connection"

// PublicKeyPins header field is used to associate a specific cryptographic public key with a certain web server.
const PublicKeyPins = "Public-Key-Pins"

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

// ReportTo header field is used to specify a URI to which the user agent sends reports about various issues.
const ReportTo = "Report-To"

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

// UserAgent header field is used to provide information about the user agent (client) making the request.
const UserAgent = "User-Agent"

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
const XHTTPMethodOverride = "X-Http-Method-Override"

// XPoweredBy header field is used to indicate the technology (e.g., server framework, language) powering a website.
const XPoweredBy = "X-Powered-By"

// XRedirectBy header field is used to indicate the entity responsible for the redirection in the response.
const XRedirectBy = "X-Redirect-By"

// XRequestID header field is used to uniquely identify a request.
const XRequestID = "X-Request-ID"

// XRequestedWith header field is used to indicate the type of request (e.g., XMLHttpRequest) made by the user agent.
const XRequestedWith = "X-Requested-With"

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

// NewClearSiteDataHeader creates a new Clear-Site-Data Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data
//
//	// Create a new Header instance.
//	newHeader := goheader.NewClearSiteDataHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Clear-Site-Data
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewClearSiteDataHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ClearSiteData,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewConnectionHeader creates a new Connection Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
//
//	// Create a new Header instance.
//	newHeader := goheader.NewConnectionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Connection
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewConnectionHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Connection,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentDPRHeader creates a new Content-DPR Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-DPR
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentDPRHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-DPR
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentDPRHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         ContentDPR,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewContentDispositionHeader creates a new Content-Disposition Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentDispositionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Disposition
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentDispositionHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentDisposition,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentEncodingHeader creates a new Content-Encoding Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentEncodingHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Encoding
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentEncodingHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentEncoding,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentLanguageHeader creates a new Content-Language Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Language
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentLanguageHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Language
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentLanguageHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentLanguage,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentLengthHeader creates a new Content-Length Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentLengthHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Length
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentLengthHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentLength,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentLocationHeader creates a new Content-Location Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Location
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentLocationHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Location
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentLocationHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentLocation,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentMD5Header creates a new Content-MD5 Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-MD5
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentMD5Header("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-MD5
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentMD5Header(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentMD5,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentRangeHeader creates a new Content-Range Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Range
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentRangeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Range
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentRangeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentRange,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentSecurityPolicyHeader creates a new Content-Security-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentSecurityPolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Security-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentSecurityPolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentSecurityPolicy,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewContentSecurityPolicyReportOnlyHeader creates a new Content-Security-Policy-Report-Only Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentSecurityPolicyReportOnlyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Security-Policy-Report-Only
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentSecurityPolicyReportOnlyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentSecurityPolicyReportOnly,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewContentTypeHeader creates a new Content-Type Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type
//
//	// Create a new Header instance.
//	newHeader := goheader.NewContentTypeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Content-Type
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewContentTypeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ContentType,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewCookieHeader creates a new Cookie Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cookie
//
//	// Create a new Header instance.
//	newHeader := goheader.NewCookieHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Cookie
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewCookieHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Cookie,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewCorrelationIDHeader creates a new Correlation-ID Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Correlation-ID
//
//	// Create a new Header instance.
//	newHeader := goheader.NewCorrelationIDHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Correlation-ID
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewCorrelationIDHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         CorrelationID,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewCriticalCHHeader creates a new Critical-CH Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Critical-CH
//
//	// Create a new Header instance.
//	newHeader := goheader.NewCriticalCHHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Critical-CH
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewCriticalCHHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         CriticalCH,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewCrossOriginEmbedderPolicyHeader creates a new Cross-Origin-Embedder-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewCrossOriginEmbedderPolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Cross-Origin-Embedder-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewCrossOriginEmbedderPolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         CrossOriginEmbedderPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewCrossOriginOpenerPolicyHeader creates a new Cross-Origin-Opener-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewCrossOriginOpenerPolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Cross-Origin-Opener-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewCrossOriginOpenerPolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         CrossOriginOpenerPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewCrossOriginResourcePolicyHeader creates a new Cross-Origin-Resource-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewCrossOriginResourcePolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Cross-Origin-Resource-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewCrossOriginResourcePolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         CrossOriginResourcePolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewDNTHeader creates a new DNT Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/DNT
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDNTHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // DNT
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDNTHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         DNT,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewDPRHeader creates a new DPR Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/DPR
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDPRHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // DPR
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDPRHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         DPR,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewDateHeader creates a new Date Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDateHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Date
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDateHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Date,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewDeltaBaseHeader creates a new Delta-Base Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Delta-Base
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDeltaBaseHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Delta-Base
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDeltaBaseHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         DeltaBase,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewDeviceMemoryHeader creates a new Device-Memory Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Device-Memory
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDeviceMemoryHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Device-Memory
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDeviceMemoryHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         DeviceMemory,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewDigestHeader creates a new Digest Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Digest
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDigestHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Digest
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDigestHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Digest,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewDownlinkHeader creates a new Downlink Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Downlink
//
//	// Create a new Header instance.
//	newHeader := goheader.NewDownlinkHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Downlink
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewDownlinkHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         Downlink,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewECTHeader creates a new ECT Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ECT
//
//	// Create a new Header instance.
//	newHeader := goheader.NewECTHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // ECT
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewECTHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         ECT,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewETagHeader creates a new ETag Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag
//
//	// Create a new Header instance.
//	newHeader := goheader.NewETagHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // ETag
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewETagHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ETag,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewEarlyDataHeader creates a new Early-Data Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Early-Data
//
//	// Create a new Header instance.
//	newHeader := goheader.NewEarlyDataHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Early-Data
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewEarlyDataHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         EarlyData,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewExpectHeader creates a new Expect Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect
//
//	// Create a new Header instance.
//	newHeader := goheader.NewExpectHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Expect
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewExpectHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Expect,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewExpectCTHeader creates a new Expect-CT Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT
//
//	// Create a new Header instance.
//	newHeader := goheader.NewExpectCTHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Expect-CT
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewExpectCTHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ExpectCT,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewExpiresHeader creates a new Expires Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires
//
//	// Create a new Header instance.
//	newHeader := goheader.NewExpiresHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Expires
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewExpiresHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Expires,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewForwardedHeader creates a new Forwarded Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
//
//	// Create a new Header instance.
//	newHeader := goheader.NewForwardedHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Forwarded
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewForwardedHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Forwarded,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewFromHeader creates a new From Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/From
//
//	// Create a new Header instance.
//	newHeader := goheader.NewFromHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // From
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewFromHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         From,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewFrontEndHTTPSHeader creates a new Front-End-Https Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Front-End-Https
//
//	// Create a new Header instance.
//	newHeader := goheader.NewFrontEndHTTPSHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Front-End-Https
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewFrontEndHTTPSHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         FrontEndHTTPS,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewHTTP2SettingsHeader creates a new HTTP2-Settings Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/HTTP2-Settings
//
//	// Create a new Header instance.
//	newHeader := goheader.NewHTTP2SettingsHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // HTTP2-Settings
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewHTTP2SettingsHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         HTTP2Settings,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewHostHeader creates a new Host Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host
//
//	// Create a new Header instance.
//	newHeader := goheader.NewHostHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Host
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewHostHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Host,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewIMHeader creates a new IM Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/IM
//
//	// Create a new Header instance.
//	newHeader := goheader.NewIMHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // IM
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewIMHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         IM,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewIfMatchHeader creates a new If-Match Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match
//
//	// Create a new Header instance.
//	newHeader := goheader.NewIfMatchHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // If-Match
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewIfMatchHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         IfMatch,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewIfModifiedSinceHeader creates a new If-Modified-Since Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since
//
//	// Create a new Header instance.
//	newHeader := goheader.NewIfModifiedSinceHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // If-Modified-Since
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewIfModifiedSinceHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         IfModifiedSince,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewIfNoneMatchHeader creates a new If-None-Match Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
//
//	// Create a new Header instance.
//	newHeader := goheader.NewIfNoneMatchHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // If-None-Match
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewIfNoneMatchHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         IfNoneMatch,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewIfRangeHeader creates a new If-Range Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Range
//
//	// Create a new Header instance.
//	newHeader := goheader.NewIfRangeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // If-Range
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewIfRangeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         IfRange,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewIfUnmodifiedSinceHeader creates a new If-Unmodified-Since Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Unmodified-Since
//
//	// Create a new Header instance.
//	newHeader := goheader.NewIfUnmodifiedSinceHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // If-Unmodified-Since
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewIfUnmodifiedSinceHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         IfUnmodifiedSince,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewKeepAliveHeader creates a new Keep-Alive Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
//
//	// Create a new Header instance.
//	newHeader := goheader.NewKeepAliveHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Keep-Alive
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewKeepAliveHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         KeepAlive,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewLargeAllocationHeader creates a new Large-Allocation Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Large-Allocation
//
//	// Create a new Header instance.
//	newHeader := goheader.NewLargeAllocationHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Large-Allocation
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewLargeAllocationHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         LargeAllocation,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewLastModifiedHeader creates a new Last-Modified Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified
//
//	// Create a new Header instance.
//	newHeader := goheader.NewLastModifiedHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Last-Modified
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewLastModifiedHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         LastModified,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewLinkHeader creates a new Link Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
//
//	// Create a new Header instance.
//	newHeader := goheader.NewLinkHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Link
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewLinkHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Link,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewLocationHeader creates a new Location Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Location
//
//	// Create a new Header instance.
//	newHeader := goheader.NewLocationHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Location
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewLocationHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Location,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewMaxForwardsHeader creates a new Max-Forwards Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Max-Forwards
//
//	// Create a new Header instance.
//	newHeader := goheader.NewMaxForwardsHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Max-Forwards
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewMaxForwardsHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         MaxForwards,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewNELHeader creates a new NEL Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/NEL
//
//	// Create a new Header instance.
//	newHeader := goheader.NewNELHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // NEL
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewNELHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         NEL,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewOriginHeader creates a new Origin Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
//
//	// Create a new Header instance.
//	newHeader := goheader.NewOriginHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Origin
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewOriginHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Origin,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewP3PHeader creates a new P3P Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/P3P
//
//	// Create a new Header instance.
//	newHeader := goheader.NewP3PHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // P3P
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewP3PHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         P3P,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewPermissionsPolicyHeader creates a new Permissions-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewPermissionsPolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Permissions-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewPermissionsPolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         PermissionsPolicy,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewPragmaHeader creates a new Pragma Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma
//
//	// Create a new Header instance.
//	newHeader := goheader.NewPragmaHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Pragma
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewPragmaHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Pragma,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewPreferHeader creates a new Prefer Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Prefer
//
//	// Create a new Header instance.
//	newHeader := goheader.NewPreferHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Prefer
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewPreferHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Prefer,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewPreferenceAppliedHeader creates a new Preference-Applied Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Preference-Applied
//
//	// Create a new Header instance.
//	newHeader := goheader.NewPreferenceAppliedHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Preference-Applied
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewPreferenceAppliedHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         PreferenceApplied,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewProxyAuthenticateHeader creates a new Proxy-Authenticate Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate
//
//	// Create a new Header instance.
//	newHeader := goheader.NewProxyAuthenticateHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Proxy-Authenticate
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewProxyAuthenticateHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ProxyAuthenticate,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewProxyAuthorizationHeader creates a new Proxy-Authorization Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
//
//	// Create a new Header instance.
//	newHeader := goheader.NewProxyAuthorizationHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Proxy-Authorization
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewProxyAuthorizationHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ProxyAuthorization,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewProxyConnectionHeader creates a new Proxy-Connection Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Connection
//
//	// Create a new Header instance.
//	newHeader := goheader.NewProxyConnectionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Proxy-Connection
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewProxyConnectionHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ProxyConnection,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewPublicKeyPinsHeader creates a new Public-Key-Pins Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins
//
//	// Create a new Header instance.
//	newHeader := goheader.NewPublicKeyPinsHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Public-Key-Pins
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewPublicKeyPinsHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         PublicKeyPins,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewRTTHeader creates a new RTT Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/RTT
//
//	// Create a new Header instance.
//	newHeader := goheader.NewRTTHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // RTT
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewRTTHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         RTT,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewRangeHeader creates a new Range Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
//
//	// Create a new Header instance.
//	newHeader := goheader.NewRangeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Range
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewRangeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Range,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewRefererHeader creates a new Referer Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
//
//	// Create a new Header instance.
//	newHeader := goheader.NewRefererHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Referer
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewRefererHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Referer,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewReferrerPolicyHeader creates a new Referrer-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewReferrerPolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Referrer-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewReferrerPolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ReferrerPolicy,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewRefreshHeader creates a new Refresh Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Refresh
//
//	// Create a new Header instance.
//	newHeader := goheader.NewRefreshHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Refresh
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewRefreshHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Refresh,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewReportToHeader creates a new Report-To Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Report-To
//
//	// Create a new Header instance.
//	newHeader := goheader.NewReportToHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Report-To
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewReportToHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ReportTo,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewRetryAfterHeader creates a new Retry-After Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
//
//	// Create a new Header instance.
//	newHeader := goheader.NewRetryAfterHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Retry-After
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewRetryAfterHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         RetryAfter,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewSaveDataHeader creates a new Save-Data Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Save-Data
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSaveDataHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Save-Data
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSaveDataHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SaveData,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHPrefersColorSchemeHeader creates a new Sec-CH-Prefers-Color-Scheme Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-Prefers-Color-Scheme
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHPrefersColorSchemeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-Prefers-Color-Scheme
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHPrefersColorSchemeHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHPrefersColorScheme,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHPrefersReducedMotionHeader creates a new Sec-CH-Prefers-Reduced-Motion Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-Prefers-Reduced-Motion
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHPrefersReducedMotionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-Prefers-Reduced-Motion
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHPrefersReducedMotionHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHPrefersReducedMotion,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHPrefersReducedTransparencyHeader creates a new Sec-CH-Prefers-Reduced-Transparency Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-Prefers-Reduced-Transparency
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHPrefersReducedTransparencyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-Prefers-Reduced-Transparency
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHPrefersReducedTransparencyHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHPrefersReducedTransparency,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAHeader creates a new Sec-CH-UA Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUA,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAArchHeader creates a new Sec-CH-UA-Arch Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Arch
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAArchHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Arch
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAArchHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAArch,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUABitnessHeader creates a new Sec-CH-UA-Bitness Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Bitness
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUABitnessHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Bitness
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUABitnessHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUABitness,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAFullVersionHeader creates a new Sec-CH-UA-Full-Version Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Full-Version
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAFullVersionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Full-Version
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAFullVersionHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAFullVersion,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAFullVersionListHeader creates a new Sec-CH-UA-Full-Version-List Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Full-Version-List
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAFullVersionListHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Full-Version-List
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAFullVersionListHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAFullVersionList,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAMobileHeader creates a new Sec-CH-UA-Mobile Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Mobile
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAMobileHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Mobile
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAMobileHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAMobile,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAModelHeader creates a new Sec-CH-UA-Model Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Model
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAModelHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Model
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAModelHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAModel,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAPlatformHeader creates a new Sec-CH-UA-Platform Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Platform
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAPlatformHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Platform
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAPlatformHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAPlatform,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecCHUAPlatformVersionHeader creates a new Sec-CH-UA-Platform-Version Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA-Platform-Version
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecCHUAPlatformVersionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-CH-UA-Platform-Version
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecCHUAPlatformVersionHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecCHUAPlatformVersion,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecFetchDestHeader creates a new Sec-Fetch-Dest Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecFetchDestHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-Fetch-Dest
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecFetchDestHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchDest,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewSecFetchModeHeader creates a new Sec-Fetch-Mode Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecFetchModeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-Fetch-Mode
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecFetchModeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchMode,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewSecFetchSiteHeader creates a new Sec-Fetch-Site Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecFetchSiteHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-Fetch-Site
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecFetchSiteHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchSite,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewSecFetchUserHeader creates a new Sec-Fetch-User Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-User
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecFetchUserHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-Fetch-User
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecFetchUserHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SecFetchUser,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewSecGPCHeader creates a new Sec-GPC Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-GPC
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecGPCHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-GPC
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecGPCHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SecGPC,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewSecPurposeHeader creates a new Sec-Purpose Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Purpose
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecPurposeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-Purpose
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecPurposeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SecPurpose,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewSecWebSocketAcceptHeader creates a new Sec-WebSocket-Accept Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Accept
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSecWebSocketAcceptHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Sec-WebSocket-Accept
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSecWebSocketAcceptHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SecWebSocketAccept,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewServerHeader creates a new Server Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server
//
//	// Create a new Header instance.
//	newHeader := goheader.NewServerHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Server
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewServerHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Server,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewServerTimingHeader creates a new Server-Timing Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing
//
//	// Create a new Header instance.
//	newHeader := goheader.NewServerTimingHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Server-Timing
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewServerTimingHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ServerTiming,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewServiceWorkerNavigationPreloadHeader creates a new Service-Worker-Navigation-Preload Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Service-Worker-Navigation-Preload
//
//	// Create a new Header instance.
//	newHeader := goheader.NewServiceWorkerNavigationPreloadHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Service-Worker-Navigation-Preload
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewServiceWorkerNavigationPreloadHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ServiceWorkerNavigationPreload,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewSetCookieHeader creates a new Set-Cookie Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSetCookieHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Set-Cookie
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSetCookieHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SetCookie,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewSourceMapHeader creates a new SourceMap Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/SourceMap
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSourceMapHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // SourceMap
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSourceMapHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         SourceMap,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewStatusHeader creates a new Status Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Status
//
//	// Create a new Header instance.
//	newHeader := goheader.NewStatusHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Status
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewStatusHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Status,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewStrictTransportSecurityHeader creates a new Strict-Transport-Security Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
//
//	// Create a new Header instance.
//	newHeader := goheader.NewStrictTransportSecurityHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Strict-Transport-Security
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewStrictTransportSecurityHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         StrictTransportSecurity,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewSupportsLoadingModeHeader creates a new Supports-Loading-Mode Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Supports-Loading-Mode
//
//	// Create a new Header instance.
//	newHeader := goheader.NewSupportsLoadingModeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Supports-Loading-Mode
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewSupportsLoadingModeHeader(values ...string) Header {
	return Header{
		Experimental: true,
		Name:         SupportsLoadingMode,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewTEHeader creates a new TE Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/TE
//
//	// Create a new Header instance.
//	newHeader := goheader.NewTEHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // TE
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewTEHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         TE,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewTimingAllowOriginHeader creates a new Timing-Allow-Origin Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Timing-Allow-Origin
//
//	// Create a new Header instance.
//	newHeader := goheader.NewTimingAllowOriginHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Timing-Allow-Origin
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewTimingAllowOriginHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         TimingAllowOrigin,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewTKHeader creates a new Tk Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Tk
//
//	// Create a new Header instance.
//	newHeader := goheader.NewTKHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Tk
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewTKHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         TK,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewTrailerHeader creates a new Trailer Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
//
//	// Create a new Header instance.
//	newHeader := goheader.NewTrailerHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Trailer
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewTrailerHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Trailer,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewTransferEncodingHeader creates a new Transfer-Encoding Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
//
//	// Create a new Header instance.
//	newHeader := goheader.NewTransferEncodingHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Transfer-Encoding
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewTransferEncodingHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         TransferEncoding,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewUpgradeHeader creates a new Upgrade Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade
//
//	// Create a new Header instance.
//	newHeader := goheader.NewUpgradeHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Upgrade
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewUpgradeHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Upgrade,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewUpgradeInsecureRequestsHeader creates a new Upgrade-Insecure-Requests Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade-Insecure-Requests
//
//	// Create a new Header instance.
//	newHeader := goheader.NewUpgradeInsecureRequestsHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Upgrade-Insecure-Requests
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewUpgradeInsecureRequestsHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         UpgradeInsecureRequests,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewUserAgentHeader creates a new User-Agent Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
//
//	// Create a new Header instance.
//	newHeader := goheader.NewUserAgentHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // User-Agent
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewUserAgentHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         UserAgent,
		Request:      true,
		Response:     false,
		Standard:     true,
		Values:       values}
}

// NewVaryHeader creates a new Vary Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
//
//	// Create a new Header instance.
//	newHeader := goheader.NewVaryHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Vary
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewVaryHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Vary,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewViaHeader creates a new Via Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via
//
//	// Create a new Header instance.
//	newHeader := goheader.NewViaHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Via
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewViaHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Via,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewViewportWidthHeader creates a new Viewport-Width Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Viewport-Width
//
//	// Create a new Header instance.
//	newHeader := goheader.NewViewportWidthHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Viewport-Width
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewViewportWidthHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         ViewportWidth,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewWWWAuthenticateHeader creates a new WWW-Authenticate Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
//
//	// Create a new Header instance.
//	newHeader := goheader.NewWWWAuthenticateHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // WWW-Authenticate
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewWWWAuthenticateHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         WWWAuthenticate,
		Request:      false,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewWantDigestHeader creates a new Want-Digest Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Want-Digest
//
//	// Create a new Header instance.
//	newHeader := goheader.NewWantDigestHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Want-Digest
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewWantDigestHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         WantDigest,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewWarningHeader creates a new Warning Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Warning
//
//	// Create a new Header instance.
//	newHeader := goheader.NewWarningHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Warning
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewWarningHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Warning,
		Request:      true,
		Response:     true,
		Standard:     true,
		Values:       values}
}

// NewWidthHeader creates a new Width Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Width
//
//	// Create a new Header instance.
//	newHeader := goheader.NewWidthHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // Width
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewWidthHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         Width,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXATTDeviceIDHeader creates a new X-ATT-DeviceId Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-ATT-DeviceId
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXATTDeviceIDHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-ATT-DeviceId
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXATTDeviceIDHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XATTDeviceID,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXContentDurationHeader creates a new X-Content-Duration Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Duration
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXContentDurationHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Content-Duration
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXContentDurationHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XContentDuration,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXContentSecurityPolicyHeader creates a new X-Content-Security-Policy Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Security-Policy
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXContentSecurityPolicyHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Content-Security-Policy
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXContentSecurityPolicyHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XContentSecurityPolicy,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXContentTypeOptionsHeader creates a new X-Content-Type-Options Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXContentTypeOptionsHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Content-Type-Options
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXContentTypeOptionsHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XContentTypeOptions,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXCorrelationIDHeader creates a new X-Correlation-ID Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Correlation-ID
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXCorrelationIDHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Correlation-ID
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXCorrelationIDHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XCorrelationID,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXCSRFTokenHeader creates a new X-Csrf-Token Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Csrf-Token
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXCSRFTokenHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Csrf-Token
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXCSRFTokenHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XCSRFToken,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXDNSPrefetchControlHeader creates a new X-DNS-Prefetch-Control Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXDNSPrefetchControlHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-DNS-Prefetch-Control
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXDNSPrefetchControlHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XDNSPrefetchControl,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXForwardedForHeader creates a new X-Forwarded-For Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXForwardedForHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Forwarded-For
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXForwardedForHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XForwardedFor,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXForwardedHostHeader creates a new X-Forwarded-Host Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXForwardedHostHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Forwarded-Host
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXForwardedHostHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XForwardedHost,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXForwardedProtoHeader creates a new X-Forwarded-Proto Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXForwardedProtoHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Forwarded-Proto
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXForwardedProtoHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XForwardedProto,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXFrameOptionsHeader creates a new X-Frame-Options Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXFrameOptionsHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Frame-Options
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXFrameOptionsHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XFrameOptions,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXHTTPMethodOverrideHeader creates a new X-Http-Method-Override Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Http-Method-Override
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXHTTPMethodOverrideHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Http-Method-Override
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXHTTPMethodOverrideHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XHTTPMethodOverride,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXPoweredByHeader creates a new X-Powered-By Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXPoweredByHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Powered-By
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXPoweredByHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XPoweredBy,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXRedirectByHeader creates a new X-Redirect-By Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Redirect-By
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXRedirectByHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Redirect-By
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXRedirectByHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XRedirectBy,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXRequestIDHeader creates a new X-Request-ID Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Request-ID
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXRequestIDHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Request-ID
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXRequestIDHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XRequestID,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXRequestedWithHeader creates a new X-Requested-With Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Requested-With
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXRequestedWithHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Requested-With
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXRequestedWithHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XRequestedWith,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXUACompatibleHeader creates a new X-UA-Compatible Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-UA-Compatible
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXUACompatibleHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-UA-Compatible
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXUACompatibleHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XUACompatible,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXUIDHHeader creates a new X-UIDH Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-UIDH
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXUIDHHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-UIDH
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXUIDHHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XUIDH,
		Request:      true,
		Response:     false,
		Standard:     false,
		Values:       values}
}

// NewXWapProfileHeader creates a new X-Wap-Profile Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Wap-Profile
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXWapProfileHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-Wap-Profile
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXWapProfileHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XWapProfile,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXWebKitCSPHeader creates a new X-WebKit-CSP Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-WebKit-CSP
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXWebKitCSPHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-WebKit-CSP
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXWebKitCSPHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XWebKitCSP,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
}

// NewXXSSProtectionHeader creates a new X-XSS-Protection Header with the specified values.
// It accepts a variadic number of strings, where each value represents an item to be added to the Header.
// More information on the HTTP header can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
//
//	// Create a new Header instance.
//	newHeader := goheader.NewXXSSProtectionHeader("Example", "Values")
//	fmt.Println(newHeader.Name) // X-XSS-Protection
//	fmt.Println(newHeader.Value) // ["Example", "Value"]
func NewXXSSProtectionHeader(values ...string) Header {
	return Header{
		Experimental: false,
		Name:         XXSSProtection,
		Request:      false,
		Response:     true,
		Standard:     false,
		Values:       values}
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
