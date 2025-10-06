// Package goheader provides typed, composable builders for HTTP headers.
//
// # Overview
//
// goheader defines string constants for common, experimental, and legacy
// HTTP header field names, plus a small set of value builders that render
// correct header syntax for many well-known fields (e.g. Accept, Cache-Control,
// CORS headers, Client Hints, WebSocket handshake headers, etc.).
//
// The core type is Header, which captures metadata about a header
// (name, request/response applicability, standard vs experimental) and its
// rendered values. Helpers like NewAcceptHeader, NewCacheControlHeader, and
// friends return a Header with a fully formatted value based on a small
// config struct (e.g. AcceptConfig, CacheControlConfig).
//
// Once you have one or more Header values, NewHeaders builds a concrete
// http.Header and canonicalizes keys via http.CanonicalHeaderKey.
//
// Design notes
//
//   - Each “builder” follows the same pattern:
//   - A Value or Directive type that renders one entry (String()).
//   - A Config type that aggregates entries and renders the final value.
//   - A NewXxxHeader(cfg) function that returns a Header.
//   - Date/time values are formatted with http.TimeFormat (IMF-fixdate).
//   - Quality factors (q=) are included only when meaningful; zero or invalid
//     values are omitted by design.
//   - Some headers are marked Experimental or non-Standard; consult the
//     Header fields to understand their status.
//   - Builders perform light validation and focus on correct rendering;
//     they do not attempt to enforce all RFC constraints.
//
// Quick start
//
//	// Compose specific headers with typed configs.
//	accept := goheader.NewAcceptHeader(goheader.AcceptConfig{
//		Values: []goheader.AcceptValue{
//			{MediaType: "application/json", Quality: 1.0},
//			{MediaType: "text/html", Quality: 0.8, Params: map[string]string{"charset": "utf-8"}},
//		},
//	})
//
//	ct := goheader.NewContentTypeHeader(goheader.ContentTypeConfig{
//		MediaType: "application/json",
//		Params:    map[string]string{"charset": "UTF-8"},
//	})
//
//	// Build a concrete http.Header map.
//	h := goheader.NewHeaders(accept, ct)
//	// Example: map[Accept:[application/json;q=1.0, text/html;charset=utf-8;q=0.8]
//	//            Content-Type:[application/json; charset=UTF-8]]
//
// Common builders
//
//   - Content & negotiation: Accept, Accept-Charset, Accept-Encoding,
//     Accept-Language, Content-Type, Content-Encoding, Content-Language,
//     Content-Disposition, Content-Range.
//   - Caching & validation: Cache-Control, Expires, ETag, Last-Modified, Age,
//     Vary.
//   - CORS: Access-Control-Allow-* / -Request-*, Origin.
//   - Security & policies: Content-Security-Policy (+ Report-Only),
//     Strict-Transport-Security, Permissions-Policy, Referrer-Policy.
//   - Client hints: Accept-CH, Critical-CH, Device-Memory, DPR, Width,
//     Viewport-Width, Sec-CH-*.
//   - WebSocket: Sec-WebSocket-* (Accept, Key, Extensions, Protocol, Version).
//   - Miscellaneous: Link, Location, Retry-After, Server-Timing, Report-To,
//     Reporting-Endpoints, Set-Cookie, User-Agent, Via, Warning, etc.
//
// Example: A-IM (instance-manipulations)
//
//	cfg := goheader.AIMConfig{
//		Values: []goheader.AIMValue{
//			{Token: "gzip", Quality: 1.0},
//			{Token: "vcdiff", Quality: 0.5, Extensions: []string{"custom=1"}},
//		},
//	}
//	aim := goheader.NewAIMHeader(cfg)
//	h := goheader.NewHeaders(aim)
//
// This package aims to make header construction explicit, testable, and
// readable, while keeping you close to the underlying wire format.
package goheader
