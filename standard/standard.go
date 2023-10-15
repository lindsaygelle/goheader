package standard

// Standard represents a specific standard or specification identified by its unique numerical value.
type Standard uint16

// RFC1544 is the defined standard with the unique identifier 1544.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc1544.
const RFC1544 Standard = 1544

// RFC1864 is the defined standard with the unique identifier 1864.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc1864.
const RFC1864 Standard = 1864

// RFC2616 is the defined standard with the unique identifier 2616.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc2616.
const RFC2616 Standard = 2616

// RFC2965 is the defined standard with the unique identifier 2965.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc2965.
const RFC2965 Standard = 2965

// RFC3229 is the defined standard with the unique identifier 3229.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc3229.
const RFC3229 Standard = 3229

// RFC4021 is the defined standard with the unique identifier 4021.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc4021.
const RFC4021 Standard = 4021

// RFC5789 is the defined standard with the unique identifier 5789.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc5789.
const RFC5789 Standard = 5789

// RFC5988 is the defined standard with the unique identifier 5988.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc5988.
const RFC5988 Standard = 5988

// RFC6265 is the defined standard with the unique identifier 6265.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc6265.
const RFC6265 Standard = 6265

// RFC6266 is the defined standard with the unique identifier 6266.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc6266.
const RFC6266 Standard = 6266

// RFC6454 is the defined standard with the unique identifier 6454.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc6454.
const RFC6454 Standard = 6454

// RFC7089 is the defined standard with the unique identifier 7089.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7089.
const RFC7089 Standard = 7089

// RFC7234 is the defined standard with the unique identifier 7234.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7234.
const RFC7234 Standard = 7234

// RFC7239 is the defined standard with the unique identifier 7239.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7239.
const RFC7239 Standard = 7239

// RFC7240 is the defined standard with the unique identifier 7240.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7240.
const RFC7240 Standard = 7240

// RFC7469 is the defined standard with the unique identifier 7469.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7469.
const RFC7469 Standard = 7469

// RFC7480 is the defined standard with the unique identifier 7480.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7480.
const RFC7480 Standard = 7480

// RFC7540 is the defined standard with the unique identifier 7540.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc7540.
const RFC7540 Standard = 7540

// RFC8942 is the defined standard with the unique identifier 8942.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc8942.
const RFC8942 Standard = 8942

// RFC9110 is the defined standard with the unique identifier 9110.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc9110.
const RFC9110 Standard = 9110

// RFC9111 is the defined standard with the unique identifier 9111.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc9111.
const RFC9111 Standard = 9111

// RFC9113 is the defined standard with the unique identifier 9113.
// It refers to the Request for Comments (RFC) document available at https://www.rfc-editor.org/rfc/rfc9113.
const RFC9113 Standard = 9113

// New creates a new Standard.
func New(value uint) Standard {
	return Standard(value)
}
