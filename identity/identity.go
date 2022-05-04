/*
Package identity provides code for parsing, storing and retrieving Red Hat Cloud identity
from Go standard library context.

To use Go HTTP middleware (handler), pass the EnforceIdentity function to the multiplexer:

	r := mux.NewRouter()
	r.Use(identity.EnforceIdentity)

By default, both parsed and unparsed identities are stored in context.
To extract identity or raw identity (base64 JSON string) from a context, use functions
GetIdentity and GetRawIdentity:

	id := identity.GetIdentity(ctx)
	idRaw := identity.GetRawIdentity(ctx)

The default middleware performs no logging. To plug the middleware into the application
logging, use EnforceIdentityWithLogger:

	func ErrorLogFunc(ctx context.Context, rawId, msg string) {
		log := context.Value(myLoggerKey)
		log.Errorf("Identity error: %s, raw identity: %s", msg, rawId)
	}

	// Go standard HTTP library example
	handler := identity.EnforceIdentity(MyHandler())
	handler.ServeHTTP(rr, req)

	// Chi routing library example
	r := mux.NewRouter()
	r.Use(identity.EnforceIdentityWithLogger(ErrorLogFunc))
*/
package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// context key type and values
type identityKey int

// Internal is the "internal" field of an XRHID
type Internal struct {
	OrgID       string  `json:"org_id"`
	AuthTime    float32 `json:"auth_time,omitempty"`
	CrossAccess bool    `json:"cross_access,omitempty"`
}

// User is the "user" field of an XRHID
type User struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Active    bool   `json:"is_active"`
	OrgAdmin  bool   `json:"is_org_admin"`
	Internal  bool   `json:"is_internal"`
	Locale    string `json:"locale"`
	UserID    string `json:"user_id"`
}

// Associate is the "associate" field of an XRHID
type Associate struct {
	Role      []string `json:"Role"`
	Email     string   `json:"email"`
	GivenName string   `json:"givenName"`
	RHatUUID  string   `json:"rhatUUID"`
	Surname   string   `json:"surname"`
}

// X509 is the "x509" field of an XRHID
type X509 struct {
	SubjectDN string `json:"subject_dn"`
	IssuerDN  string `json:"issuer_dn"`
}

// System is the "system" field of an XRHID
type System struct {
	CommonName string `json:"cn,omitempty"`
	CertType   string `json:"cert_type,omitempty"`
	ClusterId  string `json:"cluster_id,omitempty"`
}

// Identity is the main body of the XRHID
type Identity struct {
	AccountNumber         string    `json:"account_number,omitempty"`
	EmployeeAccountNumber string    `json:"employee_account_number,omitempty"`
	OrgID                 string    `json:"org_id"`
	Internal              Internal  `json:"internal"`
	User                  User      `json:"user,omitempty"`
	System                System    `json:"system,omitempty"`
	Associate             Associate `json:"associate,omitempty"`
	X509                  X509      `json:"x509,omitempty"`
	Type                  string    `json:"type"`
	AuthType              string    `json:"auth_type,omitempty"`
}

// ServiceDetails describe the services the org is entitled to
type ServiceDetails struct {
	IsEntitled bool `json:"is_entitled"`
	IsTrial    bool `json:"is_trial"`
}

// XRHID is the "identity" principal object set by Cloud Platform 3scale
type XRHID struct {
	Identity     Identity                  `json:"identity"`
	Entitlements map[string]ServiceDetails `json:"entitlements"`
}

const (
	parsedKey identityKey = iota
	rawKey    identityKey = iota
)

// Get returns the identity struct from the context or empty value when not present.
// Deprecated in v2, use GetIdentity instead.
func Get(ctx context.Context) XRHID {
	return GetIdentity(ctx)
}

// With returns a copy of context with identity header as a value.
// Deprecated in v2, use WithIdentity instead.
func With(ctx context.Context, id XRHID) context.Context {
	return WithIdentity(ctx, id)
}

// GetIdentityHeader returns the identity header from the given context if one is present.
// Can be used to retrieve the header and pass it forward to other applications.
// Returns the empty string if identity headers cannot be found.
// Deprecated in v2, use WithRawIdentity instead.
func GetIdentityHeader(ctx context.Context) string {
	if id, ok := ctx.Value(parsedKey).(XRHID); ok {
		identityHeaders, err := json.Marshal(id)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(identityHeaders)
	}
	return ""
}

// EnforceIdentity extracts, checks and places the X-Rh-Identity header into the
// request context. If the Identity is invalid, the request will be aborted.
// No logging is performed, errors are returned with HTTP code 400 and plain
// text in response body. For more control of the logging or payload, use
// DecodeAndCheckIdentity and DecodeIdentityCtx exported functions and write
// your own middleware.
//
// Deprecated in v2, use EnforceIdentityWithLogger.
func EnforceIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := DecodeIdentityCtx(r.Context(), r.Header.Get("X-Rh-Identity"))
		if err != nil {
			http.Error(w, http.StatusText(400)+": "+err.Error(), 400)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetIdentity returns the identity struct from the context or empty value when not present.
func GetIdentity(ctx context.Context) XRHID {
	value := ctx.Value(parsedKey)
	if value == nil {
		return XRHID{}
	}
	return value.(XRHID)
}

// WithIdentity returns a copy of context with identity header as a value.
func WithIdentity(ctx context.Context, id XRHID) context.Context {
	return context.WithValue(ctx, parsedKey, id)
}

// GetRawIdentity returns the string identity struct from the context or empty string when not present.
func GetRawIdentity(ctx context.Context) string {
	value := ctx.Value(rawKey)
	if value == nil {
		return ""
	}
	return value.(string)
}

// WithRawIdentity returns a copy of context with identity header as a string value.
// This can be useful when identity needs to be passed somewhere else as string.
// Function EncodeIdentity can be used to construct raw identity from existing
// identity stored via WithIdentity.
func WithRawIdentity(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, rawKey, id)
}

// EncodeIdentity returns the identity header from the given context if one is present.
// Can be used to retrieve the header and pass it forward to other applications.
// Returns the empty string if identity headers cannot be found.
// This function performs JSON and base64 encoding on each call, consider using
// function WithRawIdentity to store and GetRawIdentity to fetch raw identity string.
func EncodeIdentity(ctx context.Context) string {
	if id, ok := ctx.Value(parsedKey).(XRHID); ok {
		identityHeaders, err := json.Marshal(id)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(identityHeaders)
	}
	return ""
}

var (
	ErrMissingIdentity      = errors.New("missing x-rh-identity header")
	ErrDecodeIdentity       = errors.New("unable to b64 decode x-rh-identity header")
	ErrInvalidOrgIdIdentity = errors.New("x-rh-identity header has an invalid or missing org_id")
	ErrMissingIdentityType  = errors.New("x-rh-identity header is missing type")
	ErrUnmarshalIdentity    = errors.New("x-rh-identity header does not contain valid JSON")
)

// checkBasePolicy performs semantic identity check and returns nil for valid values or
// an error instead.
func checkBasePolicy(id *XRHID) error {
	if (id.Identity.Type == "Associate" || id.Identity.Type == "X509") && id.Identity.AccountNumber == "" {
		return nil
	}

	if id.Identity.OrgID == "" && id.Identity.Internal.OrgID == "" {
		return ErrInvalidOrgIdIdentity
	}

	if id.Identity.Type == "" {
		return ErrMissingIdentityType
	}

	return nil
}

// DecodeIdentity returns identity value decoded from a base64 JSON encoded
// string.
//
// To put identity into a context, use WithIdentity or DecodeIdentityCtx functions.
func DecodeIdentity(header string) (XRHID, error) {
	if header == "" {
		return XRHID{}, ErrMissingIdentity
	}

	idRaw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return XRHID{}, ErrDecodeIdentity
	}

	var id XRHID
	err = json.Unmarshal(idRaw, &id)
	if err != nil {
		return XRHID{}, fmt.Errorf("%w: %w", ErrUnmarshalIdentity, err)
	}

	// If org_id is not defined at the top level, use the internal one.
	// See: https://issues.redhat.com/browse/RHCLOUD-17717
	if id.Identity.OrgID == "" && id.Identity.Internal.OrgID != "" {
		id.Identity.OrgID = id.Identity.Internal.OrgID
	}

	return id, nil
}

// DecodeAndCheckIdentity returns identity value decoded from a base64 JSON encoded
// string. The function performs series of checks and will return errors
// for invalid identities.
//
// To decode identity without performing any checks, use DecodeIdentity function.
//
// To put identity into a context, use WithIdentity or DecodeIdentityCtx functions.
func DecodeAndCheckIdentity(header string) (XRHID, error) {
	id, err := DecodeIdentity(header)
	if err != nil {
		return XRHID{}, err
	}

	err = checkBasePolicy(&id)
	if err != nil {
		return XRHID{}, err
	}

	return id, nil
}

// DecodeIdentityCtx decodes, checks and puts identity raw string and value into
// existing context. For more information about decode and validation process, read
// DecodeAndCheckIdentity function documentation.
func DecodeIdentityCtx(ctx context.Context, header string) (context.Context, error) {
	id, err := DecodeAndCheckIdentity(header)
	if err != nil {
		return ctx, err
	}
	nc := WithIdentity(ctx, id)
	nc = WithRawIdentity(nc, header)
	return nc, nil
}

// EnforceIdentityWithLogger extracts, checks and places the X-Rh-Identity header into the
// request context. If the Identity is invalid, the request will be aborted.
// Logging callback interface can be used to implement context-aware application
// logging.
func EnforceIdentityWithLogger(logger ErrorFunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Rh-Identity")
			ctx, err := DecodeIdentityCtx(r.Context(), id)
			if err != nil {
				msg := http.StatusText(400) + ": " + err.Error()
				logger(ctx, id, msg)
				http.Error(w, msg, 400)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
