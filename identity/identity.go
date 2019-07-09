package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

type identityKey int

// Key the key for the XRHID in that gets added to the context
const Key identityKey = iota

// Internal is the "internal" field of an XRHID
type Internal struct {
	OrgID string `json:"org_id"`
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
}

// Identity is the main body of the XRHID
type Identity struct {
	AccountNumber string                 `json:"account_number"`
	Internal      Internal               `json:"internal"`
	User          User                   `json:"user,omitempty"`
	System        map[string]interface{} `json:"system,omitempty"`
}

// XRHID is the "identity" pricipal object set by Cloud Platform 3scale
type XRHID struct {
	Identity Identity `json:"identity"`
}

func getErrorText(code int, reason string) string {
	return http.StatusText(code) + ": " + reason
}

func doError(w http.ResponseWriter, code int, reason string) {
	http.Error(w, getErrorText(code, reason), code)
}

// Get returns the identity struct from the context
func Get(ctx context.Context) XRHID {
	return ctx.Value(Key).(XRHID)
}

// EnforceIdentity extracts the X-Rh-Identity header and places the contents into the
// request context.  If the Identity is invalid, the request will be aborted.
func EnforceIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawHeaders := r.Header["X-Rh-Identity"]

		// must have an x-rh-id header
		if len(rawHeaders) != 1 {
			doError(w, 400, "missing x-rh-identity header")
			return
		}

		// must be able to base64 decode header
		idRaw, err := base64.StdEncoding.DecodeString(rawHeaders[0])
		if err != nil {
			doError(w, 400, "unable to b64 decode x-rh-identity header")
			return
		}

		var jsonData XRHID
		err = json.Unmarshal(idRaw, &jsonData)
		if err != nil {
			doError(w, 400, "x-rh-identity header is does not contain valid JSON")
			return
		}

		if jsonData.Identity.AccountNumber == "" || jsonData.Identity.AccountNumber == "-1" {
			doError(w, 400, "x-rh-identity header has an invalid or missing account number")
			return
		}

		if jsonData.Identity.Internal.OrgID == "" {
			doError(w, 400, "x-rh-identity header has an invalid or missing org_id")
			return
		}

		ctx := context.WithValue(r.Context(), Key, jsonData)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
