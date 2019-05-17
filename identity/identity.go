package identity

import (
	"net/http"
	"context"
	"encoding/base64"
	"encoding/json"
)

type key int

const IdentityKey key = iota

type Internal struct {
	Org_id string `json:org_id`
}

type XRhIdentity struct {
	Account_number string `json:"account_number"`
	Internal Internal `json:"internal"`
}

func getErrorText(code int, reason string) string {
	return http.StatusText(code) + ": " + reason
}

func doError(w http.ResponseWriter, code int, reason string) {
	http.Error(w, getErrorText(code, reason), code)
}

// Get returns the identity struct from the context
func Get(ctx context.Context) XRhIdentity {
	return ctx.Value(IdentityKey).(XRhIdentity)
}

// Identity extracts the X-Rh-Identity header and places the contents into the
// request context
func Identity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawHeaders := r.Header["X-Rh-Identity"]

		// must have an x-rh-id header
		if (len(rawHeaders) != 1) {
			doError(w, 400, "missing x-rh-identity header")
			return
		}

		// must be able to base64 decode header
		idRaw, err := base64.StdEncoding.DecodeString(rawHeaders[0])
		if (err != nil) {
			doError(w, 400, "unable to b64 decode x-rh-identity header")
			return
		}

		var jsonData XRhIdentity
		err = json.Unmarshal(idRaw, &jsonData)
		if (err != nil) {
			doError(w, 400, "x-rh-identity header is does not contain vaild JSON")
			return
		}

		if (jsonData.Account_number == "" || jsonData.Account_number == "-1") {
			doError(w, 400, "x-rh-identity header has an invalid or missing account number")
			return
		}

		if (jsonData.Internal.Org_id == "") {
			doError(w, 400, "x-rh-identity header has an invalid or missing org_id")
			return
		}

		ctx := context.WithValue(r.Context(), IdentityKey, jsonData)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
