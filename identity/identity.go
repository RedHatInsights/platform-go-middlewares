package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
)

// Key the key for the XRHID in that gets added to the context
const Key identityKey = iota

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

func (j *XRHID) checkHeader(w http.ResponseWriter) error {

	var error_count int = 0 // number of errors encountered

	if j.Identity.AccountNumber == "" || j.Identity.AccountNumber == "-1" {
		doError(w, 400, "x-rh-identity header has an invalid or missing account number")
		error_count++
	}

	if j.Identity.Internal.OrgID == "" {
		doError(w, 400, "x-rh-identity header has an invalid or missing org_id")
		error_count++
	}

	if j.Identity.Type == "" {
		doError(w, 400, "x-rh-identity header is missing type")
		error_count++
	}

	// If the type of "Associate" is in place, this is a Turnpike internal request
	if j.Identity.Type == "Associate" {
		error_count = 0
	}

	if error_count> 0 {
		return errors.New("failed identity header check")
	}

	return nil

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

		err = jsonData.checkHeader(w)
		if err != nil {
			return
		}

		ctx := context.WithValue(r.Context(), Key, jsonData)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
