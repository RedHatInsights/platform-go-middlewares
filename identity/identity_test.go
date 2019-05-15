package identity

import (
	"strings"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

const validJson = `{ "account_number": "540155", "type": "User", "internal": { "org_id": "1979710" } }`

func GetTestHandler(allowPass bool) http.HandlerFunc {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		if (!allowPass) {
			panic("test entered test handler, this should not happen")
		}
	}

	return http.HandlerFunc(fn)
}

func boiler(t *testing.T, req *http.Request, expectedStatusCode int, expectedBody string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler := Identity(GetTestHandler(expectedStatusCode == 200))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != expectedStatusCode {
		t.Errorf("handler returned wrong status code: got %v want %v", status, expectedStatusCode)
	}

	if rr.Body.String() != expectedBody {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedBody)
	}

	return rr
}

func getBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func TestIdentitySetsOrgIdOnValidXRHID(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	req.Header.Set("x-rh-identity", getBase64(validJson))
	boiler(t, req, 200, "")

	// TODO test that the org_id gets on to the context
	// TODO test that the account_number gets on to the context

	// var expected = "1979710"
	// var ctxOrgId = req.Context().Value("org_id").(string)
	// if (ctxOrgId != expected) {
	// 	t.Errorf("unexpected or missing org_id on context: got %s want %s", ctxOrgId, expected)
	// }
}

func TestIdentityShouldNotAcceptMissingXHRID(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	boiler(t, req, 400, "Bad Request: missing x-rh-identity header\n")
}

func TestIdentityFailOnBadB64Data(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	req.Header.Set("x-rh-identity", "=" + getBase64(validJson))
	boiler(t, req, 400, "Bad Request: unable to b64 decode x-rh-identity header\n")
}

func TestIdentityFailOnInvalidJson(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	req.Header.Set("x-rh-identity", getBase64(validJson + "}"))
	boiler(t, req, 400, "Bad Request: x-rh-identity header is does not contain vaild JSON\n")
}

func TestIdentityFailOnMissingAccountNumber(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	req.Header.Set("x-rh-identity", getBase64(`{ "type": "User", "internal": { "org_id": "1979710" } }`))
	boiler(t, req, 400, "Bad Request: x-rh-identity header has an invalid or missing account number\n")
}

func TestIdentityFailOnInvalidAccountNumber(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	req.Header.Set("x-rh-identity", getBase64(strings.Replace(validJson, "540155", "-1", 1)))
	boiler(t, req, 400, "Bad Request: x-rh-identity header has an invalid or missing account number\n")
}

func TestIdentityFailOnMissingOrgId(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
	req.Header.Set("x-rh-identity", getBase64(strings.Replace(validJson, `"org_id": "1979710"`, "", 1)))
	boiler(t, req, 400, "Bad Request: x-rh-identity header has an invalid or missing org_id\n")
}
