package identity_test

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"encoding/base64"
	"strings"
	"github.com/RedHatInsights/platform-go-middlewares/identity"


	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

func boiler(req *http.Request, expectedStatusCode int, expectedBody string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler := identity.Identity(GetTestHandler(expectedStatusCode == 200))
	handler.ServeHTTP(rr, req)

	Expect(rr.Code).To(Equal(expectedStatusCode))
	Expect(rr.Body.String()).To(Equal(expectedBody))

	return rr
}

func getBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func TestIdentity(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Identity Suite")
}

var _ = Describe("Identity", func() {
	var req *http.Request
	BeforeEach(func() {
		r, err := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
		if (err != nil) { panic("Test error unable to get a NewRequest") }
		req = r
	})

	Context("With a valid x-rh-id header", func() {
		It("should 200 and set the org_id on the context", func() {
			req.Header.Set("x-rh-identity", getBase64(validJson))
			boiler(req, 200, "")
		})
	})

	Context("With a missing x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			boiler(req, 400, "Bad Request: missing x-rh-identity header\n")
		})
	})

	Context("With invalid b64 data in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", "=" + getBase64(validJson))
			boiler(req, 400, "Bad Request: unable to b64 decode x-rh-identity header\n")
		})
	})

	Context("With invalid json data (valid b64) in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", getBase64(validJson + "}"))
			boiler(req, 400, "Bad Request: x-rh-identity header is does not contain vaild JSON\n")
		})
	})

	Context("With missing account_number in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", getBase64(`{ "type": "User", "internal": { "org_id": "1979710" } }`))
			boiler(req, 400, "Bad Request: x-rh-identity header has an invalid or missing account number\n")
		})
	})

	Context("With a -1 account_number in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", getBase64(strings.Replace(validJson, "540155", "-1", 1)))
			boiler(req, 400, "Bad Request: x-rh-identity header has an invalid or missing account number\n")
		})
	})

	Context("With missing org_id in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", getBase64(strings.Replace(validJson, `"org_id": "1979710"`, "", 1)))
			boiler(req, 400, "Bad Request: x-rh-identity header has an invalid or missing org_id\n")
		})
	})
})
