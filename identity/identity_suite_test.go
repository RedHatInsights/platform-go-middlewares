package identity_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redhatinsights/platform-go-middlewares/v2/identity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// example header based on x-rh-identity seen in stage env
var exampleHeader = `
{
  "entitlements": {
    "insights": {
      "is_entitled": true,
      "is_trial": false
    },
    "cost_management": {
      "is_entitled": true,
      "is_trial": false
    }
  },
  "identity": {
    "internal": {
      "cross_access": false,
      "auth_time": 0,
      "org_id": "1979710"
    },
    "user": {
      "is_active": true,
      "locale": "en_US",
      "is_org_admin": true,
      "username": "Test",
      "email": "test@test.com",
      "first_name": "Test",
      "user_id": "55555555",
      "last_name": "User",
      "is_internal": true
    },
    "auth_type": "jwt-auth",
    "org_id": "1979710",
    "account_number": "540155",
    "type": "User"
  }
}
`

var serviceAccountIdentity = `
{
  "identity": {
    "account_number": "540155",
    "auth_type": "jwt-auth",
    "internal": {},
    "org_id": "1979710",
    "service_account": {
      "client_id": "0000",
      "username": "jdoe"
    },
    "type": "ServiceAccount"
  }
}
`

var validJson = [...]string{
	`{ "identity": {"account_number": "540155", "auth_type": "jwt-auth", "org_id": "1979710", "type": "User", "internal": {"org_id": "1979710"} } }`,
	`{ "identity": {"account_number": "540155", "auth_type": "cert-auth", "org_id": "1979710", "type": "Associate", "internal": {"org_id": "1979710"} } }`,
	`{ "identity": {"account_number": "540155", "auth_type": "basic-auth", "type": "Associate", "internal": {"org_id": "1979710"} } }`,
	`{ "identity": {"account_number": "540155", "auth_type": "cert-auth", "org_id": "1979710", "type": "Associate", "internal": {} } }`,
	exampleHeader,
	serviceAccountIdentity,
}

func GetTestHandler(allowPass bool) http.HandlerFunc {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		if !allowPass {
			panic("test entered test handler, this should not happen")
		}
	}

	return http.HandlerFunc(fn)
}

func boilerWithCustomHandler(req *http.Request, expectedStatusCode int, expectedBody string, handlerFunc http.HandlerFunc) {
	rr := httptest.NewRecorder()

	handler := identity.EnforceIdentity(handlerFunc)
	handler.ServeHTTP(rr, req)

	Expect(rr.Body.String()).To(Equal(expectedBody))
	Expect(rr.Code).To(Equal(expectedStatusCode))
	Expect(rr.Body.String()).To(Equal(expectedBody))
}

func boiler(req *http.Request, expectedStatusCode int, expectedBody string) {
	rr := httptest.NewRecorder()
	handler := identity.EnforceIdentity(GetTestHandler(expectedStatusCode == 200))
	handler.ServeHTTP(rr, req)

	Expect(rr.Code).To(Equal(expectedStatusCode))
	Expect(rr.Body.String()).To(Equal(expectedBody))
}

func noopLogger(ctx context.Context, rawId, msg string) {
}

func boilerWithLogger(req *http.Request, expectedStatusCode int, expectedBody string) {
	rr := httptest.NewRecorder()

	handler := identity.EnforceIdentityWithLogger(noopLogger)
	handler(GetTestHandler(expectedStatusCode == 200)).ServeHTTP(rr, req)

	Expect(rr.Code).To(Equal(expectedStatusCode))
	Expect(rr.Body.String()).To(Equal(expectedBody))
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
		if err != nil {
			panic("Test error unable to get a NewRequest")
		}
		req = r
	})

	Context("WithIdentity a valid x-rh-id header", func() {
		It("should 200 and set raw identity on the context", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))

				boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						raw := identity.GetRawIdentity(nreq.Context())
						id, err1 := identity.DecodeAndCheckIdentity(raw)
						Expect(err1).To(BeNil())
						Expect(id.Identity.OrgID).To(Equal("1979710"))
						Expect(id.Identity.AccountNumber).To(Equal("540155"))
					}
					return http.HandlerFunc(fn)
				}())
			}
		})

		It("should 200 and set the org_id on the context", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))

				boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						id := identity.GetIdentity(nreq.Context())
						Expect(id.Identity.OrgID).To(Equal("1979710"))
						Expect(id.Identity.AccountNumber).To(Equal("540155"))
					}
					return http.HandlerFunc(fn)
				}())
			}
		})

		It("should 200 and set the entitlements on the context", func() {
			req.Header.Set("x-rh-identity", getBase64(exampleHeader))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id := identity.GetIdentity(nreq.Context())
					Expect(id.Entitlements["insights"].IsEntitled).To(BeTrue())
					Expect(id.Entitlements["cost_management"].IsEntitled).To(BeTrue())
				}
				return http.HandlerFunc(fn)
			}())
		})

		It("should be able to return the header again if headers are requested", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))

				boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						h := identity.EncodeIdentity(nreq.Context())
						Expect(h).ToNot(BeEmpty())
					}
					return http.HandlerFunc(fn)
				}())
			}
		})
	})

	Context("WithIdentity a valid x-rh-id header and logger", func() {
		It("should throw a 400 with a descriptive message", func() {
			boilerWithLogger(req, 400, "Bad Request: missing x-rh-identity header\n")
		})
	})

	Context("WithIdentity a missing x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			boiler(req, 400, "Bad Request: missing x-rh-identity header\n")
		})

		It("should return empty string if headers are requested", func() {
			boilerWithCustomHandler(req, 400, "Bad Request: missing x-rh-identity header\n", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					h := identity.EncodeIdentity(nreq.Context())
					Expect(h).To(BeEmpty())
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("WithIdentity invalid b64 data in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", "="+getBase64(jsonIdentity))
				boiler(req, 400, "Bad Request: unable to b64 decode x-rh-identity header\n")
			}
		})
	})

	Context("WithIdentity invalid json data (valid b64) in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity+"}"))
				boiler(req, 400, "Bad Request: x-rh-identity header does not contain valid JSON: invalid character '}' after top-level value\n")
			}
		})

		It("should return empty string if headers are requested", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity+"}"))
				boilerWithCustomHandler(req, 400, "Bad Request: x-rh-identity header does not contain valid JSON: invalid character '}' after top-level value\n", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						h := identity.EncodeIdentity(nreq.Context())
						Expect(h).To(BeEmpty())
					}
					return http.HandlerFunc(fn)
				}())
			}
		})
	})

	Context("WithIdentity missing account_number in the x-rh-id header", func() {
		It("should 200", func() {
			req.Header.Set("x-rh-identity", getBase64(`{ "identity": {"org_id": "1979710", "auth_type": "basic-auth", "type": "Associate", "internal": {"org_id": "1979710"} } }`))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id := identity.GetIdentity(nreq.Context())
					Expect(id.Identity.OrgID).To(Equal("1979710"))
					Expect(id.Identity.Internal.OrgID).To(Equal("1979710"))
					Expect(id.Identity.AccountNumber).To(Equal(""))
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("WithIdentity a valid x-rh-id header", func() {
		It("should 200 and set the type to associate", func() {
			req.Header.Set("x-rh-identity", getBase64(`{ "identity": {"type": "Associate"} }`))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id := identity.GetIdentity(nreq.Context())
					Expect(id.Identity.Type).To(Equal("Associate"))
				}
				return http.HandlerFunc(fn)
			}())
		})

		It("should 200 and set the type to X509", func() {
			req.Header.Set("x-rh-identity", getBase64(`{"identity": {"type": "X509"}}`))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id := identity.GetIdentity(nreq.Context())
					Expect(id.Identity.Type).To(Equal("X509"))
				}
				return http.HandlerFunc(fn)
			}())
		})

		It("should 200 and set the correct values for a ServiceAccount identity", func() {
			req.Header.Set("x-rh-identity", getBase64(serviceAccountIdentity))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id := identity.Get(nreq.Context())
					Expect(id.Identity.Type).To(Equal("ServiceAccount"))
					Expect(id.Identity.ServiceAccount.Username).To(Equal("jdoe"))
					Expect(id.Identity.ServiceAccount.ClientId).To(Equal("0000"))
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("WithIdentity missing org_id in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			var missingOrgIDJson = [...]string{
				`{ "identity": {"account_number": "540155", "type": "User", "internal": {} } }`,
			}

			for _, jsonIdentity := range missingOrgIDJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))
				boiler(req, 400, "Bad Request: x-rh-identity header has an invalid or missing org_id\n")
			}
		})
	})

	Context("WithIdentity missing type in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", getBase64(`{"identity":{"account_number":"540155","type":"", "org_id":"1979710", "internal": {"org_id": "1979710"}}}`))
			boiler(req, 400, "Bad Request: x-rh-identity header is missing type\n")
		})
	})
})
