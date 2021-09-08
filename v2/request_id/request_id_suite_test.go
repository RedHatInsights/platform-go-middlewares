package request_id_test

import (
	"testing"

	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/redhatinsights/platform-go-middlewares/v2/request_id"
)

func TestRequestId(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RequestId Suite")
}

func getHandlerFunc(allowPass bool) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowPass {
			panic("test entered test handler, this should not happen")
		}
	})
}

var _ = Describe("Request ID", func() {

	var (
		req *http.Request
		rr  *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		req, _ = http.NewRequest("GET", "/", nil)
		rr = httptest.NewRecorder()
	})

	Context("With No X-Request-Id header", func() {
		It("should add in a header", func() {
			handler := request_id.RequestID(getHandlerFunc(true))
			handler.ServeHTTP(rr, req)
			Expect(rr.Header().Get("X-Request-Id")).NotTo(Equal(""))
		})
	})

	Context("With an already set X-Request-Id header", func() {
		It("should preserve the header", func() {
			req.Header.Set("X-Request-Id", "testing")
			handler := request_id.RequestID(getHandlerFunc(true))
			handler.ServeHTTP(rr, req)
			Expect(req.Header.Get("X-Request-Id")).To(Equal("testing"))
		})
	})

	Context("With every request", func() {
		It("should put a header in the response", func() {
			handler := request_id.RequestID(getHandlerFunc(true))
			handler.ServeHTTP(rr, req)
			Expect(rr.Header().Get("X-Request-Id")).NotTo(BeNil())
		})
	})

	Context("With ConfiguredRequestID", func() {
		It("can be set to use a different header", func() {
			handler := request_id.ConfiguredRequestID("X-Rh-Request-Id")(getHandlerFunc(true))
			handler.ServeHTTP(rr, req)
			Expect(rr.Header().Get("X-Request-Id")).To(Equal(""))
			Expect(rr.Header().Get("X-Rh-Request-Id")).NotTo(Equal(""))
		})
	})
})
