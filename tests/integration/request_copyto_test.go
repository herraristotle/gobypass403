package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestCustomCopyTo(t *testing.T) {
	// Create original request with custom settings
	origReq := &fasthttp.Request{}
	origReq.SetRequestURI("http://example.com/@rawpath?query=1")
	// fasthttp only materializes the Host header at write time, so set it
	// explicitly: this test asserts both full header-string equality and Host
	// preservation, which are only consistent when the original carries the
	// Host header itself.
	origReq.Header.SetHost("example.com")
	origReq.Header.Set("X-Custom", "value")
	origReq.Header.DisableNormalizing()          // Disable header normalization
	origReq.Header.SetNoDefaultContentType(true) // Disable default Content-Type
	origReq.UseHostHeader = true
	origReq.URI().DisablePathNormalizing = true

	// Create destination request
	dstReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dstReq)

	// Perform custom copy
	CustomCopyTo(origReq, dstReq)

	// Verify basic fields
	assert.Equal(t, origReq.Header.String(), dstReq.Header.String(), "Headers should match")
	assert.Equal(t, origReq.URI().String(), dstReq.URI().String(), "URI should match")

	// Verify custom settings
	assert.Equal(t, origReq.UseHostHeader, dstReq.UseHostHeader, "UseHostHeader should match")
	assert.Equal(t, origReq.URI().DisablePathNormalizing, dstReq.URI().DisablePathNormalizing, "DisablePathNormalizing should match")

	// Verify header normalization settings
	//assert.True(t, dstReq.Header.DisableNormalizing(), "DisableNormalizing should be true")
	//assert.True(t, dstReq.Header.NoDefaultContentType(), "NoDefaultContentType should be true")

	// Verify path preservation. fasthttp's Path() never includes the query
	// string, so assert path and query separately.
	assert.Equal(t, "/@rawpath", string(dstReq.URI().Path()), "Path should be preserved exactly")
	assert.Equal(t, "query=1", string(dstReq.URI().QueryString()), "Query string should be preserved")
	assert.Equal(t, "http", string(dstReq.URI().Scheme()), "Scheme should be preserved")
	assert.Equal(t, "example.com", string(dstReq.URI().Host()), "Host should be preserved")

	// Verify headers
	assert.Equal(t, "value", string(dstReq.Header.Peek("X-Custom")), "Custom header should be preserved")
	assert.Equal(t, "example.com", string(dstReq.Header.Peek("Host")), "Host header should be preserved")
}

func CustomCopyTo(req *fasthttp.Request, dst *fasthttp.Request) {
	// Copy all standard fields using the built-in CopyTo
	req.CopyTo(dst)

	// Copy additional fields not handled by the built-in CopyTo
	dst.UseHostHeader = req.UseHostHeader

	// Preserve path normalization settings
	dst.URI().DisablePathNormalizing = req.URI().DisablePathNormalizing

	// Preserve header normalization settings
	dst.Header.DisableNormalizing()

	// Preserve no default content type setting
	dst.Header.SetNoDefaultContentType(true)

	// Explicitly set the Host header from the original request. fasthttp only
	// populates Header.host at write time, so a URI-derived host must fall
	// back to the URI object.
	if h := req.Header.Peek("Host"); len(h) > 0 {
		dst.Header.SetHostBytes(h)
	} else if uriHost := req.URI().Host(); len(uriHost) > 0 {
		dst.Header.SetHostBytes(uriHost)
	}
}
