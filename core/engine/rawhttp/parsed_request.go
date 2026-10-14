/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package rawhttp

import (
	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// ParsedRequest holds a full raw HTTP request imported from a --request-file
// (issue #2, phase 2). It becomes the base request every bypass module
// mutates: Method/Body feed the payload generator, RawURI seeds path
// variants, and Headers/Host are injected into every generated payload.
type ParsedRequest struct {
	Method  string            // HTTP method from the request line
	RawURI  string            // origin-form request-target (path + optional query)
	Headers []payload.Headers // imported headers (Host and Content-Length excluded)
	Host    string            // Host header value ("" when absent)
	Body    string            // verbatim body after the header section
}
