/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Expansion decision for Addendum 5 Phase B (feedback-expand).

Given a confirmed hit (a response whose status class improved on the target's
baseline), decide what to send next: a bounded, depth-1 batch derived from the
shape that worked. Pure and deterministic — the scanner supplies the confirmed
request, the set of RawURIs it already sent, and a Composer for the path
family. Nothing here mutates an existing module's payload set or the registry.

Depth 1 is structural: Mutate only ever derives from the confirmed request, so
an expansion batch cannot be expanded again.
*/
package expand

import (
	"net"
	"strconv"
	"strings"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// Hard caps (approved plan).
const (
	PerHit    = 256  // extra requests per confirmed hit
	PerTarget = 1024 // extra requests per target, across all modules
)

// Supported module names (the registry itself is append-only and never
// touched by expansion).
const (
	ModulePathPrefix              = "path_prefix"
	ModuleMidPaths                = "mid_paths"
	ModuleEndPaths                = "end_paths"
	ModuleCharEncode              = "char_encode"
	ModuleCaseSubstitution        = "case_substitution"
	ModuleNginxBypasses           = "nginx_bypasses"
	ModuleHaproxyBypasses         = "haproxy_bypasses"
	ModuleUnicodePathNormalize    = "unicode_path_normalization"
	ModuleUnicodePathTruncate     = "unicode_path_truncation"
	ModuleUnicodePathExperimental = "unicode_path_experimental"
	ModuleHTTPMethods             = "http_methods"
	ModuleHeadersMethod           = "headers_method"
	ModuleHeadersIP               = "headers_ip"
)

var pathFamily = map[string]bool{
	ModulePathPrefix:              true,
	ModuleMidPaths:                true,
	ModuleEndPaths:                true,
	ModuleCharEncode:              true,
	ModuleCaseSubstitution:        true,
	ModuleNginxBypasses:           true,
	ModuleHaproxyBypasses:         true,
	ModuleUnicodePathNormalize:    true,
	ModuleUnicodePathTruncate:     true,
	ModuleUnicodePathExperimental: true,
}

var methodFamily = map[string]bool{
	ModuleHTTPMethods:   true,
	ModuleHeadersMethod: true,
}

// methodTokens are the method names a header may carry (headers_method).
var methodTokens = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
	"PROPFIND": true, "MKCOL": true, "COPY": true, "MOVE": true, "LOCK": true,
	"UNLOCK": true, "PURGE": true, "DEBUG": true,
}

// Supported reports whether the module has a Phase-B mutator family. Every
// other module expands to nothing (an explicit, documented limit rather than
// a guess).
func Supported(module string) bool {
	return pathFamily[module] || methodFamily[module] || module == ModuleHeadersIP
}

// Composer regenerates a module's candidate requests for an arbitrary
// RawURI. The scanner supplies it (it owns the generator configuration), so
// path-family expansion is "run the module's own transformation once more,
// against the shape that worked" instead of a reimplementation that could
// drift from the module it is imitating.
type Composer interface {
	Compose(rawURI string) []payload.BypassPayload
}

// Request is a confirmed hit plus what the scanner has already sent.
type Request struct {
	Module  string
	Payload payload.BypassPayload // the request that worked
	Sent    []string              // RawURIs already requested for this module
}

// Mutate returns the derived requests for a confirmed hit: deterministic
// order, deduped against Sent and itself, at most PerHit and at most budget.
// A nil/empty result means "send nothing".
func Mutate(req Request, composer Composer, budget int) []payload.BypassPayload {
	if budget <= 0 || !Supported(req.Module) {
		return nil
	}
	if budget > PerHit {
		budget = PerHit
	}

	// RawURIs already requested. Only the path family uses this: a derived
	// request must target a shape that has not been tried yet. Method/header
	// families keep the confirmed RawURI on purpose.
	sentURIs := make(map[string]bool, len(req.Sent)+1)
	for _, uri := range req.Sent {
		sentURIs[uri] = true
	}
	sentURIs[req.Payload.RawURI] = true

	// Full request shapes already produced. The key covers method,
	// request-target and headers, so method/header twins of one RawURI do not
	// shadow each other, and the confirmed request is excluded.
	seen := map[string]bool{requestKey(req.Payload): true}
	out := make([]payload.BypassPayload, 0, budget)

	// add appends p unless its full request shape was already produced.
	add := func(p payload.BypassPayload) {
		if len(out) >= budget {
			return
		}
		k := requestKey(p)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, p)
	}

	switch {
	case pathFamily[req.Module]:
		if composer == nil {
			return nil
		}
		for _, p := range composer.Compose(req.Payload.RawURI) {
			if sentURIs[p.RawURI] {
				continue
			}
			sentURIs[p.RawURI] = true
			add(p)
		}

	case req.Module == ModuleHTTPMethods:
		for _, m := range methodTwins(req.Payload.Method) {
			p := req.Payload
			p.Method = m
			add(p)
		}

	case req.Module == ModuleHeadersMethod:
		name, value, ok := methodHeader(req.Payload)
		if ok {
			for _, m := range methodTwins(value) {
				p := req.Payload
				p.Headers = replaceHeader(req.Payload.Headers, name, m)
				add(p)
			}
		}

	case req.Module == ModuleHeadersIP:
		name, value, ok := ipHeader(req.Payload)
		if ok {
			for _, v := range ipVariants(value) {
				p := req.Payload
				p.Headers = replaceHeader(req.Payload.Headers, name, v)
				add(p)
			}
		}
	}

	return out
}

// requestKey identifies a full request shape for dedupe purposes: the
// path-family variants differ in RawURI, the method family in Method, and the
// header family in a header value.
func requestKey(p payload.BypassPayload) string {
	var b strings.Builder
	b.WriteString(p.Method)
	b.WriteByte(0)
	b.WriteString(p.RawURI)
	for _, h := range p.Headers {
		b.WriteByte(0)
		b.WriteString(h.Header)
		b.WriteByte(':')
		b.WriteString(h.Value)
	}
	return b.String()
}

// methodTwins returns case-permutation and trailing-space siblings of a
// method, deterministically ordered. The plain lowercase/uppercase twins come
// first because that is the pair that already defeats case-insensitive
// comparison in practice (see the http_methods lowercase twins).
func methodTwins(method string) []string {
	if method == "" {
		return nil
	}
	lower := strings.ToLower(method)
	upper := strings.ToUpper(method)

	var out []string
	seen := map[string]bool{}
	push := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	push(lower)
	push(upper)
	push(lower + " ")
	push(upper + " ")

	// Remaining case permutations, in binary counting order, bounded so a
	// long method cannot explode the batch (the PerHit cap also applies).
	const maxPermutations = 32
	letters := 0
	for i := 0; i < len(upper); i++ {
		if upper[i] >= 'A' && upper[i] <= 'Z' {
			letters++
		}
		if letters > 16 {
			break
		}
	}
	if letters <= 16 {
		for mask := 1; mask < 1<<letters; mask++ {
			var b strings.Builder
			bit := 0
			for i := 0; i < len(upper); i++ {
				c := upper[i]
				if c >= 'A' && c <= 'Z' {
					if mask&(1<<bit) != 0 {
						c = c + ('a' - 'A')
					}
					bit++
				}
				b.WriteByte(c)
			}
			push(b.String())
			if len(out) >= maxPermutations {
				break
			}
		}
	}
	return out
}

// methodHeader finds the method-valued header of a headers_method payload.
func methodHeader(p payload.BypassPayload) (name, value string, ok bool) {
	for _, h := range p.Headers {
		if methodTokens[strings.ToUpper(strings.TrimSpace(h.Value))] {
			return h.Header, h.Value, true
		}
	}
	return "", "", false
}

// ipHeader finds the first header carrying an IPv4 value.
func ipHeader(p payload.BypassPayload) (name, value string, ok bool) {
	for _, h := range p.Headers {
		if isIPv4(h.Value) {
			return h.Header, h.Value, true
		}
	}
	return "", "", false
}

func isIPv4(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.To4() != nil
}

// ipVariants returns alternative notations and neighbours of an IPv4 value
// (loopback/private-address spoofing: middleboxes and ACLs parse these
// differently). Deterministic order; unknown notation -> nothing.
func ipVariants(value string) []string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	a, b, c, d := v4[0], v4[1], v4[2], v4[3]
	dotted := strconv.Itoa(int(a)) + "." + strconv.Itoa(int(b)) + "." +
		strconv.Itoa(int(c)) + "." + strconv.Itoa(int(d))

	var out []string
	seen := map[string]bool{}
	push := func(s string) {
		if s == "" || s == value || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	// Single-integer, octal-dotted and hex notations of the same address.
	asUint32 := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
	push(strconv.FormatUint(uint64(asUint32), 10))
	push(octalDotted(a, b, c, d))
	push("0x" + strconv.FormatUint(uint64(asUint32), 16))
	push("::ffff:" + dotted)

	// Short forms valid in inet_aton-style parsers.
	if b == 0 && c == 0 {
		push(strconv.Itoa(int(a)) + "." + strconv.Itoa(int(d)))
	} else if c == 0 {
		push(strconv.Itoa(int(a)) + "." + strconv.Itoa(int(b)) + "." + strconv.Itoa(int(d)))
	}

	// Neighbouring address in the same /24 (same host, next IP).
	if d < 255 {
		push(strconv.Itoa(int(a)) + "." + strconv.Itoa(int(b)) + "." +
			strconv.Itoa(int(c)) + "." + strconv.Itoa(int(d+1)))
	}
	return out
}

// octalDotted renders 127.0.0.1 as 0177.0.0.1 (leading zero marks an octal
// octet; octets below 8 render the same in both bases, so they stay plain).
func octalDotted(octets ...byte) string {
	parts := make([]string, 0, len(octets))
	for _, o := range octets {
		octal := strconv.FormatUint(uint64(o), 8)
		if o >= 8 {
			octal = "0" + octal
		}
		parts = append(parts, octal)
	}
	return strings.Join(parts, ".")
}

// replaceHeader returns headers with the named header's value replaced
// (first match), leaving every other header untouched.
func replaceHeader(headers []payload.Headers, name, value string) []payload.Headers {
	out := make([]payload.Headers, len(headers))
	copy(out, headers)
	for i := range out {
		if out[i].Header == name {
			out[i].Value = value
			break
		}
	}
	return out
}
