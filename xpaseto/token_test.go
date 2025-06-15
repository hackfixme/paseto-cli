package xpaseto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	actx "go.hackfix.me/paseto-cli/app/context"
)

func TestNewToken(t *testing.T) {
	ts := &actx.MockTimeSource{T: timeNow}

	tests := []struct {
		name   string
		claims []Claim
		expErr string
		verify func(*testing.T, *Token)
	}{
		{
			name:   "ok/empty_claims_with_defaults",
			claims: []Claim{},
			verify: func(t *testing.T, tok *Token) {
				iat, err := tok.GetIssuedAt()
				require.NoError(t, err)
				assert.Equal(t, timeNow, iat)

				nbf, err := tok.GetNotBefore()
				require.NoError(t, err)
				assert.Equal(t, timeNow, nbf)

				exp, err := tok.GetExpiration()
				require.NoError(t, err)
				assert.Equal(t, timeNow.Add(defaultExpiration), exp)
			},
		},
		{
			name: "ok/string_claim",
			claims: []Claim{
				ClaimIssuer("test-issuer"),
			},
			verify: func(t *testing.T, tok *Token) {
				iss, err := tok.GetIssuer()
				require.NoError(t, err)
				assert.Equal(t, "test-issuer", iss)
			},
		},
		{
			name: "ok/time_claim",
			claims: []Claim{
				ClaimExpiration(timeNow.Add(2 * time.Hour)),
			},
			verify: func(t *testing.T, tok *Token) {
				exp, err := tok.GetExpiration()
				require.NoError(t, err)
				assert.Equal(t, timeNow.Add(2*time.Hour), exp)
			},
		},
		{
			name: "ok/custom_claim",
			claims: []Claim{
				NewClaim("role", "Role", "admin"),
			},
			verify: func(t *testing.T, tok *Token) {
				var role string
				err := tok.Get("role", &role)
				require.NoError(t, err)
				assert.Equal(t, "admin", role)
			},
		},
		{
			name: "ok/override_defaults",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(-time.Hour)),
				ClaimNotBefore(timeNow.Add(-30 * time.Minute)),
				ClaimExpiration(timeNow.Add(30 * time.Minute)),
			},
			verify: func(t *testing.T, tok *Token) {
				iat, err := tok.GetIssuedAt()
				require.NoError(t, err)
				assert.Equal(t, timeNow.Add(-time.Hour), iat)

				nbf, err := tok.GetNotBefore()
				require.NoError(t, err)
				assert.Equal(t, timeNow.Add(-30*time.Minute), nbf)

				exp, err := tok.GetExpiration()
				require.NoError(t, err)
				assert.Equal(t, timeNow.Add(30*time.Minute), exp)
			},
		},
		{
			name: "err/invalid_claim",
			claims: []Claim{
				NewClaim("invalid", "Invalid", make(chan int)), // channels can't be JSON marshaled
			},
			expErr: "failed creating new token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := NewToken(ts, tt.claims...)

			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tok)
			if tt.verify != nil {
				tt.verify(t, tok)
			}
		})
	}
}

func TestParseToken(t *testing.T) {
	ts := &actx.MockTimeSource{T: timeNow}

	keyTokens := createTestKeyTokens(t, ts)

	tests := []struct {
		name   string
		key    *Key
		token  string
		expErr string
		verify func(*testing.T, *Token)
	}{
		{
			name:   "ok/v4_local_token",
			key:    keyTokens["v4_local"].key,
			token:  keyTokens["v4_local"].token,
			verify: verifyTestIssuer,
		},
		{
			name:   "ok/v4_public_token",
			key:    keyTokens["v4_public"].key.Public(),
			token:  keyTokens["v4_public"].token,
			verify: verifyTestIssuer,
		},
		{
			name:   "ok/v3_local_token",
			key:    keyTokens["v3_local"].key,
			token:  keyTokens["v3_local"].token,
			verify: verifyTestIssuer,
		},
		{
			name:   "ok/v3_public_token",
			key:    keyTokens["v3_public"].key.Public(),
			token:  keyTokens["v3_public"].token,
			verify: verifyTestIssuer,
		},
		{
			name:   "ok/v2_local_token",
			key:    keyTokens["v2_local"].key,
			token:  keyTokens["v2_local"].token,
			verify: verifyTestIssuer,
		},
		{
			name:   "ok/v2_public_token",
			key:    keyTokens["v2_public"].key.Public(),
			token:  keyTokens["v2_public"].token,
			verify: verifyTestIssuer,
		},
		{
			name:   "err/invalid_token_format",
			key:    keyTokens["v4_local"].key,
			token:  "invalid-token",
			expErr: "failed parsing token",
		},
		{
			name:   "err/key_token_protocol_mismatch",
			key:    keyTokens["v3_local"].key,
			token:  keyTokens["v4_local"].token,
			expErr: ErrKeyTokenProtocolMismatch.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := ParseToken(tt.key, tt.token)

			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tok)
			if tt.verify != nil {
				tt.verify(t, tok)
			}
		})
	}
}

func TestTokenValidate(t *testing.T) {
	ts := &actx.MockTimeSource{T: timeNow}
	tolerance := 5 * time.Minute

	tests := []struct {
		name       string
		claims     []Claim
		timeSource actx.TimeSource
		tolerance  time.Duration
		extraRules []paseto.Rule
		expErr     string
	}{
		{
			name: "ok/valid_token",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(-time.Hour)),
				ClaimNotBefore(timeNow.Add(-30 * time.Minute)),
				ClaimExpiration(timeNow.Add(time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
		},
		{
			name: "ok/with_tolerance",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(2 * time.Minute)),
				ClaimNotBefore(timeNow.Add(2 * time.Minute)),
				ClaimExpiration(timeNow.Add(time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
		},
		{
			name: "err/future_issued_at",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(time.Hour)),
				ClaimNotBefore(timeNow.Add(time.Hour)),
				ClaimExpiration(timeNow.Add(2 * time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
			expErr:     "future Issued At time",
		},
		{
			name: "err/not_before_future",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(-time.Hour)),
				ClaimNotBefore(timeNow.Add(time.Hour)),
				ClaimExpiration(timeNow.Add(2 * time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
			expErr:     "not valid yet",
		},
		{
			name: "err/expired",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(-2 * time.Hour)),
				ClaimNotBefore(timeNow.Add(-90 * time.Minute)),
				ClaimExpiration(timeNow.Add(-time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
			expErr:     "expired",
		},
		{
			name: "err/time_inconsistency",
			claims: []Claim{
				ClaimIssuedAt(timeNow),
				ClaimNotBefore(timeNow.Add(-time.Hour)),
				ClaimExpiration(timeNow.Add(time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
			expErr:     "Issued At time is after Not Before time",
		},
		{
			name: "err/extra_rule_failure",
			claims: []Claim{
				ClaimIssuedAt(timeNow.Add(-time.Hour)),
				ClaimNotBefore(timeNow.Add(-30 * time.Minute)),
				ClaimExpiration(timeNow.Add(time.Hour)),
			},
			timeSource: ts,
			tolerance:  tolerance,
			extraRules: []paseto.Rule{
				func(token paseto.Token) error {
					return assert.AnError
				},
			},
			expErr: assert.AnError.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := NewToken(ts, tt.claims...)
			require.NoError(t, err)

			err = tok.Validate(tt.timeSource, tt.tolerance, tt.extraRules...)

			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTokenProtocol(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		expErr string
		verify func(*testing.T, paseto.Protocol)
	}{
		{
			name:  "ok/v4_local",
			token: "v4.local.test",
			verify: func(t *testing.T, p paseto.Protocol) {
				assert.Equal(t, paseto.V4Local, p)
			},
		},
		{
			name:  "ok/v4_public",
			token: "v4.public.test",
			verify: func(t *testing.T, p paseto.Protocol) {
				assert.Equal(t, paseto.V4Public, p)
			},
		},
		{
			name:  "ok/v3_local",
			token: "v3.local.test",
			verify: func(t *testing.T, p paseto.Protocol) {
				assert.Equal(t, paseto.V3Local, p)
			},
		},
		{
			name:  "ok/v3_public",
			token: "v3.public.test",
			verify: func(t *testing.T, p paseto.Protocol) {
				assert.Equal(t, paseto.V3Public, p)
			},
		},
		{
			name:  "ok/v2_local",
			token: "v2.local.test",
			verify: func(t *testing.T, p paseto.Protocol) {
				assert.Equal(t, paseto.V2Local, p)
			},
		},
		{
			name:  "ok/v2_public",
			token: "v2.public.test",
			verify: func(t *testing.T, p paseto.Protocol) {
				assert.Equal(t, paseto.V2Public, p)
			},
		},
		{
			name:   "err/invalid_header",
			token:  "invalid.token",
			expErr: "invalid token header",
		},
		{
			name:   "err/empty_token",
			token:  "",
			expErr: "invalid token header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocol, err := TokenProtocol(tt.token)

			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)
			if tt.verify != nil {
				tt.verify(t, protocol)
			}
		})
	}
}

func TestTokenWrite(t *testing.T) {
	ts := &actx.MockTimeSource{T: timeNow}

	tok, err := NewToken(ts,
		ClaimIssuer("test-issuer"),
		ClaimSubject("test-subject"),
		NewClaim("role", "Role", "admin"),
		NewClaim("scope", "Scope", "read"),
	)
	require.NoError(t, err)

	tests := []struct {
		name   string
		token  *Token
		format TokenFormat
		writer io.Writer
		expErr string
		verify func(*testing.T, string)
	}{
		{
			name:   "ok/text_format",
			token:  tok,
			format: TokenFormatText,
			writer: &bytes.Buffer{},
			verify: func(t *testing.T, output string) {
				assert.Contains(t, output, "Issuer:")
				assert.Contains(t, output, "test-issuer")
				assert.Contains(t, output, "Subject:")
				assert.Contains(t, output, "test-subject")
				assert.Contains(t, output, "Custom Claims")
				assert.Contains(t, output, "role:")
				assert.Contains(t, output, "admin")
				assert.Contains(t, output, "scope:")
				assert.Contains(t, output, "read")
			},
		},
		{
			name:   "ok/json_format",
			token:  tok,
			format: TokenFormatJSON,
			writer: &bytes.Buffer{},
			verify: func(t *testing.T, output string) {
				var claims map[string]any
				err := json.Unmarshal([]byte(output), &claims)
				require.NoError(t, err)
				assert.Equal(t, "test-issuer", claims["iss"])
				assert.Equal(t, "test-subject", claims["sub"])
				assert.Equal(t, "admin", claims["role"])
				assert.Equal(t, "read", claims["scope"])
			},
		},
		{
			name:   "err/invalid_format",
			token:  tok,
			format: TokenFormat("invalid"),
			writer: &bytes.Buffer{},
			expErr: "invalid token format",
		},
		{
			name:   "err/write_error_text",
			token:  tok,
			format: TokenFormatText,
			writer: &failingWriter{},
			expErr: "failed writing token data",
		},
		{
			name:   "err/write_error_json",
			token:  tok,
			format: TokenFormatJSON,
			writer: &failingWriter{},
			expErr: "failed writing token data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, ok := tt.writer.(*bytes.Buffer)
			if !ok {
				buf = &bytes.Buffer{}
			}

			err := tt.token.Write(tt.writer, tt.format)

			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)
			output := buf.String()
			if tt.verify != nil {
				tt.verify(t, output)
			}
		})
	}
}

// keyTokenPair holds a key and its corresponding encoded token
type keyTokenPair struct {
	key   *Key
	token string
}

// createTestKeyTokens creates all combinations of keys and tokens for testing
func createTestKeyTokens(t *testing.T, ts actx.TimeSource) map[string]keyTokenPair {
	testToken, err := NewToken(ts, ClaimIssuer("test"))
	require.NoError(t, err)

	versions := []paseto.Version{paseto.Version2, paseto.Version3, paseto.Version4}
	purposes := []paseto.Purpose{paseto.Local, paseto.Public}

	result := make(map[string]keyTokenPair)

	for _, ver := range versions {
		for _, purpose := range purposes {
			key, err := NewKey(ver, purpose, nil)
			require.NoError(t, err)

			var token string
			var keyName string

			if purpose == paseto.Local {
				token, err = key.Encrypt(testToken)
				keyName = fmt.Sprintf("%s_local", ver)
			} else {
				token, err = key.Sign(testToken)
				keyName = fmt.Sprintf("%s_public", ver)
			}
			require.NoError(t, err)

			result[keyName] = keyTokenPair{key: key, token: token}
		}
	}

	return result
}

// verifyTestIssuer is a common verification function
func verifyTestIssuer(t *testing.T, tok *Token) {
	iss, err := tok.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, "test", iss)
}

// failingWriter always returns an error on Write
type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	return 0, assert.AnError
}
