package xpaseto

import (
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimTypes(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() Claim
		expCode  string
		expName  string
		expValue any
	}{
		{
			name:     "audience",
			fn:       func() Claim { return ClaimAudience("test-aud") },
			expCode:  "aud",
			expName:  "Audience",
			expValue: "test-aud",
		},
		{
			name:     "expiration",
			fn:       func() Claim { return ClaimExpiration(timeNow) },
			expCode:  "exp",
			expName:  "Expiration",
			expValue: timeNow,
		},
		{
			name:     "id",
			fn:       func() Claim { return ClaimID("test-id") },
			expCode:  "jti",
			expName:  "ID",
			expValue: "test-id",
		},
		{
			name:     "issued_at",
			fn:       func() Claim { return ClaimIssuedAt(timeNow) },
			expCode:  "iat",
			expName:  "Issued At",
			expValue: timeNow,
		},
		{
			name:     "issuer",
			fn:       func() Claim { return ClaimIssuer("test-iss") },
			expCode:  "iss",
			expName:  "Issuer",
			expValue: "test-iss",
		},
		{
			name:     "not_before",
			fn:       func() Claim { return ClaimNotBefore(timeNow) },
			expCode:  "nbf",
			expName:  "Not Before",
			expValue: timeNow,
		},
		{
			name:     "subject",
			fn:       func() Claim { return ClaimSubject("test-sub") },
			expCode:  "sub",
			expName:  "Subject",
			expValue: "test-sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := tt.fn()
			assert.Equal(t, tt.expCode, claim.Code)
			assert.Equal(t, tt.expName, claim.Name)
			assert.Equal(t, tt.expValue, claim.Value)
		})
	}
}

func TestRegisteredClaims(t *testing.T) {
	claims := RegisteredClaims()

	require.Len(t, claims, 7)

	codes := make([]string, len(claims))
	for i, claim := range claims {
		codes[i] = claim.Code
	}

	expectedCodes := []string{"jti", "iat", "nbf", "exp", "iss", "sub", "aud"}
	assert.ElementsMatch(t, expectedCodes, codes)

	for _, claim := range claims {
		switch claim.Code {
		case "jti", "iss", "sub", "aud":
			assert.Equal(t, "", claim.Value)
		case "iat", "nbf", "exp":
			assert.Equal(t, time.Time{}, claim.Value)
		}
	}
}

func TestNotBeforeNbf(t *testing.T) {
	tolerance := 5 * time.Second

	tests := []struct {
		name   string
		nbf    time.Time
		ref    time.Time
		expErr string
	}{
		{
			name: "ok/valid_time_before_nbf",
			nbf:  timeNow,
			ref:  timeNow.Add(1 * time.Hour),
		},
		{
			name: "ok/valid_time_equal_nbf",
			nbf:  timeNow,
			ref:  timeNow,
		},
		{
			name: "ok/valid_time_within_tolerance",
			nbf:  timeNow,
			ref:  timeNow.Add(-3 * time.Second),
		},
		{
			name:   "err/token_not_valid_yet",
			nbf:    timeNow,
			ref:    timeNow.Add(-10 * time.Second),
			expErr: "this token is not valid yet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			token.SetNotBefore(tt.nbf)

			rule := NotBeforeNbf(tt.ref, tolerance)
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("err/missing_nbf_claim", func(t *testing.T) {
		token := paseto.NewToken()
		rule := NotBeforeNbf(timeNow, tolerance)
		err := rule(token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not present in claims")
	})
}

func TestNotExpired(t *testing.T) {
	tolerance := 5 * time.Second

	tests := []struct {
		name   string
		exp    time.Time
		ref    time.Time
		expErr string
	}{
		{
			name: "ok/valid_time_before_exp",
			exp:  timeNow,
			ref:  timeNow.Add(-1 * time.Hour),
		},
		{
			name: "ok/valid_time_equal_exp",
			exp:  timeNow,
			ref:  timeNow,
		},
		{
			name: "ok/valid_time_within_tolerance",
			exp:  timeNow,
			ref:  timeNow.Add(3 * time.Second),
		},
		{
			name:   "err/token_expired",
			exp:    timeNow,
			ref:    timeNow.Add(10 * time.Second),
			expErr: "this token has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			token.SetExpiration(tt.exp)

			rule := NotExpired(tt.ref, tolerance)
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("err/missing_exp_claim", func(t *testing.T) {
		token := paseto.NewToken()
		rule := NotExpired(timeNow, tolerance)
		err := rule(token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not present in claims")
	})
}

func TestNotIssuedAfter(t *testing.T) {
	tolerance := 5 * time.Second

	tests := []struct {
		name   string
		iat    time.Time
		ref    time.Time
		expErr string
	}{
		{
			name: "ok/valid_time_after_iat",
			iat:  timeNow,
			ref:  timeNow.Add(1 * time.Hour),
		},
		{
			name: "ok/valid_time_equal_iat",
			iat:  timeNow,
			ref:  timeNow,
		},
		{
			name: "ok/valid_time_within_tolerance",
			iat:  timeNow,
			ref:  timeNow.Add(-3 * time.Second),
		},
		{
			name:   "err/future_issued_at",
			iat:    timeNow,
			ref:    timeNow.Add(-10 * time.Second),
			expErr: "this token has a future Issued At time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			token.SetIssuedAt(tt.iat)

			rule := NotIssuedAfter(tt.ref, tolerance)
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("err/missing_iat_claim", func(t *testing.T) {
		token := paseto.NewToken()
		rule := NotIssuedAfter(timeNow, tolerance)
		err := rule(token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not present in claims")
	})
}

func TestClaimTimeConsistency(t *testing.T) {
	tests := []struct {
		name   string
		iat    time.Time
		nbf    time.Time
		exp    time.Time
		expErr string
	}{
		{
			name: "ok/valid_time_sequence",
			iat:  timeNow,
			nbf:  timeNow.Add(1 * time.Hour),
			exp:  timeNow.Add(2 * time.Hour),
		},
		{
			name: "ok/all_times_equal",
			iat:  timeNow,
			nbf:  timeNow,
			exp:  timeNow,
		},
		{
			name: "ok/iat_equals_nbf_before_exp",
			iat:  timeNow,
			nbf:  timeNow,
			exp:  timeNow.Add(1 * time.Hour),
		},
		{
			name: "ok/iat_before_nbf_equals_exp",
			iat:  timeNow,
			nbf:  timeNow.Add(1 * time.Hour),
			exp:  timeNow.Add(1 * time.Hour),
		},
		{
			name:   "err/iat_after_exp",
			iat:    timeNow.Add(2 * time.Hour),
			nbf:    timeNow.Add(1 * time.Hour),
			exp:    timeNow,
			expErr: "Issued At time is after Expiration time",
		},
		{
			name:   "err/iat_after_nbf",
			iat:    timeNow.Add(2 * time.Hour),
			nbf:    timeNow.Add(1 * time.Hour),
			exp:    timeNow.Add(3 * time.Hour),
			expErr: "Issued At time is after Not Before time",
		},
		{
			name:   "err/nbf_after_exp",
			iat:    timeNow,
			nbf:    timeNow.Add(2 * time.Hour),
			exp:    timeNow.Add(1 * time.Hour),
			expErr: "Not Before time is after Expiration time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			token.SetIssuedAt(tt.iat)
			token.SetNotBefore(tt.nbf)
			token.SetExpiration(tt.exp)

			rule := ClaimTimeConsistency()
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("err/missing_iat_claim", func(t *testing.T) {
		token := paseto.NewToken()
		token.SetNotBefore(timeNow)
		token.SetExpiration(timeNow.Add(1 * time.Hour))

		rule := ClaimTimeConsistency()
		err := rule(token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not present in claims")
	})

	t.Run("err/missing_nbf_claim", func(t *testing.T) {
		token := paseto.NewToken()
		token.SetIssuedAt(timeNow)
		token.SetExpiration(timeNow.Add(1 * time.Hour))

		rule := ClaimTimeConsistency()
		err := rule(token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not present in claims")
	})

	t.Run("err/missing_exp_claim", func(t *testing.T) {
		token := paseto.NewToken()
		token.SetIssuedAt(timeNow)
		token.SetNotBefore(timeNow)

		rule := ClaimTimeConsistency()
		err := rule(token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not present in claims")
	})
}

func TestAllowAudiences(t *testing.T) {
	tests := []struct {
		name   string
		aud    string
		expErr string
	}{
		{
			name: "ok",
			aud:  "Test",
		},
		{
			name:   "err/missing_claim",
			aud:    "",
			expErr: "value for key `aud' not present in claims",
		},
		{
			name:   "err/not_allowed",
			aud:    "Test2",
			expErr: "audience 'Test2' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			if tt.aud != "" {
				token.SetAudience(tt.aud)
			}

			rule := AllowAudiences([]string{"Test"})
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAllowIssuers(t *testing.T) {
	tests := []struct {
		name   string
		iss    string
		expErr string
	}{
		{
			name: "ok",
			iss:  "Test",
		},
		{
			name:   "err/missing_claim",
			iss:    "",
			expErr: "value for key `iss' not present in claims",
		},
		{
			name:   "err/not_allowed",
			iss:    "Test2",
			expErr: "issuer 'Test2' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			if tt.iss != "" {
				token.SetIssuer(tt.iss)
			}

			rule := AllowIssuers([]string{"Test"})
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAllowSubjects(t *testing.T) {
	tests := []struct {
		name   string
		sub    string
		expErr string
	}{
		{
			name: "ok",
			sub:  "Test",
		},
		{
			name:   "err/missing_claim",
			sub:    "",
			expErr: "value for key `sub' not present in claims",
		},
		{
			name:   "err/not_allowed",
			sub:    "Test2",
			expErr: "subject 'Test2' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := paseto.NewToken()
			if tt.sub != "" {
				token.SetSubject(tt.sub)
			}

			rule := AllowSubjects([]string{"Test"})
			err := rule(token)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
