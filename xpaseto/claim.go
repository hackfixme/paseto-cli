package xpaseto

import (
	"time"
)

// Claim represents a token claim with a code, human-readable name, and value.
type Claim struct {
	Code  string
	Name  string
	Value any
}

// NewClaim creates a new claim with the specified code, name, and value.
func NewClaim(code, name string, value any) Claim {
	return Claim{
		Code:  code,
		Name:  name,
		Value: value,
	}
}

// ClaimAudience creates an audience claim with the specified value.
func ClaimAudience(aud string) Claim {
	return NewClaim("aud", "Audience", aud)
}

// ClaimExpiration creates an expiration claim with the specified time.
func ClaimExpiration(t time.Time) Claim {
	return NewClaim("exp", "Expiration", t)
}

// ClaimID creates an ID claim with the specified value.
func ClaimID(id string) Claim {
	return NewClaim("jti", "ID", id)
}

// ClaimIssuedAt creates an issued at claim with the specified time.
func ClaimIssuedAt(t time.Time) Claim {
	return NewClaim("iat", "Issued At", t)
}

// ClaimIssuer creates an issuer claim with the specified value.
func ClaimIssuer(iss string) Claim {
	return NewClaim("iss", "Issuer", iss)
}

// ClaimNotBefore creates a not before claim with the specified time.
func ClaimNotBefore(t time.Time) Claim {
	return NewClaim("nbf", "Not Before", t)
}

// ClaimSubject creates a subject claim with the specified value.
func ClaimSubject(sub string) Claim {
	return NewClaim("sub", "Subject", sub)
}

// StdClaims returns a slice of standard claims with empty values.
func StdClaims() []Claim {
	return []Claim{
		ClaimID(""),
		ClaimIssuedAt(time.Time{}),
		ClaimNotBefore(time.Time{}),
		ClaimExpiration(time.Time{}),
		ClaimIssuer(""),
		ClaimSubject(""),
		ClaimAudience(""),
	}
}
