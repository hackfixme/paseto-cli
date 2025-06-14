package xpaseto

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
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

// NotBeforeNbf checks that the token has a valid "nbf" field, and that its time
// is before the given time. This is the same rule as paseto.NotBeforeNbf, just
// with a time argument.
func NotBeforeNbf(t time.Time, tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		nbf, err := token.GetNotBefore()
		if err != nil {
			return err
		}

		if t.Before(nbf.Add(-tolerance)) {
			return fmt.Errorf("this token is not valid yet")
		}

		return nil
	}
}

// NotExpired checks that the token has a valid "exp" field, and that its time
// is after the given time. This is the same rule as paseto.NotExpired, just
// with a time argument.
func NotExpired(t time.Time, tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}

		if t.After(exp.Add(tolerance)) {
			return fmt.Errorf("this token has expired")
		}

		return nil
	}
}

// NotIssuedAfter checks that the token has a valid "iat" field, and that its
// time is before the given time. This is a subset of the paseto.ValidAt rule.
func NotIssuedAfter(t time.Time, tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		iat, err := token.GetIssuedAt()
		if err != nil {
			return err
		}

		if t.Before(iat.Add(-tolerance)) {
			return fmt.Errorf("this token has a future Issued At time")
		}

		return nil
	}
}

// ClaimTimeConsistency checks that the "iat", "nbf", and "exp" fields exist and
// are valid, and that their times are consistent with each other.
// Specifically it checks that iat <= nbf <= exp.
func ClaimTimeConsistency() paseto.Rule {
	return func(token paseto.Token) error {
		iat, err := token.GetIssuedAt()
		if err != nil {
			return err
		}

		nbf, err := token.GetNotBefore()
		if err != nil {
			return err
		}

		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}

		if iat.After(exp) {
			return fmt.Errorf("Issued At time is after Expiration time")
		}

		if iat.After(nbf) {
			return fmt.Errorf("Issued At time is after Not Before time")
		}

		if nbf.After(exp) {
			return fmt.Errorf("Not Before time is after Expiration time")
		}

		return nil
	}
}
