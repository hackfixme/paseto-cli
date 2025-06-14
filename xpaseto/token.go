package xpaseto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"aidanwoods.dev/go-paseto"

	actx "go.hackfix.me/paseto-cli/app/context"
)

// TokenFormat represents the output format for token display.
type TokenFormat string

const (
	TokenFormatText TokenFormat = "text"
	TokenFormatJSON TokenFormat = "json"
)

// Token represents a PASETO token with claims.
type Token struct {
	*paseto.Token
}

const defaultExpiration = time.Hour

// NewToken creates a new token with the specified claims.
// Default claims (iat, nbf, exp) are automatically added if not provided.
func NewToken(ts actx.TimeSource, claims ...Claim) (*Token, error) {
	token := paseto.NewToken()

	for _, c := range claims {
		switch val := c.Value.(type) {
		case string:
			token.SetString(c.Code, val)
		case time.Time:
			token.SetTime(c.Code, val)
		default:
			if err := token.Set(c.Code, c.Value); err != nil {
				return nil, fmt.Errorf("failed creating new token: %w", err)
			}
		}
	}

	var (
		setClaims = token.Claims()
		now       = ts.Now()
	)
	if _, ok := setClaims["iat"]; !ok {
		token.SetIssuedAt(now)
	}
	if _, ok := setClaims["nbf"]; !ok {
		token.SetNotBefore(now)
	}
	if _, ok := setClaims["exp"]; !ok {
		token.SetExpiration(now.Add(defaultExpiration))
	}

	return &Token{&token}, nil
}

// ParseToken parses a PASETO token string using the provided key.
func ParseToken(key *Key, token string) (*Token, error) {
	tp, err := TokenProtocol(token)
	if err != nil {
		return nil, fmt.Errorf("failed parsing token: %w", err)
	}
	if tp.Version() != key.version || tp.Purpose() != key.purpose {
		return nil, ErrKeyTokenProtocolMismatch
	}

	var (
		parser = paseto.MakeParser(nil)
		tk     *paseto.Token
	)
	switch key.version {
	case paseto.Version2:
		if key.purpose == paseto.Local {
			tk, err = parser.ParseV2Local(key.key.(paseto.V2SymmetricKey), token)
		} else {
			tk, err = parser.ParseV2Public(key.key.(paseto.V2AsymmetricPublicKey), token)
		}
	case paseto.Version3:
		if key.purpose == paseto.Local {
			tk, err = parser.ParseV3Local(key.key.(paseto.V3SymmetricKey), token, nil)
		} else {
			tk, err = parser.ParseV3Public(key.key.(paseto.V3AsymmetricPublicKey), token, nil)
		}
	case paseto.Version4:
		if key.purpose == paseto.Local {
			tk, err = parser.ParseV4Local(key.key.(paseto.V4SymmetricKey), token, nil)
		} else {
			tk, err = parser.ParseV4Public(key.key.(paseto.V4AsymmetricPublicKey), token, nil)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed parsing token: %w", err)
	}

	return &Token{tk}, nil
}

// Validate validates the token against default and additional rules.
func (tk *Token) Validate(
	ts actx.TimeSource, timeSkewTolerance time.Duration,
	extraRules ...paseto.Rule,
) (err error) {
	defaultRules := []paseto.Rule{
		ClaimTimeConsistency(),
		NotIssuedAfter(ts.Now(), timeSkewTolerance),
		NotBeforeNbf(ts.Now(), timeSkewTolerance),
		NotExpired(ts.Now(), timeSkewTolerance),
	}

	rules := append(defaultRules, extraRules...)

	for _, rule := range rules {
		if err = rule(*tk.Token); err != nil {
			return fmt.Errorf("invalid token: %w", err)
		}
	}

	return nil
}

// Write writes the token to the specified writer in the given format.
func (tk *Token) Write(w io.Writer, f TokenFormat) (err error) {
	switch f {
	case TokenFormatText:
		tw := tabwriter.NewWriter(w, 6, 2, 2, ' ', 0)

		seenClaims := map[string]bool{}
		for _, claim := range StdClaims() {
			valPtr := reflect.New(reflect.TypeOf(claim.Value))
			err = tk.Get(claim.Code, valPtr.Interface())
			if err != nil {
				if strings.Contains(err.Error(), "not present in claims") {
					continue
				}
				return fmt.Errorf("failed marshaling token data to text: %w", err)
			}
			seenClaims[claim.Code] = true
			_, err = fmt.Fprintln(tw, fmt.Sprintf("%s:\t%v\t", claim.Name, valPtr.Elem().Interface()))
			if err != nil {
				return fmt.Errorf("failed writing token data: %w", err)
			}
		}

		customClaims := []Claim{}
		for code, val := range tk.Claims() {
			if seenClaims[code] {
				continue
			}
			customClaims = append(customClaims, NewClaim(code, "", val))
		}

		slices.SortFunc(customClaims, func(a, b Claim) int {
			return strings.Compare(a.Code, b.Code)
		})

		if len(customClaims) > 0 {
			_, err = fmt.Fprintln(tw, "\nCustom Claims")
			if err != nil {
				return fmt.Errorf("failed writing token data: %w", err)
			}
			_, err = fmt.Fprintln(tw, "-------------")
			if err != nil {
				return fmt.Errorf("failed writing token data: %w", err)
			}
			for _, cc := range customClaims {
				_, err = fmt.Fprintln(tw, fmt.Sprintf("%s:\t%v\t", cc.Code, cc.Value))
				if err != nil {
					return fmt.Errorf("failed writing token data: %w", err)
				}
			}
		}

		err = tw.Flush()
		if err != nil {
			return fmt.Errorf("failed writing token data: %w", err)
		}
	case TokenFormatJSON:
		m, err := json.MarshalIndent(tk.Claims(), "", "  ")
		if err != nil {
			return fmt.Errorf("failed marshaling token data to JSON: %w", err)
		}
		_, err = w.Write(m)
		if err != nil {
			return fmt.Errorf("failed writing token data: %w", err)
		}
	default:
		return fmt.Errorf("invalid token format: %v", f)
	}

	return nil
}

// TokenProtocol determines the PASETO protocol from a token string.
func TokenProtocol(token string) (paseto.Protocol, error) {
	switch {
	case strings.HasPrefix(token, paseto.V4Local.Header()):
		return paseto.V4Local, nil
	case strings.HasPrefix(token, paseto.V4Public.Header()):
		return paseto.V4Public, nil
	case strings.HasPrefix(token, paseto.V3Local.Header()):
		return paseto.V3Local, nil
	case strings.HasPrefix(token, paseto.V3Public.Header()):
		return paseto.V3Public, nil
	case strings.HasPrefix(token, paseto.V2Local.Header()):
		return paseto.V2Local, nil
	case strings.HasPrefix(token, paseto.V2Public.Header()):
		return paseto.V2Public, nil
	}

	return paseto.Protocol{}, errors.New("invalid token header")
}
