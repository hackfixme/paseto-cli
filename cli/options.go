package cli

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/alecthomas/kong"

	"go.hackfix.me/paseto-cli/xpaseto"
	"go.hackfix.me/paseto-cli/xtime"
)

// ClaimsOption contains token claims passed via CLI arguments and stdin.
type ClaimsOption struct {
	fromArgs  map[string]any
	fromStdin map[string]any
}

// ClaimsMapper parses token claims from CLI arguments and stdin.
type ClaimsMapper struct {
	stdin io.Reader
}

var _ kong.Mapper = (*ClaimsMapper)(nil)

// Decode implements the kong.Mapper interface.
func (cm ClaimsMapper) Decode(kctx *kong.DecodeContext, target reflect.Value) error {
	var value string
	err := kctx.Scan.PopValueInto("claims", &value)
	if err != nil {
		return err
	}

	co := target.Interface().(ClaimsOption)
	if co.fromArgs == nil {
		co.fromArgs = make(map[string]any)
	}

	if value == "-" {
		if co.fromStdin != nil {
			// Already read stdin
			return nil
		}
		var err error
		co.fromStdin, err = readClaimsFromStdin(cm.stdin)
		if err != nil {
			return fmt.Errorf("failed reading claims from stdin: %w", err)
		}
	} else if kv := strings.SplitN(value, "=", 2); len(kv) == 2 {
		co.fromArgs[kv[0]] = kv[1]
	} else {
		return fmt.Errorf("must be in key=value format")
	}

	target.Set(reflect.ValueOf(co))

	return nil
}

// ExpirationMapper parses the token expiration duration or timestamp.
type ExpirationMapper struct {
	timeNow func() time.Time
}

var _ kong.Mapper = (*ExpirationMapper)(nil)

// Decode implements the kong.Mapper interface.
func (em ExpirationMapper) Decode(kctx *kong.DecodeContext, target reflect.Value) error {
	var value string
	err := kctx.Scan.PopValueInto("expiration", &value)
	if err != nil {
		return err
	}

	timeNow := em.timeNow()

	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		dur, err := xtime.ParseDuration(value)
		if err != nil {
			return err
		}
		t = timeNow.Add(dur)
	}

	if t.Before(timeNow) {
		return errors.New("expiration time is in the past")
	}

	target.Set(reflect.ValueOf(t))

	return nil
}

// // ExpirationOption is a custom option ...
// type ExpirationOption sql.NullTime

// ProtocolVersionOption is a custom option that parses the protocol version.
type ProtocolVersionOption paseto.Version

var _ encoding.TextUnmarshaler = (*ProtocolVersionOption)(nil)

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (o *ProtocolVersionOption) UnmarshalText(text []byte) error {
	ver, err := strconv.Atoi(string(text))
	if err != nil {
		return err
	}

	*o = ProtocolVersionOption(paseto.Version(fmt.Sprintf("v%d", ver)))

	return nil
}

// Validate implements kong's Validatable interface.
func (o *ProtocolVersionOption) Validate() error {
	if slices.Contains([]paseto.Version{paseto.Version2, paseto.Version3, paseto.Version4}, paseto.Version(*o)) {
		return nil
	}
	return errors.New("invalid version")
}

func readClaimsFromStdin(in io.Reader) (map[string]any, error) {
	if f, ok := in.(*os.File); ok {
		stat, err := f.Stat()
		if err != nil {
			panic(err)
		}

		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, errors.New("no data received on stdin")
		}
	}

	data, err := io.ReadAll(in)
	if err != nil {
		panic(err)
	}

	claims := make(map[string]any)
	if err = json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("failed unmarshaling JSON: %w", err)
	}

	return claims, nil
}

func mergeClaims(
	fromArgs, fromStdin map[string]any, expiration time.Time, isExpirationSet bool,
) []xpaseto.Claim {
	// Claims from args can override ones from stdin
	claimsInput := make(map[string]any)
	if fromStdin != nil {
		claimsInput = fromStdin
	}
	maps.Copy(claimsInput, fromArgs)

	claims := make([]xpaseto.Claim, 0, len(claimsInput))
	for code, value := range claimsInput {
		if code == "exp" && isExpirationSet {
			continue
		}
		claim := xpaseto.NewClaim(code, "", value)
		claims = append(claims, claim)
	}

	if isExpirationSet {
		claims = append(claims, xpaseto.ClaimExpiration(expiration))
	}

	return claims
}
