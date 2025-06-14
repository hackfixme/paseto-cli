package app

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/mandelsoft/vfs/pkg/vfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.hackfix.me/paseto-cli/xpaseto"
)

func TestAppGenkeyOK(t *testing.T) {
	t.Parallel()

	type expected struct {
		keyLen []int
	}
	testCases := []struct {
		purpose  paseto.Purpose
		version  paseto.Version
		encoding xpaseto.KeyEncoding
		out      string
		expected expected
	}{
		{
			purpose:  paseto.Local,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingHex,
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingHex,
			out:      string(paseto.Version2),
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingPEM,
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingPEM,
			out:      string(paseto.Version2),
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingHex,
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingHex,
			out:      string(paseto.Version3),
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingPEM,
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingPEM,
			out:      string(paseto.Version3),
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingHex,
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingHex,
			out:      string(paseto.Version4),
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingPEM,
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Local,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingPEM,
			out:      string(paseto.Version4),
			expected: expected{
				keyLen: []int{32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingHex,
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingHex,
			out:      string(paseto.Version2),
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingPEM,
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version2,
			encoding: xpaseto.KeyEncodingPEM,
			out:      string(paseto.Version2),
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingHex,
			expected: expected{
				keyLen: []int{48, 49},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingHex,
			out:      string(paseto.Version3),
			expected: expected{
				keyLen: []int{48, 49},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingPEM,
			expected: expected{
				keyLen: []int{48, 49},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version3,
			encoding: xpaseto.KeyEncodingPEM,
			out:      string(paseto.Version3),
			expected: expected{
				keyLen: []int{48, 49},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingHex,
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingHex,
			out:      string(paseto.Version4),
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingPEM,
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
		{
			purpose:  paseto.Public,
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingPEM,
			out:      string(paseto.Version4),
			expected: expected{
				keyLen: []int{64, 32},
			},
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		var (
			out  = "stdout"
			args = []string{"genkey"}
		)
		if tc.out != "" {
			out = "file"
			args = append(args, "--out-file", tc.out)
		}
		name := fmt.Sprintf("%s/%s/%s/%s", tc.purpose, tc.version, tc.encoding, out)
		t.Run(name, func(t *testing.T) {
			args = append(args,
				string(tc.purpose), "--protocol-version", string(tc.version)[1:],
				"--encoding", string(tc.encoding),
			)
			err = app.Run(args...)
			h(assert.NoError(t, err))
			h(assert.Empty(t, app.stderr.Bytes()))

			stdout := app.stdout.Bytes()
			outLines := bytes.Split(stdout, []byte("\n"))
			for i, expKeyLen := range tc.expected.keyLen {
				var (
					kt     = keyType(tc.purpose, i)
					keyEnc []byte
				)
				if tc.out == "" && tc.encoding == xpaseto.KeyEncodingHex && tc.purpose == paseto.Public {
					var (
						ktStr []byte
						found bool
					)
					ktStr, keyEnc, found = bytes.Cut(bytes.Trim(outLines[i], "\n"), []byte(": "))
					require.True(t, found)
					assert.Equal(t, kt.Long(), string(ktStr))
				} else if tc.out == "" {
					keyEnc = bytes.Trim(stdout, "\n")
				} else {
					path := fmt.Sprintf("/%s-%s.key", tc.version, kt.Short())
					keyEnc, err = vfs.ReadFile(app.ctx.FS, path)
					h(assert.NoError(t, err))
				}

				if tc.encoding == xpaseto.KeyEncodingHex {
					key := make([]byte, hex.DecodedLen(len(keyEnc)))
					n, err := hex.Decode(key, keyEnc)
					h(assert.NoError(t, err))
					h(assert.Equal(t, expKeyLen, n))
				} else {
					keyBlock, rest := pem.Decode(keyEnc)
					h(assert.NotNil(t, keyBlock))
					h(assert.Len(t, keyBlock.Bytes, expKeyLen))
					stdout = rest
				}
			}
		})
	}
}

func TestAppGenkeyErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		args   []string
		expErr string
	}{
		{
			name:   "missing_purpose",
			args:   []string{"genkey"},
			expErr: `expected "<protocol-purpose>"`,
		},
		{
			name:   "invalid_purpose",
			args:   []string{"genkey", "blah"},
			expErr: `<protocol-purpose> must be one of "local","public" but got "blah"`,
		},
		{
			name:   "invalid_encoding",
			args:   []string{"genkey", "local", "--encoding", "blah"},
			expErr: `--encoding must be one of "hex","pem" but got "blah"`,
		},
		{
			name:   "invalid_version",
			args:   []string{"genkey", "local", "--protocol-version", "1"},
			expErr: `--protocol-version: invalid version`,
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err = app.Run(tc.args...)
			h(assert.EqualError(t, err, tc.expErr))
			h(assert.Empty(t, app.stdout.Bytes()))
			h(assert.Empty(t, app.stderr.Bytes()))
		})
	}
}

func TestAppSignOK(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		version         paseto.Version
		encoding        xpaseto.KeyEncoding
		expiration      string
		claimsFromArgs  map[string]any
		claimsFromStdin map[string]any
		expClaims       map[string]any
	}{
		{
			name:     "v4/default_exp-no_claims",
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingHex,
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.Add(time.Hour).Format(time.RFC3339),
			},
		},
		{
			name:     "v4/default_exp-no_claims-pem",
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingPEM,
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.Add(time.Hour).Format(time.RFC3339),
			},
		},
		{
			name:       "v4/1d_exp-no_claims",
			version:    paseto.Version4,
			encoding:   xpaseto.KeyEncodingHex,
			expiration: "1d",
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			},
		},
		{
			name:           "v2/1d_exp-claims_from_args",
			version:        paseto.Version2,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			claimsFromArgs: map[string]any{"a": "1", "b": "2"},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
			},
		},
		{
			name:           "v3/1d_exp-claims_from_args",
			version:        paseto.Version3,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			claimsFromArgs: map[string]any{"a": "1", "b": "2"},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
			},
		},
		{
			name:           "v4/1d_exp-claims_from_args",
			version:        paseto.Version4,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     "1d",
			claimsFromArgs: map[string]any{"a": "1", "b": "2"},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
			},
		},
		{
			name:            "v4/1d_exp-claims_from_args_and_stdin",
			version:         paseto.Version4,
			encoding:        xpaseto.KeyEncodingHex,
			expiration:      "1d",
			claimsFromArgs:  map[string]any{"a": "1", "b": "2"},
			claimsFromStdin: map[string]any{"b": float64(20), "c": float64(3)},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
				"c":   float64(3),
			},
		},
		{
			name:           "v4/exp_from_claim_arg",
			version:        paseto.Version4,
			encoding:       xpaseto.KeyEncodingHex,
			claimsFromArgs: map[string]any{"exp": timeNow.AddDate(0, 0, 7).Format(time.RFC3339)},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 7).Format(time.RFC3339),
			},
		},
		{
			name:           "v4/exp_arg_overrides_claim_arg",
			version:        paseto.Version4,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     "1d",
			claimsFromArgs: map[string]any{"exp": timeNow.AddDate(0, 0, 7).Format(time.RFC3339)},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			},
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := xpaseto.NewKey(tc.version, paseto.Public, nil)
			h(assert.NoError(t, err))

			path := fmt.Sprintf("/%s-%s.key", tc.version, xpaseto.KeyTypePrivate.Short())
			f, err := app.ctx.FS.Create(path)
			h(assert.NoError(t, err))
			err = key.Write(f, tc.encoding, false)
			h(assert.NoError(t, err))

			args := []string{
				"sign", "--protocol-version", string(tc.version)[1:], "--key-file", path,
			}

			if tc.expiration != "" {
				args = append(args, "--expiration", tc.expiration)
			}
			for cn, cv := range tc.claimsFromArgs {
				args = append(args, "--claim", fmt.Sprintf("%s=%s", cn, cv))
			}

			if len(tc.claimsFromStdin) > 0 {
				args = append(args, "--claim", "-")
				go func() {
					defer app.stdin.Close()
					claimsJSON, err := json.Marshal(tc.claimsFromStdin)
					h(assert.NoError(t, err))
					_, err = app.stdin.Write(claimsJSON)
					h(assert.NoError(t, err))
				}()
			}

			err = app.Run(args...)
			h(assert.NoError(t, err))
			h(assert.Empty(t, app.stderr.Bytes()))

			stdout := strings.Trim(app.stdout.String(), "\n")
			tp, err := xpaseto.TokenProtocol(stdout)
			h(assert.Equal(t, fmt.Sprintf("%s.public.", tc.version), tp.Header()))

			token, err := xpaseto.ParseToken(key.Public(), stdout)
			h(assert.NoError(t, err))

			gotClaims := token.Claims()
			h(assert.Equal(t, tc.expClaims, gotClaims))
		})
	}
}

func TestAppSignErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		keyFile string
		args    []string
		expErr  string
	}{
		{
			name:   "missing_key_file_flag",
			args:   []string{"sign"},
			expErr: `missing flags: --key-file=STRING`,
		},
		{
			name:   "missing_key_file",
			args:   []string{"sign", "--key-file", "/missing.key"},
			expErr: `failed reading key file '/missing.key': file does not exist`,
		},
		{
			name:   "invalid_version",
			args:   []string{"sign", "--protocol-version", "1"},
			expErr: `--protocol-version: invalid version`,
		},
		{
			name:    "invalid_claim",
			keyFile: "/v4.key",
			args:    []string{"sign", "--claim", "blah"},
			expErr:  `--claim: must be in key=value format`,
		},
		{
			name:    "invalid_expiration_flag",
			keyFile: "/v4.key",
			args:    []string{"sign", "--expiration", timeNow.Add(-time.Hour).Format(time.RFC3339)},
			expErr:  `--expiration: expiration time is in the past`,
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args
			if tc.keyFile != "" {
				key, err := xpaseto.NewKey(paseto.Version4, paseto.Public, nil)
				h(assert.NoError(t, err))

				f, err := app.ctx.FS.Create(tc.keyFile)
				h(assert.NoError(t, err))
				err = key.Write(f, xpaseto.KeyEncodingHex, false)
				h(assert.NoError(t, err))

				args = append(args, "--key-file", tc.keyFile)
			}

			err = app.Run(args...)
			h(assert.EqualError(t, err, tc.expErr))
			h(assert.Empty(t, app.stdout.Bytes()))
			h(assert.Empty(t, app.stderr.Bytes()))
		})
	}
}

func TestAppEncryptOK(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		version         paseto.Version
		encoding        xpaseto.KeyEncoding
		expiration      string
		claimsFromArgs  map[string]any
		claimsFromStdin map[string]any
		expClaims       map[string]any
	}{
		{
			name:     "v4/default_exp-no_claims",
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingHex,
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.Add(time.Hour).Format(time.RFC3339),
			},
		},
		{
			name:     "v4/default_exp-no_claims-pem",
			version:  paseto.Version4,
			encoding: xpaseto.KeyEncodingPEM,
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.Add(time.Hour).Format(time.RFC3339),
			},
		},
		{
			name:       "v4/1d_exp-no_claims",
			version:    paseto.Version4,
			encoding:   xpaseto.KeyEncodingHex,
			expiration: "1d",
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			},
		},
		{
			name:           "v2/1d_exp-claims_from_args",
			version:        paseto.Version2,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			claimsFromArgs: map[string]any{"a": "1", "b": "2"},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
			},
		},
		{
			name:           "v3/1d_exp-claims_from_args",
			version:        paseto.Version3,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			claimsFromArgs: map[string]any{"a": "1", "b": "2"},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
			},
		},
		{
			name:           "v4/1d_exp-claims_from_args",
			version:        paseto.Version4,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     "1d",
			claimsFromArgs: map[string]any{"a": "1", "b": "2"},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
			},
		},
		{
			name:            "v4/1d_exp-claims_from_args_and_stdin",
			version:         paseto.Version4,
			encoding:        xpaseto.KeyEncodingHex,
			expiration:      "1d",
			claimsFromArgs:  map[string]any{"a": "1", "b": "2"},
			claimsFromStdin: map[string]any{"b": float64(20), "c": float64(3)},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
				"a":   "1",
				"b":   "2",
				"c":   float64(3),
			},
		},
		{
			name:           "v4/exp_from_claim_arg",
			version:        paseto.Version4,
			encoding:       xpaseto.KeyEncodingHex,
			claimsFromArgs: map[string]any{"exp": timeNow.AddDate(0, 0, 7).Format(time.RFC3339)},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 7).Format(time.RFC3339),
			},
		},
		{
			name:           "v4/exp_arg_overrides_claim_arg",
			version:        paseto.Version4,
			encoding:       xpaseto.KeyEncodingHex,
			expiration:     "1d",
			claimsFromArgs: map[string]any{"exp": timeNow.AddDate(0, 0, 7).Format(time.RFC3339)},
			expClaims: map[string]any{
				"iat": timeNow.Format(time.RFC3339),
				"nbf": timeNow.Format(time.RFC3339),
				"exp": timeNow.AddDate(0, 0, 1).Format(time.RFC3339),
			},
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := xpaseto.NewKey(tc.version, paseto.Local, nil)
			h(assert.NoError(t, err))

			path := fmt.Sprintf("/%s-%s.key", tc.version, xpaseto.KeyTypePrivate.Short())
			f, err := app.ctx.FS.Create(path)
			h(assert.NoError(t, err))
			err = key.Write(f, tc.encoding, false)
			h(assert.NoError(t, err))

			args := []string{
				"encrypt", "--protocol-version", string(tc.version)[1:], "--key-file", path,
			}

			if tc.expiration != "" {
				args = append(args, "--expiration", tc.expiration)
			}
			for cn, cv := range tc.claimsFromArgs {
				args = append(args, "--claim", fmt.Sprintf("%s=%s", cn, cv))
			}

			if len(tc.claimsFromStdin) > 0 {
				args = append(args, "--claim", "-")
				go func() {
					defer app.stdin.Close()
					claimsJSON, err := json.Marshal(tc.claimsFromStdin)
					h(assert.NoError(t, err))
					_, err = app.stdin.Write(claimsJSON)
					h(assert.NoError(t, err))
				}()
			}

			err = app.Run(args...)
			h(assert.NoError(t, err))
			h(assert.Empty(t, app.stderr.Bytes()))

			stdout := strings.Trim(app.stdout.String(), "\n")
			tp, err := xpaseto.TokenProtocol(stdout)
			h(assert.Equal(t, fmt.Sprintf("%s.local.", tc.version), tp.Header()))

			token, err := xpaseto.ParseToken(key, stdout)
			h(assert.NoError(t, err))

			gotClaims := token.Claims()
			h(assert.Equal(t, tc.expClaims, gotClaims))
		})
	}
}

func TestAppEncryptErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		keyFile string
		args    []string
		expErr  string
	}{
		{
			name:   "missing_key_file_flag",
			args:   []string{"encrypt"},
			expErr: `missing flags: --key-file=STRING`,
		},
		{
			name:   "missing_key_file",
			args:   []string{"encrypt", "--key-file", "/missing.key"},
			expErr: `failed reading key file '/missing.key': file does not exist`,
		},
		{
			name:   "invalid_version",
			args:   []string{"encrypt", "--protocol-version", "1"},
			expErr: `--protocol-version: invalid version`,
		},
		{
			name:    "invalid_claim",
			keyFile: "/v4.key",
			args:    []string{"encrypt", "--claim", "blah"},
			expErr:  `--claim: must be in key=value format`,
		},
		{
			name:    "invalid_expiration_flag",
			keyFile: "/v4.key",
			args:    []string{"encrypt", "--expiration", timeNow.Add(-time.Hour).Format(time.RFC3339)},
			expErr:  `--expiration: expiration time is in the past`,
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args
			if tc.keyFile != "" {
				key, err := xpaseto.NewKey(paseto.Version4, paseto.Local, nil)
				h(assert.NoError(t, err))

				f, err := app.ctx.FS.Create(tc.keyFile)
				h(assert.NoError(t, err))
				err = key.Write(f, xpaseto.KeyEncodingHex, false)
				h(assert.NoError(t, err))

				args = append(args, "--key-file", tc.keyFile)
			}

			err = app.Run(args...)
			h(assert.EqualError(t, err, tc.expErr))
			h(assert.Empty(t, app.stdout.Bytes()))
			h(assert.Empty(t, app.stderr.Bytes()))
		})
	}
}

func TestAppParseOK(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		variant   string
		purpose   paseto.Purpose
		version   paseto.Version
		encoding  xpaseto.KeyEncoding
		outputFmt xpaseto.TokenFormat
		claims    []xpaseto.Claim
		args      []string
		expOutput string
	}{
		{
			variant:   "claims_default",
			purpose:   paseto.Local,
			version:   paseto.Version2,
			encoding:  xpaseto.KeyEncodingHex,
			outputFmt: xpaseto.TokenFormatText,
			claims:    []xpaseto.Claim{},
			expOutput: "" +
				"Issued At:   2025-01-01 00:00:00 +0000 UTC  \n" +
				"Not Before:  2025-01-01 00:00:00 +0000 UTC  \n" +
				"Expiration:  2025-01-01 01:00:00 +0000 UTC  \n",
		},
		{
			variant:   "claims_default",
			purpose:   paseto.Public,
			version:   paseto.Version3,
			encoding:  xpaseto.KeyEncodingPEM,
			outputFmt: xpaseto.TokenFormatText,
			claims:    []xpaseto.Claim{},
			expOutput: "" +
				"Issued At:   2025-01-01 00:00:00 +0000 UTC  \n" +
				"Not Before:  2025-01-01 00:00:00 +0000 UTC  \n" +
				"Expiration:  2025-01-01 01:00:00 +0000 UTC  \n",
		},
		{
			variant:   "claims_default",
			purpose:   paseto.Public,
			version:   paseto.Version4,
			encoding:  xpaseto.KeyEncodingPEM,
			outputFmt: xpaseto.TokenFormatText,
			claims:    []xpaseto.Claim{},
			expOutput: "" +
				"Issued At:   2025-01-01 00:00:00 +0000 UTC  \n" +
				"Not Before:  2025-01-01 00:00:00 +0000 UTC  \n" +
				"Expiration:  2025-01-01 01:00:00 +0000 UTC  \n",
		},
		{
			// The token is expired, but no error is expected since validation is disabled.
			variant:   "token_expired_no_validate",
			purpose:   paseto.Public,
			version:   paseto.Version4,
			encoding:  xpaseto.KeyEncodingPEM,
			outputFmt: xpaseto.TokenFormatText,
			claims: []xpaseto.Claim{
				xpaseto.ClaimIssuedAt(timeNow.AddDate(0, 0, -7)),
				xpaseto.ClaimNotBefore(timeNow.AddDate(0, 0, -7)),
				xpaseto.ClaimExpiration(timeNow.AddDate(0, 0, -1)),
			},
			args: []string{"--no-validate"},
			expOutput: "" +
				"Issued At:   2024-12-25 00:00:00 +0000 UTC  \n" +
				"Not Before:  2024-12-25 00:00:00 +0000 UTC  \n" +
				"Expiration:  2024-12-31 00:00:00 +0000 UTC  \n",
		},
		{
			variant:   "exp_custom_claims",
			purpose:   paseto.Local,
			version:   paseto.Version2,
			encoding:  xpaseto.KeyEncodingHex,
			outputFmt: xpaseto.TokenFormatText,
			claims: []xpaseto.Claim{
				xpaseto.ClaimExpiration(timeNow.AddDate(0, 0, 7)),
				xpaseto.NewClaim("a", "", 1),
				xpaseto.NewClaim("b", "", 2),
			},
			expOutput: "" +
				"Issued At:   2025-01-01 00:00:00 +0000 UTC  \n" +
				"Not Before:  2025-01-01 00:00:00 +0000 UTC  \n" +
				"Expiration:  2025-01-08 00:00:00 +0000 UTC  \n\n" +
				"Custom Claims\n" +
				"-------------\n" +
				"a:    1     \n" +
				"b:    2     \n",
		},
		{
			variant:   "exp_custom_claims_json",
			purpose:   paseto.Local,
			version:   paseto.Version2,
			encoding:  xpaseto.KeyEncodingHex,
			outputFmt: xpaseto.TokenFormatJSON,
			claims: []xpaseto.Claim{
				xpaseto.ClaimExpiration(timeNow.AddDate(0, 0, 7)),
				xpaseto.NewClaim("a", "", 1),
				xpaseto.NewClaim("b", "", 2),
			},
			expOutput: `{
  "a": 1,
  "b": 2,
  "exp": "2025-01-08T00:00:00Z",
  "iat": "2025-01-01T00:00:00Z",
  "nbf": "2025-01-01T00:00:00Z"
}`,
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		name := fmt.Sprintf("%s/%s/%s/%s", tc.purpose, tc.version, tc.encoding, tc.variant)
		t.Run(name, func(t *testing.T) {
			key, err := xpaseto.NewKey(tc.version, tc.purpose, nil)
			h(assert.NoError(t, err))

			kt := xpaseto.KeyTypeSymmetric
			op := key.Encrypt
			if tc.purpose == paseto.Public {
				kt = xpaseto.KeyTypePrivate
				op = key.Sign
				key = key.Public()
			}
			path := fmt.Sprintf("/%s-%s.key", tc.version, kt.Short())
			f, err := app.ctx.FS.Create(path)
			h(assert.NoError(t, err))
			err = key.Write(f, tc.encoding, false)
			h(assert.NoError(t, err))

			token, err := xpaseto.NewToken(app.ctx.Time, tc.claims...)
			h(assert.NoError(t, err))

			tkStr, err := op(token)
			h(assert.NoError(t, err))

			args := []string{
				"parse", "--key-file", path,
				"--output-format", string(tc.outputFmt), tkStr,
			}

			args = append(args, tc.args...)

			err = app.Run(args...)
			h(assert.NoError(t, err))
			h(assert.Empty(t, app.stderr.Bytes()))
			h(assert.Equal(t, tc.expOutput, app.stdout.String()))
		})
	}
}

func TestAppParseErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		purpose  paseto.Purpose
		version  paseto.Version
		encoding xpaseto.KeyEncoding
		keyFile  string
		token    []byte
		claims   []xpaseto.Claim
		args     []string
		expErr   string
	}{
		{
			name:    "missing_key_file_flag",
			purpose: paseto.Local,
			version: paseto.Version2,
			expErr:  `missing flags: --key-file=STRING`,
		},
		{
			name:    "missing_token",
			purpose: paseto.Local,
			version: paseto.Version2,
			token:   []byte(""),
			keyFile: "/v2-sym.key",
			expErr:  `missing positional arguments <token>`,
		},
		{
			name:    "malformed_token",
			purpose: paseto.Local,
			version: paseto.Version2,
			token:   []byte("blah"),
			keyFile: "/v2-sym.key",
			expErr:  `invalid token header`,
		},
		{
			name:    "invalid_output_format",
			purpose: paseto.Local,
			version: paseto.Version2,
			keyFile: "/v2-sym.key",
			args:    []string{"--output-format", "blah"},
			expErr:  `--output-format must be one of "text","json" but got "blah"`,
		},
		{
			name:    "missing_key_file",
			purpose: paseto.Local,
			version: paseto.Version2,
			token:   []byte("v4.public.blah"),
			args:    []string{"--key-file", "/missing.key"},
			expErr:  `failed reading key file '/missing.key': file does not exist`,
		},
		{
			name:    "expired_token",
			keyFile: "/v2-sym.key",
			purpose: paseto.Local,
			version: paseto.Version2,
			claims: []xpaseto.Claim{
				xpaseto.ClaimIssuedAt(timeNow.Add(-2 * time.Hour)),
				xpaseto.ClaimNotBefore(timeNow.Add(-2 * time.Hour)),
				xpaseto.ClaimExpiration(timeNow.Add(-time.Hour)),
			},
			expErr: `invalid token: this token has expired`,
		},
		{
			name:    "iat_future",
			keyFile: "/v2-sym.key",
			purpose: paseto.Local,
			version: paseto.Version2,
			claims: []xpaseto.Claim{
				xpaseto.ClaimIssuedAt(timeNow.Add(time.Hour)),
				xpaseto.ClaimNotBefore(timeNow.Add(time.Hour)),
				xpaseto.ClaimExpiration(timeNow.Add(2 * time.Hour)),
			},
			expErr: `invalid token: this token has a future Issued At time`,
		},
		{
			name:    "iat_after_exp",
			keyFile: "/v2-sym.key",
			purpose: paseto.Local,
			version: paseto.Version2,
			claims: []xpaseto.Claim{
				xpaseto.ClaimIssuedAt(timeNow),
				xpaseto.ClaimNotBefore(timeNow),
				xpaseto.ClaimExpiration(timeNow.Add(-time.Hour)),
			},
			expErr: `invalid token: Issued At time is after Expiration time`,
		},
		{
			name:    "iat_after_nbf",
			keyFile: "/v2-sym.key",
			purpose: paseto.Local,
			version: paseto.Version2,
			claims: []xpaseto.Claim{
				xpaseto.ClaimIssuedAt(timeNow.Add(time.Hour)),
				xpaseto.ClaimNotBefore(timeNow),
				xpaseto.ClaimExpiration(timeNow.Add(2 * time.Hour)),
			},
			expErr: `invalid token: Issued At time is after Not Before time`,
		},
		{
			name:    "nbf_after_exp",
			keyFile: "/v2-sym.key",
			purpose: paseto.Local,
			version: paseto.Version2,
			claims: []xpaseto.Claim{
				xpaseto.ClaimIssuedAt(timeNow),
				xpaseto.ClaimNotBefore(timeNow.Add(2 * time.Hour)),
				xpaseto.ClaimExpiration(timeNow.Add(time.Hour)),
			},
			expErr: `invalid token: Not Before time is after Expiration time`,
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := xpaseto.NewKey(tc.version, tc.purpose, nil)
			h(assert.NoError(t, err))

			op := key.Encrypt
			if tc.purpose == paseto.Public {
				op = key.Sign
				key = key.Public()
			}

			args := []string{"parse"}
			if tc.keyFile != "" {
				f, err := app.ctx.FS.Create(tc.keyFile)
				h(assert.NoError(t, err))
				err = key.Write(f, xpaseto.KeyEncodingHex, false)
				h(assert.NoError(t, err))
				args = append(args, "--key-file", tc.keyFile)
			}

			token, err := xpaseto.NewToken(app.ctx.Time, tc.claims...)
			h(assert.NoError(t, err))

			args = append(args, tc.args...)

			if len(tc.token) > 0 {
				args = append(args, string(tc.token))
			} else if tc.token == nil {
				tkStr, err := op(token)
				h(assert.NoError(t, err))
				args = append(args, tkStr)
			}

			err = app.Run(args...)
			h(assert.EqualError(t, err, tc.expErr))
			h(assert.Empty(t, app.stdout.Bytes()))
			h(assert.Empty(t, app.stderr.Bytes()))
		})
	}
}

func keyType(p paseto.Purpose, i int) xpaseto.KeyType {
	if p == paseto.Local {
		return xpaseto.KeyTypeSymmetric
	}
	if i == 0 {
		return xpaseto.KeyTypePrivate
	}
	return xpaseto.KeyTypePublic
}
