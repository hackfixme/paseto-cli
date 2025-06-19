package xpaseto

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKey(t *testing.T) {
	tests := []struct {
		name      string
		version   paseto.Version
		purpose   paseto.Purpose
		key       key
		expType   KeyType
		expPublic bool
		expErr    string
		expPanic  bool
		panicType string
	}{
		{
			name:      "ok/v2_local_nil_key",
			version:   paseto.Version2,
			purpose:   paseto.Local,
			key:       nil,
			expType:   KeyTypeSymmetric,
			expPublic: false,
		},
		{
			name:      "ok/v2_public_nil_key",
			version:   paseto.Version2,
			purpose:   paseto.Public,
			key:       nil,
			expType:   KeyTypePrivate,
			expPublic: true,
		},
		{
			name:      "ok/v3_local_nil_key",
			version:   paseto.Version3,
			purpose:   paseto.Local,
			key:       nil,
			expType:   KeyTypeSymmetric,
			expPublic: false,
		},
		{
			name:      "ok/v3_public_nil_key",
			version:   paseto.Version3,
			purpose:   paseto.Public,
			key:       nil,
			expType:   KeyTypePrivate,
			expPublic: true,
		},
		{
			name:      "ok/v4_local_nil_key",
			version:   paseto.Version4,
			purpose:   paseto.Local,
			key:       nil,
			expType:   KeyTypeSymmetric,
			expPublic: false,
		},
		{
			name:      "ok/v4_public_nil_key",
			version:   paseto.Version4,
			purpose:   paseto.Public,
			key:       nil,
			expType:   KeyTypePrivate,
			expPublic: true,
		},
		{
			name:      "ok/v2_local_with_key",
			version:   paseto.Version2,
			purpose:   paseto.Local,
			key:       paseto.NewV2SymmetricKey(),
			expType:   KeyTypeSymmetric,
			expPublic: false,
		},
		{
			name:      "ok/v2_public_with_private_key",
			version:   paseto.Version2,
			purpose:   paseto.Public,
			key:       paseto.NewV2AsymmetricSecretKey(),
			expType:   KeyTypePrivate,
			expPublic: false,
		},
		{
			name:      "ok/v2_public_with_public_key",
			version:   paseto.Version2,
			purpose:   paseto.Public,
			key:       paseto.NewV2AsymmetricSecretKey().Public(),
			expType:   KeyTypePublic,
			expPublic: false,
		},
		{
			name:      "ok/v3_symmetric_key",
			version:   paseto.Version3,
			purpose:   paseto.Local,
			key:       paseto.NewV3SymmetricKey(),
			expType:   KeyTypeSymmetric,
			expPublic: false,
		},
		{
			name:      "ok/v3_private_key",
			version:   paseto.Version3,
			purpose:   paseto.Public,
			key:       paseto.NewV3AsymmetricSecretKey(),
			expType:   KeyTypePrivate,
			expPublic: false,
		},
		{
			name:      "ok/v3_public_key",
			version:   paseto.Version3,
			purpose:   paseto.Public,
			key:       paseto.NewV3AsymmetricSecretKey().Public(),
			expType:   KeyTypePublic,
			expPublic: false,
		},
		{
			name:      "ok/v4_symmetric_key",
			version:   paseto.Version4,
			purpose:   paseto.Local,
			key:       paseto.NewV4SymmetricKey(),
			expType:   KeyTypeSymmetric,
			expPublic: false,
		},
		{
			name:      "ok/v4_private_key",
			version:   paseto.Version4,
			purpose:   paseto.Public,
			key:       paseto.NewV4AsymmetricSecretKey(),
			expType:   KeyTypePrivate,
			expPublic: false,
		},
		{
			name:      "ok/v4_public_key",
			version:   paseto.Version4,
			purpose:   paseto.Public,
			key:       paseto.NewV4AsymmetricSecretKey().Public(),
			expType:   KeyTypePublic,
			expPublic: false,
		},
		{
			name:    "err/invalid_version",
			version: paseto.Version("1"),
			purpose: paseto.Local,
			key:     nil,
			expErr:  "invalid protocol: unsupported PASETO version",
		},
		{
			name:      "err/panic_on_invalid_public_key_type",
			version:   paseto.Version2,
			purpose:   paseto.Public,
			key:       nil,
			expType:   KeyTypePrivate,
			expPublic: true,
			expPanic:  true,
		},
		{
			name:      "err/panic_on_newkey_error_in_public",
			version:   paseto.Version2,
			purpose:   paseto.Public,
			key:       nil,
			expType:   KeyTypePrivate,
			expPublic: false,
			expPanic:  true,
			panicType: "newkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewKey(tt.version, tt.purpose, tt.key)
			if tt.expErr != "" {
				assert.Contains(t, err.Error(), tt.expErr)
				assert.Nil(t, key)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)

			assert.Equal(t, tt.version, key.version)
			assert.Equal(t, tt.purpose, key.purpose)
			assert.NotNil(t, key.key)

			if tt.key == nil {
				assert.NotNil(t, key.key)
				if tt.purpose == paseto.Public {
					assert.NotNil(t, key.public)
				} else {
					assert.Nil(t, key.public)
				}
			} else {
				assert.Equal(t, tt.key, key.key)
			}

			assert.Equal(t, tt.expType, key.Type())

			if tt.expPanic {
				if tt.panicType == "newkey" {
					invalidKey := Key{
						key:     key.key,
						public:  key.public,
						version: paseto.Version("1"),
						purpose: tt.purpose,
						typ:     tt.expType,
					}
					assert.PanicsWithError(t, "invalid protocol: unsupported PASETO version", func() {
						invalidKey.Public()
					})
				} else {
					key.public = mockInvalidKey{}
					assert.PanicsWithValue(t, "invalid key type: xpaseto.mockInvalidKey", func() {
						key.Public()
					})
				}
			} else {
				publicKey := key.Public()
				if tt.expPublic {
					require.NotNil(t, publicKey)
					assert.Equal(t, tt.version, publicKey.version)
					assert.Equal(t, tt.purpose, publicKey.purpose)
					assert.Equal(t, KeyTypePublic, publicKey.Type())
					assert.Equal(t, key.public, publicKey.key)
				} else {
					assert.Nil(t, publicKey)
				}
			}
		})
	}
}

func TestKey_Encrypt(t *testing.T) {
	tests := []struct {
		name    string
		version paseto.Version
		purpose paseto.Purpose
		keyType KeyType
		claims  []Claim
		expErr  string
	}{
		{
			name:    "ok/v2_local_encryption_with_claims",
			version: paseto.Version2,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			claims: []Claim{
				ClaimSubject("user123"),
				ClaimAudience("app"),
			},
		},
		{
			name:    "ok/v3_local_encryption_with_claims",
			version: paseto.Version3,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			claims: []Claim{
				ClaimSubject("user456"),
				ClaimIssuer("auth-service"),
			},
		},
		{
			name:    "ok/v4_local_encryption_with_claims",
			version: paseto.Version4,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			claims: []Claim{
				ClaimSubject("user789"),
				ClaimID("token123"),
			},
		},
		{
			name:    "ok/v2_local_encryption_empty_token",
			version: paseto.Version2,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			claims:  []Claim{},
		},
		{
			name:    "err/v2_public_key_encryption",
			version: paseto.Version2,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
			claims:  []Claim{ClaimSubject("user")},
			expErr:  "encrypting only works with symmetric keys",
		},
		{
			name:    "err/v3_public_key_encryption",
			version: paseto.Version3,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
			claims:  []Claim{ClaimSubject("user")},
			expErr:  "encrypting only works with symmetric keys",
		},
		{
			name:    "err/v4_public_key_encryption",
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
			claims:  []Claim{ClaimSubject("user")},
			expErr:  "encrypting only works with symmetric keys",
		},
		{
			name:    "err/v2_asymmetric_public_key_encryption",
			version: paseto.Version2,
			purpose: paseto.Public,
			keyType: KeyTypePublic,
			claims:  []Claim{ClaimSubject("user")},
			expErr:  "encrypting only works with symmetric keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewKey(tt.version, tt.purpose, nil)
			require.NoError(t, err)

			if tt.keyType == KeyTypePublic {
				key = key.Public()
				require.NotNil(t, key)
			}

			token, err := NewToken(timeNowFn, tt.claims...)
			require.NoError(t, err)

			encryptedToken, err := key.Encrypt(token)
			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				assert.Empty(t, encryptedToken)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, encryptedToken)

			parsedToken, err := ParseToken(key, encryptedToken)
			require.NoError(t, err)

			for _, claim := range tt.claims {
				switch v := claim.Value.(type) {
				case string:
					val, err := parsedToken.GetString(claim.Code)
					require.NoError(t, err)
					assert.Equal(t, v, val)
				case time.Time:
					val, err := parsedToken.GetTime(claim.Code)
					require.NoError(t, err)
					assert.Equal(t, v, val)
				}
			}

			protocol, err := TokenProtocol(encryptedToken)
			require.NoError(t, err)
			assert.Equal(t, tt.version, protocol.Version())
			assert.Equal(t, paseto.Local, protocol.Purpose())
		})
	}
}

func TestKey_Render(t *testing.T) {
	tests := []struct {
		name     string
		version  paseto.Version
		purpose  paseto.Purpose
		keyType  KeyType
		encoding KeyEncoding
		validate func(t *testing.T, result string)
	}{
		{
			name:     "ok/symmetric_key_hex_encoding",
			version:  paseto.Version4,
			purpose:  paseto.Local,
			keyType:  KeyTypeSymmetric,
			encoding: KeyEncodingHex,
			validate: func(t *testing.T, result string) {
				assert.Len(t, result, 64) // 32 bytes * 2 hex chars
				assert.Regexp(t, "^[0-9a-f]+$", result)
			},
		},
		{
			name:     "ok/symmetric_key_pem_encoding",
			version:  paseto.Version4,
			purpose:  paseto.Local,
			keyType:  KeyTypeSymmetric,
			encoding: KeyEncodingPEM,
			validate: func(t *testing.T, result string) {
				lines := strings.Split(strings.TrimSpace(result), "\n")
				assert.GreaterOrEqual(t, len(lines), 3) // At least header, content, footer
				assert.Equal(t, "-----BEGIN SYMMETRIC KEY-----", lines[0])
				assert.Equal(t, "-----END SYMMETRIC KEY-----", lines[len(lines)-1])
			},
		},
		{
			name:     "ok/private_key_hex_encoding",
			version:  paseto.Version4,
			purpose:  paseto.Public,
			keyType:  KeyTypePrivate,
			encoding: KeyEncodingHex,
			validate: func(t *testing.T, result string) {
				assert.Len(t, result, 128) // 64 bytes * 2 hex chars
				assert.Regexp(t, "^[0-9a-f]+$", result)
			},
		},
		{
			name:     "ok/private_key_pem_encoding",
			version:  paseto.Version4,
			purpose:  paseto.Public,
			keyType:  KeyTypePrivate,
			encoding: KeyEncodingPEM,
			validate: func(t *testing.T, result string) {
				lines := strings.Split(strings.TrimSpace(result), "\n")
				assert.GreaterOrEqual(t, len(lines), 3) // At least header, content, footer
				assert.Equal(t, "-----BEGIN PRIVATE KEY-----", lines[0])
				assert.Equal(t, "-----END PRIVATE KEY-----", lines[len(lines)-1])
			},
		},
		{
			name:     "ok/public_key_hex_encoding",
			version:  paseto.Version4,
			purpose:  paseto.Public,
			keyType:  KeyTypePublic,
			encoding: KeyEncodingHex,
			validate: func(t *testing.T, result string) {
				assert.Len(t, result, 64) // 32 bytes * 2 hex chars
				assert.Regexp(t, "^[0-9a-f]+$", result)
			},
		},
		{
			name:     "ok/public_key_pem_encoding",
			version:  paseto.Version4,
			purpose:  paseto.Public,
			keyType:  KeyTypePublic,
			encoding: KeyEncodingPEM,
			validate: func(t *testing.T, result string) {
				lines := strings.Split(strings.TrimSpace(result), "\n")
				assert.GreaterOrEqual(t, len(lines), 3) // At least header, content, footer
				assert.Equal(t, "-----BEGIN PUBLIC KEY-----", lines[0])
				assert.Equal(t, "-----END PUBLIC KEY-----", lines[len(lines)-1])
			},
		},
		{
			name:     "ok/v2_symmetric_key_hex",
			version:  paseto.Version2,
			purpose:  paseto.Local,
			keyType:  KeyTypeSymmetric,
			encoding: KeyEncodingHex,
			validate: func(t *testing.T, result string) {
				assert.Len(t, result, 64) // 32 bytes * 2 hex chars
				assert.Regexp(t, "^[0-9a-f]+$", result)
			},
		},
		{
			name:     "ok/v3_private_key_pem",
			version:  paseto.Version3,
			purpose:  paseto.Public,
			keyType:  KeyTypePrivate,
			encoding: KeyEncodingPEM,
			validate: func(t *testing.T, result string) {
				lines := strings.Split(strings.TrimSpace(result), "\n")
				assert.GreaterOrEqual(t, len(lines), 3) // At least header, content, footer
				assert.Equal(t, "-----BEGIN PRIVATE KEY-----", lines[0])
				assert.Equal(t, "-----END PRIVATE KEY-----", lines[len(lines)-1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				key *Key
				err error
			)

			if tt.keyType == KeyTypePublic {
				privateKey, err := NewKey(tt.version, tt.purpose, nil)
				require.NoError(t, err)
				key = privateKey.Public()
				require.NotNil(t, key)
			} else {
				key, err = NewKey(tt.version, tt.purpose, nil)
				require.NoError(t, err)
			}

			result := key.Render(tt.encoding)
			tt.validate(t, result)

			// Multiple calls to Render should produce the same output
			result2 := key.Render(tt.encoding)
			assert.Equal(t, result, result2)
		})
	}
}

func TestKey_Sign(t *testing.T) {
	tests := []struct {
		name    string
		version paseto.Version
		purpose paseto.Purpose
		keyType KeyType
		expErr  string
	}{
		{
			name:    "ok/v2_private_key",
			version: paseto.Version2,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "ok/v3_private_key",
			version: paseto.Version3,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "ok/v4_private_key",
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "err/symmetric_key",
			version: paseto.Version4,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			expErr:  "signing only works with private keys",
		},
		{
			name:    "err/public_key",
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePublic,
			expErr:  "signing only works with private keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				key *Key
				err error
			)

			if tt.keyType == KeyTypePublic {
				privKey, err := NewKey(tt.version, tt.purpose, nil)
				require.NoError(t, err)
				key = privKey.Public()
			} else {
				key, err = NewKey(tt.version, tt.purpose, nil)
				require.NoError(t, err)
			}

			token, err := NewToken(timeNowFn)
			require.NoError(t, err)

			signedToken, err := key.Sign(token)

			if tt.expErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				assert.Empty(t, signedToken)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, signedToken)

				protocol, err := TokenProtocol(signedToken)
				assert.NoError(t, err)
				assert.Equal(t, tt.version, protocol.Version())
				assert.Equal(t, tt.purpose, protocol.Purpose())
			}
		})
	}
}

func TestKey_Write(t *testing.T) {
	// Create test keys for different types
	symKey, err := NewKey(paseto.Version4, paseto.Local, nil)
	require.NoError(t, err)

	privKey, err := NewKey(paseto.Version4, paseto.Public, nil)
	require.NoError(t, err)

	pubKey := privKey.Public()
	require.NotNil(t, pubKey)

	tests := []struct {
		name     string
		key      *Key
		writer   io.Writer
		encoding KeyEncoding
		extra    bool
		expErr   string
		validate func(t *testing.T, output string, key *Key)
	}{
		{
			name:     "ok/symmetric_key_hex_no_extra",
			key:      symKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingHex,
			extra:    false,
			validate: func(t *testing.T, output string, key *Key) {
				expected := key.ExportHex()
				assert.Equal(t, expected, output)
			},
		},
		{
			name:     "ok/symmetric_key_hex_with_extra",
			key:      symKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingHex,
			extra:    true,
			validate: func(t *testing.T, output string, key *Key) {
				expected := key.ExportHex() + "\n"
				assert.Equal(t, expected, output)
			},
		},
		{
			name:     "ok/private_key_hex_no_extra",
			key:      privKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingHex,
			extra:    false,
			validate: func(t *testing.T, output string, key *Key) {
				expected := key.ExportHex()
				assert.Equal(t, expected, output)
			},
		},
		{
			name:     "ok/private_key_hex_with_extra",
			key:      privKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingHex,
			extra:    true,
			validate: func(t *testing.T, output string, key *Key) {
				expected := "Private key: " + key.ExportHex() + "\n"
				assert.Equal(t, expected, output)
			},
		},
		{
			name:     "ok/public_key_hex_with_extra",
			key:      pubKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingHex,
			extra:    true,
			validate: func(t *testing.T, output string, key *Key) {
				expected := "Public key: " + key.ExportHex() + "\n"
				assert.Equal(t, expected, output)
			},
		},
		{
			name:     "ok/symmetric_key_pem",
			key:      symKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingPEM,
			extra:    false,
			validate: func(t *testing.T, output string, key *Key) {
				lines := strings.Split(strings.TrimSpace(output), "\n")
				assert.GreaterOrEqual(t, len(lines), 3) // At least header, content, footer
				assert.Equal(t, "-----BEGIN SYMMETRIC KEY-----", lines[0])
				assert.Equal(t, "-----END SYMMETRIC KEY-----", lines[len(lines)-1])
			},
		},
		{
			name:     "ok/private_key_pem",
			key:      privKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingPEM,
			extra:    false,
			validate: func(t *testing.T, output string, key *Key) {
				lines := strings.Split(strings.TrimSpace(output), "\n")
				assert.GreaterOrEqual(t, len(lines), 3)
				assert.Equal(t, "-----BEGIN PRIVATE KEY-----", lines[0])
				assert.Equal(t, "-----END PRIVATE KEY-----", lines[len(lines)-1])
			},
		},
		{
			name:     "ok/public_key_pem",
			key:      pubKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingPEM,
			extra:    false,
			validate: func(t *testing.T, output string, key *Key) {
				lines := strings.Split(strings.TrimSpace(output), "\n")
				assert.GreaterOrEqual(t, len(lines), 3)
				assert.Equal(t, "-----BEGIN PUBLIC KEY-----", lines[0])
				assert.Equal(t, "-----END PUBLIC KEY-----", lines[len(lines)-1])
			},
		},
		{
			name:     "ok/pem_extra_ignored",
			key:      symKey,
			writer:   &bytes.Buffer{},
			encoding: KeyEncodingPEM,
			extra:    true,
			validate: func(t *testing.T, output string, key *Key) {
				expected := key.Render(KeyEncodingPEM)
				assert.Equal(t, expected, output)
			},
		},
		{
			name:     "err/write_error",
			key:      symKey,
			writer:   errorWriter{},
			encoding: KeyEncodingHex,
			extra:    false,
			expErr:   "failed writing key: write error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.key.Write(tt.writer, tt.encoding, tt.extra)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)

			buf, ok := tt.writer.(*bytes.Buffer)
			require.True(t, ok)
			output := buf.String()
			tt.validate(t, output, tt.key)
		})
	}
}

func TestLoadKey(t *testing.T) {
	v2SymKey := paseto.NewV2SymmetricKey()
	v3SymKey := paseto.NewV3SymmetricKey()
	v4SymKey := paseto.NewV4SymmetricKey()

	v2PrivKey := paseto.NewV2AsymmetricSecretKey()
	v3PrivKey := paseto.NewV3AsymmetricSecretKey()
	v4PrivKey := paseto.NewV4AsymmetricSecretKey()

	v2PubKey := v2PrivKey.Public()
	v3PubKey := v3PrivKey.Public()
	v4PubKey := v4PrivKey.Public()

	tests := []struct {
		name    string
		encData []byte
		version paseto.Version
		purpose paseto.Purpose
		keyType KeyType
		expErr  string
	}{
		{
			name:    "ok/v2_symmetric_hex",
			encData: []byte(hex.EncodeToString(v2SymKey.ExportBytes())),
			version: paseto.Version2,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
		},
		{
			name:    "ok/v3_symmetric_hex",
			encData: []byte(hex.EncodeToString(v3SymKey.ExportBytes())),
			version: paseto.Version3,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
		},
		{
			name:    "ok/v4_symmetric_hex",
			encData: []byte(hex.EncodeToString(v4SymKey.ExportBytes())),
			version: paseto.Version4,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
		},
		{
			name:    "ok/v2_private_hex",
			encData: []byte(hex.EncodeToString(v2PrivKey.ExportBytes())),
			version: paseto.Version2,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "ok/v3_private_hex",
			encData: []byte(hex.EncodeToString(v3PrivKey.ExportBytes())),
			version: paseto.Version3,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "ok/v4_private_hex",
			encData: []byte(hex.EncodeToString(v4PrivKey.ExportBytes())),
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "ok/v2_public_hex",
			encData: []byte(hex.EncodeToString(v2PubKey.ExportBytes())),
			version: paseto.Version2,
			purpose: paseto.Public,
			keyType: KeyTypePublic,
		},
		{
			name:    "ok/v3_public_hex",
			encData: []byte(hex.EncodeToString(v3PubKey.ExportBytes())),
			version: paseto.Version3,
			purpose: paseto.Public,
			keyType: KeyTypePublic,
		},
		{
			name:    "ok/v4_public_hex",
			encData: []byte(hex.EncodeToString(v4PubKey.ExportBytes())),
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePublic,
		},
		{
			name: "ok/v4_symmetric_pem",
			encData: pem.EncodeToMemory(&pem.Block{
				Type:  "SYMMETRIC KEY",
				Bytes: v4SymKey.ExportBytes(),
			}),
			version: paseto.Version4,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
		},
		{
			name: "ok/v4_private_pem",
			encData: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: v4PrivKey.ExportBytes(),
			}),
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
		},
		{
			name:    "err/invalid_hex",
			encData: []byte("invalid-hex-data"),
			version: paseto.Version4,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			expErr:  "failed decoding key data",
		},
		{
			name:    "err/wrong_key_length",
			encData: []byte(hex.EncodeToString([]byte("short"))),
			version: paseto.Version4,
			purpose: paseto.Local,
			keyType: KeyTypeSymmetric,
			expErr:  "failed loading key data",
		},
		{
			name:    "err/wrong_private_key_format",
			encData: []byte(hex.EncodeToString([]byte("invalid_private_key_data_format_here"))),
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePrivate,
			expErr:  "failed loading key data",
		},
		{
			name:    "err/wrong_public_key_format",
			encData: []byte(hex.EncodeToString([]byte("invalid_public_key_data_format"))),
			version: paseto.Version4,
			purpose: paseto.Public,
			keyType: KeyTypePublic,
			expErr:  "failed loading key data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadKey(tt.encData, tt.version, tt.purpose, tt.keyType)
			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				require.NotNil(t, key)
				assert.Equal(t, tt.version, key.version)
				assert.Equal(t, tt.purpose, key.purpose)
				assert.Equal(t, tt.keyType, key.typ)
				assert.NotNil(t, key.key)
			}
		})
	}
}

func TestKeyType_Short(t *testing.T) {
	tests := []struct {
		name     string
		kt       KeyType
		expected string
	}{
		{
			name:     "private_key",
			kt:       KeyTypePrivate,
			expected: "priv",
		},
		{
			name:     "public_key",
			kt:       KeyTypePublic,
			expected: "pub",
		},
		{
			name:     "symmetric_key",
			kt:       KeyTypeSymmetric,
			expected: "sym",
		},
		{
			name:     "invalid_key_type",
			kt:       KeyType("invalid"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kt.Short()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKeyType_Long(t *testing.T) {
	tests := []struct {
		name     string
		kt       KeyType
		expected string
	}{
		{
			name:     "private_key",
			kt:       KeyTypePrivate,
			expected: "Private key",
		},
		{
			name:     "public_key",
			kt:       KeyTypePublic,
			expected: "Public key",
		},
		{
			name:     "symmetric_key",
			kt:       KeyTypeSymmetric,
			expected: "Symmetric key",
		},
		{
			name:     "invalid_key_type",
			kt:       KeyType("invalid"),
			expected: "",
		},
		{
			name:     "empty_key_type",
			kt:       KeyType(""),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kt.Long()
			assert.Equal(t, tt.expected, result)
		})
	}
}

type mockInvalidKey struct{}

func (m mockInvalidKey) ExportHex() string   { return "" }
func (m mockInvalidKey) ExportBytes() []byte { return nil }

// errorWriter is a test helper that always returns an error on Write
type errorWriter struct{}

func (ew errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

var timeNow = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func timeNowFn() time.Time {
	return timeNow
}
