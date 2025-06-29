package paseto

import "fmt"

// Any cryptography issue (with the token) or formatting error.
// This does not include cryptography errors with input key material, these will
// return regular errors.
type TokenError struct {
	e error
}

func newTokenError(e error) error {
	return TokenError{e}
}

func (e TokenError) Error() string {
	return e.e.Error()
}

func (TokenError) Is(e error) bool {
	_, ok1 := e.(TokenError)
	_, ok2 := e.(*TokenError)
	return ok1 || ok2
}

func (e TokenError) Unwrap() error {
	return e.e
}

// Any error which is the result of a rule failure (distinct from a TokenError)
// Can be used to detect cryptographically valid tokens which have failed only
// due to a rule failure: which may warrant a slightly different processing
// follow up.
type RuleError struct {
	e error
}

func newRuleError(e error) RuleError {
	return RuleError{e}
}

func (e RuleError) Error() string {
	return e.e.Error()
}

func (RuleError) Is(e error) bool {
	_, ok1 := e.(RuleError)
	_, ok2 := e.(*RuleError)
	return ok1 || ok2
}

func (e RuleError) Unwrap() error {
	return e.e
}

func errorKeyLength(expected, given int) error {
	return fmt.Errorf("key length incorrect (%d), expected %d", given, expected)
}

var errorKeyWrongCurve = fmt.Errorf("input key was for the wrong curve")

func errorSeedLength(expected, given int) error {
	return fmt.Errorf("seed length incorrect (%d), expected %d", given, expected)
}

func errorMessageParts(given int) error {
	return newTokenError(fmt.Errorf("invalid number of message parts in token (%d)", given))
}

func errorMessageHeader(expected Protocol, givenHeader string) error {
	return newTokenError(fmt.Errorf("message header `%s' is not valid, expected `%s'", givenHeader, expected.Header()))
}

func errorMessageHeaderDecrypt(expected Protocol, givenHeader string) error {
	return fmt.Errorf("cannot decrypt message: %w", errorMessageHeader(expected, givenHeader))
}

func errorMessageHeaderVerify(expected Protocol, givenHeader string) error {
	return fmt.Errorf("cannot verify message: %w", errorMessageHeader(expected, givenHeader))
}

var unsupportedPasetoVersion = fmt.Errorf("unsupported PASETO version")
var unsupportedPasetoPurpose = fmt.Errorf("unsupported PASETO purpose")
var unsupportedPayload = fmt.Errorf("unsupported payload")

var errorPayloadShort = newTokenError(fmt.Errorf("payload is not long enough to be a valid PASETO message"))
var errorBadSignature = newTokenError(fmt.Errorf("bad signature"))
var errorBadMAC = newTokenError(fmt.Errorf("bad message authentication code"))

var errorKeyInvalid = fmt.Errorf("key was not valid")

func errorDecrypt(err error) error {
	return fmt.Errorf("the message could not be decrypted: %w", newTokenError(err))
}
