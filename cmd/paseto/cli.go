package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"

	"go.hackfix.me/paseto-cli/xpaseto"
)

type args struct {
	cmd     string
	genKey  *genKeyArgs
	encrypt *genTokenArgs
	sign    *genTokenArgs
	parse   *parseArgs
}

type genKeyArgs struct {
	version  paseto.Version
	purpose  paseto.Purpose
	encoding xpaseto.KeyEncoding
	outFile  string
}

type genTokenArgs struct {
	version paseto.Version
	keyFile string
	claims  []xpaseto.Claim
}

type parseArgs struct {
	keyFile  string
	token    string
	format   xpaseto.TokenFormat
	validate bool
}

func parseOSArgs(osArgs []string) (*args, *flag.FlagSet, error) {
	flag.CommandLine.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", osArgs[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  genkey   Generate new keys\n")
		fmt.Fprintf(os.Stderr, "  encrypt  Generate a new encrypted token\n")
		fmt.Fprintf(os.Stderr, "  sign     Generate a new signed token\n")
		fmt.Fprintf(os.Stderr, "  parse    Parse and optionally validate a token\n")
		flag.PrintDefaults()
	}

	if len(osArgs) < 2 {
		return nil, nil, fmt.Errorf("command is required")
	}

	cmd := osArgs[1]
	cmdArgs := osArgs[2:]

	var (
		parsedArgs = &args{}
		err        error
		fs         *flag.FlagSet
	)

	switch cmd {
	case "genkey":
		parsedArgs.genKey, fs, err = parseGenKeyArgs(cmdArgs)
	case "encrypt":
		parsedArgs.encrypt, fs, err = parseGenTokenArgs(cmdArgs, "encrypt")
	case "sign":
		parsedArgs.sign, fs, err = parseGenTokenArgs(cmdArgs, "sign")
	case "parse":
		parsedArgs.parse, fs, err = parseParseArgs(cmdArgs)
	default:
		return nil, nil, fmt.Errorf("invalid command: %s", cmd)
	}

	if err != nil {
		return nil, fs, err
	}

	parsedArgs.cmd = cmd
	return parsedArgs, fs, nil
}

func parseGenKeyArgs(cmdArgs []string) (*genKeyArgs, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	version := fs.Int("version", 4, `protocol version; 2, 3 or 4`)
	purpose := fs.String("purpose", "", `"local" for shared-key (symmetric) encryption or "public" for public-key (asymmetric) signing`)
	outFile := fs.String("outfile", "", `base file path to write the key(s) to; stdout will be used if not specified`)
	encoding := fs.String("encoding", "hex", `encoding type; "hex" or "pem"`)
	err := fs.Parse(cmdArgs)
	if err != nil {
		return nil, fs, err
	}

	if !slices.Contains([]int{2, 3, 4}, *version) {
		return nil, fs, fmt.Errorf("invalid version '%d'", *version)
	}

	if *purpose == "" {
		return nil, fs, fmt.Errorf("purpose is required")
	}

	if *purpose != "local" && *purpose != "public" {
		return nil, fs, fmt.Errorf("invalid purpose '%s'", *purpose)
	}

	if *encoding != "hex" && *encoding != "pem" {
		return nil, fs, fmt.Errorf("invalid encoding '%s'", *encoding)
	}

	return &genKeyArgs{
		version:  paseto.Version(fmt.Sprintf("v%d", *version)),
		purpose:  paseto.Purpose(*purpose),
		outFile:  *outFile,
		encoding: xpaseto.KeyEncoding(*encoding),
	}, fs, nil
}

func parseGenTokenArgs(cmdArgs []string, cmdName string) (*genTokenArgs, *flag.FlagSet, error) {
	fs := flag.NewFlagSet(cmdName, flag.ExitOnError)
	version := fs.Int("version", 4, `protocol version; 2, 3 or 4`)
	keyFile := fs.String("keyfile", "", fmt.Sprintf("path to a private key file to %s the token (required)", cmdName))
	exp := expiration(time.Now().Add(time.Hour))
	y, m, d := time.Now().Date()
	exampleExp := time.Date(y, m, d+1, 0, 0, 0, 0, time.Now().Location())
	fs.Var(&exp, "exp",
		fmt.Sprintf("token expiration as a duration from now (e.g. 5m, 1h, 3d, 1M3d, 1Y) or a future timestamp in RFC 3339 format (e.g. %s) (default 1h)", exampleExp.Format(time.RFC3339)))
	claimsFromArgs := map[string]any{}
	var claimsFromStdin map[string]any
	fs.Func("claim", "key=value pair to add to the token, or '-' to read claims as JSON from stdin; can be specified multiple times (e.g. role=admin)",
		func(v string) error {
			if v == "-" && claimsFromStdin == nil {
				var err error
				claimsFromStdin, err = readClaimsFromStdin()
				if err != nil {
					return fmt.Errorf("failed reading claims from stdin: %w", err)
				}
			}

			if strings.Contains(v, "=") {
				kv := strings.SplitN(v, "=", 2)
				if len(kv) == 2 {
					claimsFromArgs[kv[0]] = kv[1]
				}
			}

			return nil
		})

	err := fs.Parse(cmdArgs)
	if err != nil {
		return nil, fs, err
	}

	if !slices.Contains([]int{2, 3, 4}, *version) {
		return nil, fs, fmt.Errorf("invalid version '%d'", *version)
	}

	if *keyFile == "" {
		return nil, fs, fmt.Errorf("keyfile is required")
	}

	// Claims from args can override ones from stdin
	claimsInput := make(map[string]any)
	if claimsFromStdin != nil {
		claimsInput = claimsFromStdin
	}
	maps.Copy(claimsInput, claimsFromArgs)

	claims := make([]xpaseto.Claim, 0, len(claimsInput))
	var foundExp bool
	for code, value := range claimsInput {
		claim := xpaseto.NewClaim(code, "", value)
		claims = append(claims, claim)
		if code == "exp" {
			foundExp = true
		}
	}

	if !foundExp {
		claims = append(claims, xpaseto.ClaimExpiration(time.Time(exp)))
	}

	return &genTokenArgs{
		version: paseto.Version(fmt.Sprintf("v%d", *version)),
		keyFile: *keyFile,
		claims:  claims,
	}, fs, nil
}

func parseParseArgs(cmdArgs []string) (*parseArgs, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	keyFile := fs.String("keyfile", "", "path to a key file to verify or decrypt the token (public key for signed tokens, shared key for encrypted tokens) (required)")
	ofmt := fs.String("format", "text", `output format; "text" or "json"`)
	validate := fs.Bool("validate", true, "whether to validate the token")
	err := fs.Parse(cmdArgs)
	if err != nil {
		return nil, fs, err
	}

	if *keyFile == "" {
		return nil, fs, fmt.Errorf("keyfile is required")
	}

	if *ofmt != "text" && *ofmt != "json" {
		return nil, fs, fmt.Errorf("invalid format '%s'", *ofmt)
	}

	token := fs.Arg(0)
	if token == "" {
		return nil, fs, fmt.Errorf("token argument is required")
	}

	return &parseArgs{
		keyFile:  *keyFile,
		token:    token,
		format:   xpaseto.TokenFormat(*ofmt),
		validate: *validate,
	}, fs, nil
}

type expiration time.Time

func (e *expiration) String() string {
	return ""
}

func (e *expiration) Set(value string) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		dur, err := parseDuration(value)
		if err != nil {
			return err
		}
		t = time.Now().Add(dur)
	}

	if t.Before(time.Now()) {
		return errors.New("expiration time is in the past")
	}

	*e = expiration(t)
	return nil
}

// parseDuration parses a duration string.
// examples: "10d", "-1.5w" or "3Y4M5d".
// Add time units are "d"="D", "w"="W", "M", "y"="Y".
// Source: https://gist.github.com/xhit/79c9e137e1cfe332076cdda9f5e24699?permalink_comment_id=5170854#gistcomment-5170854
func parseDuration(s string) (time.Duration, error) {
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}

	re := regexp.MustCompile(`(\d*\.\d+|\d+)[^\d]*`)
	unitMap := map[string]time.Duration{
		"d": 24,
		"D": 24,
		"w": 7 * 24,
		"W": 7 * 24,
		"M": 30 * 24,
		"y": 365 * 24,
		"Y": 365 * 24,
	}

	strs := re.FindAllString(s, -1)
	var sumDur time.Duration
	for _, str := range strs {
		var _hours time.Duration = 1
		for unit, hours := range unitMap {
			if strings.Contains(str, unit) {
				str = strings.ReplaceAll(str, unit, "h")
				_hours = hours
				break
			}
		}

		dur, err := time.ParseDuration(str)
		if err != nil {
			return 0, err
		}

		sumDur += dur * _hours
	}

	if neg {
		sumDur = -sumDur
	}

	return sumDur, nil
}

func readClaimsFromStdin() (map[string]any, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, errors.New("no data received on stdin")
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	claims := make(map[string]any)
	if err = json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("failed unmarshaling JSON: %w", err)
	}

	return claims, nil
}
