package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"aidanwoods.dev/go-paseto"

	"go.hackfix.me/paseto-cli/xpaseto"
)

func main() {
	args, fs, err := parseOSArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if fs != nil {
			fs.Usage()
		} else {
			flag.CommandLine.Usage()
		}
		os.Exit(2)
	}
	handleErr := func(err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	switch args.cmd {
	case "genkey":
		key, err := xpaseto.NewKey(args.genKey.version, args.genKey.purpose, nil)
		handleErr(err)

		err = writeKey(key, args.genKey.outFile, args.genKey.encoding)
		handleErr(err)
		pubKey := key.Public()
		if pubKey != nil {
			err = writeKey(pubKey, args.genKey.outFile, args.genKey.encoding)
			handleErr(err)
		}
	case "encrypt":
		keyData, err := os.ReadFile(args.encrypt.keyFile)
		if err != nil {
			handleErr(fmt.Errorf("failed reading key file '%s': %w", args.encrypt.keyFile, err))
		}
		key, err := xpaseto.LoadKey(keyData, args.encrypt.version, paseto.Local, xpaseto.KeyTypeSymmetric)
		handleErr(err)

		token, err := xpaseto.NewToken(args.encrypt.claims...)
		handleErr(err)
		tokenEncrypted, err := key.Encrypt(token)
		handleErr(err)
		fmt.Println(tokenEncrypted)
	case "sign":
		keyData, err := os.ReadFile(args.sign.keyFile)
		if err != nil {
			handleErr(fmt.Errorf("failed reading key file '%s': %w", args.sign.keyFile, err))
		}
		key, err := xpaseto.LoadKey(keyData, args.sign.version, paseto.Public, xpaseto.KeyTypePrivate)
		handleErr(err)

		token, err := xpaseto.NewToken(args.sign.claims...)
		handleErr(err)
		tokenSigned, err := key.Sign(token)
		handleErr(err)
		fmt.Println(tokenSigned)
	case "parse":
		protocol, err := xpaseto.TokenProtocol(args.parse.token)
		handleErr(err)

		keyData, err := os.ReadFile(args.parse.keyFile)
		if err != nil {
			handleErr(fmt.Errorf("failed reading key file '%s': %w", args.parse.keyFile, err))
		}

		key, err := xpaseto.LoadKey(keyData, protocol.Version(), protocol.Purpose(), xpaseto.KeyTypePublic)
		handleErr(err)

		token, err := xpaseto.ParseToken(key, args.parse.token)
		handleErr(err)
		if args.parse.validate {
			err = token.Validate()
			handleErr(err)
		}

		err = token.Write(os.Stdout, args.parse.format)
		handleErr(err)
	}
}

func writeKey(k *xpaseto.Key, outFile string, enc xpaseto.KeyEncoding) error {
	var (
		w    io.Writer
		path string
	)
	if outFile == "" {
		w = os.Stdout
	} else {
		path = fmt.Sprintf("%s-%s.key", outFile, k.Type().Short())
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed opening file for writing key: %w", err)
		}
		defer f.Close()
		w = f
	}

	return k.Write(w, enc)
}
