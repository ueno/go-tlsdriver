package tlsdriver

import (
	"crypto/tls"
	"errors"
)

var Curves = []tls.CurveID{
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
	tls.X25519,
}

var curveFromString map[string]tls.CurveID
var cipherSuiteFromString map[string]*tls.CipherSuite
var versionFromString map[string]Version

func CurveFromString(name string) (tls.CurveID, error) {
	value, ok := curveFromString[name]
	if !ok {
		return 0, errors.New("unsupported curve")
	}
	return value, nil
}

func CipherSuiteFromString(name string) (*tls.CipherSuite, error) {
	value, ok := cipherSuiteFromString[name]
	if !ok {
		return nil, errors.New("unsupported cipher suite")
	}
	return value, nil
}

var CipherSuites = tls.CipherSuites

type Version uint16

//go:generate stringer -type=Version
const (
	VersionTLS10 Version = tls.VersionTLS10
	VersionTLS11 Version = tls.VersionTLS11
	VersionTLS12 Version = tls.VersionTLS12
	VersionTLS13 Version = tls.VersionTLS13
	VersionSSL30 Version = tls.VersionSSL30
)

var Versions = []Version{
	VersionTLS10,
	VersionTLS11,
	VersionTLS12,
	VersionTLS13,
	VersionSSL30,
}

func VersionFromString(name string) (Version, error) {
	value, ok := versionFromString[name]
	if !ok {
		return 0, errors.New("unsupported version")
	}
	return value, nil
}

func init() {
	curveFromString = make(map[string]tls.CurveID)
	for _, c := range Curves {
		curveFromString[c.String()] = c
	}

	cipherSuiteFromString = make(map[string]*tls.CipherSuite)
	for _, c := range tls.CipherSuites() {
		cipherSuiteFromString[c.Name] = c
	}

	versionFromString = make(map[string]Version)
	for _, c := range Versions {
		versionFromString[c.String()] = c
	}
}
