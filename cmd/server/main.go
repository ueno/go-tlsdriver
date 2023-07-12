package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	tlsdriver "github.com/ueno/go-tlsdriver"
)

type curveIDFlags []tls.CurveID

func (f *curveIDFlags) String() string {
	arr := make([]string, len(*f))
	for i, c := range *f {
		arr[i] = c.String()
	}
	return strings.Join(arr[:], ", ")
}

func (f *curveIDFlags) Set(name string) error {
	value, err := tlsdriver.CurveFromString(name)
	if err != nil {
		return err
	}
	*f = append(*f, value)
	return nil
}

type cipherSuiteFlags []*tls.CipherSuite

func (f *cipherSuiteFlags) String() string {
	arr := make([]string, len(*f))
	for i, c := range *f {
		arr[i] = c.Name
	}
	return strings.Join(arr[:], ", ")
}

func (f *cipherSuiteFlags) Set(name string) error {
	value, err := tlsdriver.CipherSuiteFromString(name)
	if err != nil {
		return err
	}
	*f = append(*f, value)
	return nil
}

func ensureHandshakeCompleted(conn *tls.Conn) error {
	conn.Handshake()
	state := conn.ConnectionState()

	cipherSuite, err := tlsdriver.CipherSuiteFromID(state.CipherSuite)
	if err != nil {
		log.Println(err)
		return err
	}

	log.Printf("Accepted connection from %s with: %s [%s]\n",
		conn.RemoteAddr().String(),
		tlsdriver.Version(state.Version).String(),
		cipherSuite.Name)

	return nil
}

func echoHandler(conn net.Conn) {
	defer conn.Close()

	if err := ensureHandshakeCompleted(conn.(*tls.Conn)); err != nil {
		log.Println(err)
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	for {
		msg, err := rw.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return
		}
		_, err = rw.Write(msg)
		if err != nil {
			log.Println(err)
			return
		}
		err = rw.Flush()
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func curveNames() []string {
	arr := make([]string, len(tlsdriver.Curves))
	for i, c := range tlsdriver.Curves {
		arr[i] = c.String()
	}
	return arr
}

func versionNames() []string {
	arr := make([]string, len(tlsdriver.Versions))
	for i, c := range tlsdriver.Versions {
		arr[i] = c.String()
	}
	return arr
}

func clientAuthTypeNames() []string {
	arr := make([]string, len(tlsdriver.ClientAuthTypes))
	for i, c := range tlsdriver.ClientAuthTypes {
		arr[i] = c.String()
	}
	return arr
}

type tlsListener struct {
	inner net.Listener
}

func (l *tlsListener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err == nil {
		if err := ensureHandshakeCompleted(conn.(*tls.Conn)); err != nil {
			log.Println(err)
			return conn, err
		}
	}
	return conn, err
}

func (l *tlsListener) Close() error {
	return l.inner.Close()
}

func (l *tlsListener) Addr() net.Addr {
	return l.inner.Addr()
}

func main() {
	var useHttp bool
	flag.BoolVar(&useHttp, "http", false, "Run HTTP server, instead of echo server")
	var listCipherSuites bool
	flag.BoolVar(&listCipherSuites, "list-ciphersuites", false, "List ciphersuites and exit")
	var minVersionString string
	flag.StringVar(&minVersionString, "min-version", "VersionTLS12",
		fmt.Sprintf("Minimum version of TLS [%s]",
			strings.Join(versionNames(), ", ")))
	var maxVersionString string
	flag.StringVar(&maxVersionString, "max-version", "VersionTLS13",
		fmt.Sprintf("Maximum version of TLS [%s]",
			strings.Join(versionNames(), ", ")))
	var curveIDs curveIDFlags
	flag.Var(&curveIDs, "curve",
		fmt.Sprintf("Preferred curve [%s]", strings.Join(curveNames(), ", ")))
	var cipherSuites cipherSuiteFlags
	flag.Var(&cipherSuites, "cipher", "Preferred cipher suite")
	var certFile string
	flag.StringVar(&certFile, "certfile", "", "Certificate file")
	var keyFile string
	flag.StringVar(&keyFile, "keyfile", "", "Key file path")
	var caFile string
	flag.StringVar(&caFile, "cafile", "", "CA certificate file")
	var clientAuthTypeString string
	flag.StringVar(&clientAuthTypeString, "client-auth", "NoClientCert",
		fmt.Sprintf("Policy for client authentication [%s]",
			strings.Join(clientAuthTypeNames(), ", ")))
	var address string
	flag.StringVar(&address, "address", ":5556", "Address to listen")
	flag.Parse()

	if listCipherSuites {
		for _, c := range tlsdriver.CipherSuites() {
			fmt.Printf("%s\n", c.Name)
		}
		return
	}

	if certFile == "" {
		log.Fatal("supply certificate file with --certfile")
	}

	if keyFile == "" {
		log.Fatal("supply key file with --keyfile")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Println(err)
		return
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		if err != nil {
			log.Println(err)
			return
		}
	}

	if caFile != "" {
		f, err := os.Open(caFile)
		if err != nil {
			log.Println(err)
			return
		}
		defer f.Close()

		pem, err := io.ReadAll(f)
		if err != nil {
			log.Println(err)
			return
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			log.Println("unable to append CA certificate")
			return
		}
	}

	cipherSuiteIDs := make([]uint16, len(cipherSuites))
	for _, v := range cipherSuites {
		cipherSuiteIDs = append(cipherSuiteIDs, v.ID)
	}

	minVersion, err := tlsdriver.VersionFromString(minVersionString)
	if err != nil {
		log.Println(err)
		return
	}

	maxVersion, err := tlsdriver.VersionFromString(maxVersionString)
	if err != nil {
		log.Println(err)
		return
	}

	clientAuthType, err := tlsdriver.ClientAuthTypeFromString(clientAuthTypeString)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{
		MinVersion:       uint16(minVersion),
		MaxVersion:       uint16(maxVersion),
		CipherSuites:     cipherSuiteIDs,
		CurvePreferences: curveIDs,
		Certificates:     []tls.Certificate{cert},
		ClientCAs:        rootCAs,
		ClientAuth:       clientAuthType,
	}

	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()
	log.Printf("Listening on %s\n", listener.Addr().String())

	if useHttp {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
		})
		server := &http.Server{
			Addr:      address,
			Handler:   mux,
			TLSConfig: config,
		}
		server.Serve(&tlsListener{
			inner: listener,
		})
	} else {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println(err)
				continue
			}

			go echoHandler(conn)
		}
	}
}
