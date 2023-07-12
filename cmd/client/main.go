package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
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

func readFromStdin(tx chan []byte, quit chan bool) {
	reader := bufio.NewReader(os.Stdin)
	for {
		msg, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			quit <- true
			break
		}
		tx <- msg
	}
}

func readFromConn(conn *tls.Conn, tx chan []byte, quit chan bool) {
	reader := bufio.NewReader(conn)
	for {
		msg, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			quit <- true
			break
		}
		tx <- msg
	}
}

func main() {
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
	var caFile string
	flag.StringVar(&caFile, "cafile", "", "CA certificate file")
	var serverName string
	flag.StringVar(&serverName, "server-name", "", "Server name to check certificate")
	var address string
	flag.StringVar(&address, "address", ":5556", "Address to connect")
	flag.Parse()

	if listCipherSuites {
		for _, c := range tlsdriver.CipherSuites() {
			fmt.Printf("%s\n", c.Name)
		}
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

	if serverName == "" {
		serverName = address
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

	config := &tls.Config{
		MinVersion:       uint16(minVersion),
		MaxVersion:       uint16(maxVersion),
		CipherSuites:     cipherSuiteIDs,
		CurvePreferences: curveIDs,
		RootCAs:          rootCAs,
		ServerName:       serverName,
	}

	conn, err := tls.Dial("tcp", address, config)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipherSuite, err := tlsdriver.CipherSuiteFromID(state.CipherSuite)
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("Connected to %s with: %s [%s]\n",
		conn.RemoteAddr().String(),
		tlsdriver.Version(state.Version).String(),
		cipherSuite.Name)

	rx1 := make(chan []byte)
	rx2 := make(chan []byte)
	quit := make(chan bool)

	go readFromStdin(rx1, quit)
	go readFromConn(conn, rx2, quit)

	for {
		var inputFromStdin []byte
		var inputFromConn []byte
		select {
		case inputFromStdin = <-rx1:
			conn.Write(inputFromStdin)
		case inputFromConn = <-rx2:
			os.Stdout.Write(inputFromConn)
		case _ = <-quit:
			return
		}
	}
}
