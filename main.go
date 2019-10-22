package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

var (
	certFile  = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile   = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	caFile    = flag.String("CA", "someCertCAFile", "A PEM encoded CA's certificate file.")
	transport *http.Transport
)

func main() {
	_ = godotenv.Load("secrets/sandbox.env")
	flag.Parse()
	setupTransport()

	resp, err := EncryptedGet(os.Getenv("PT_WELLKNOWN"))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))
}

// Based on https://gist.github.com/michaljemala/d6f4e01c4834bf47a9c4
func setupTransport() {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool, _ := x509.SystemCertPool()
	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport = &http.Transport{TLSClientConfig: tlsConfig}
}

// EncryptedGet uses the certificates for connecting to the API
func EncryptedGet(url string) (res *http.Response, err error) {
	client := &http.Client{Transport: transport}

	// Do GET something
	return client.Get(url)
}
