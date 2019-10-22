package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/Merzlabs/pecuniatordotgo/xs2a"
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

	// AIS Consent
	//TODO

	// Get endpoints
	endpoints := new(xs2a.Endpoints)
	err := getEndpoints(endpoints)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(endpoints.Authorization))
}

func getEndpoints(target interface{}) error {
	resp, err := EncryptedGet(os.Getenv("PT_WELLKNOWN"))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(target)
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
func EncryptedGet(url string) (*http.Response, error) {
	client := &http.Client{Transport: transport}

	// Do GET something
	return client.Get(url)
}

// EncryptedPost uses the certificates for connecting to the API
func EncryptedPost(url string, contenttype string, body io.Reader, header map[string]string) (*http.Response, error) {
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("POST", url, body)

	if err != nil {
		return nil, err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	// Do GET something
	return client.Do(req)
}

// BuildURL creates the complete url form params and environment
func BuildURL(suffix string) string {
	url := url.URL{
		Scheme: "https",
		Host:   os.Getenv("PT_HOST") + ":" + os.Getenv("PT_PORT"),
		Path:   os.Getenv("PT_PATH") + "/" + os.Getenv("PT_VERS") + suffix,
	}
	return url.String()
}
