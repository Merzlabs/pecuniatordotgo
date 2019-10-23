package main

import (
	"bytes"
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
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	certFile = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile  = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	caFile   = flag.String("CA", "someCertCAFile", "A PEM encoded CA's certificate file.")
	client   *http.Client
)

func main() {
	_ = godotenv.Load("secrets/sandbox.env")
	flag.Parse()
	setupClient()

	// AIS Consent
	consent := new(xs2a.ConsentResponse)
	err := startConsent(consent)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(consent.ID))

	// Get endpoints
	endpoints := new(xs2a.Endpoints)
	err = getEndpoints(endpoints)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(endpoints.Authorization))
}

func startConsent(consent *xs2a.ConsentResponse) error {
	accs := []xs2a.Account{xs2a.Account{IBAN: os.Getenv("PT_IBAN")}}
	access := &xs2a.ConsentAccess{
		Balances:     accs,
		Transactions: accs,
	}
	creq := &xs2a.ConsentRequest{
		Access:                   *access,
		RecurringIndicator:       true,
		ValidUntil:               "2019-10-30", //TODO generate usefull value
		FrequencyPerDay:          4,
		CombinedServiceIndicator: false,
	}
	data, err := json.Marshal(creq)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)

	contentType := "application/json"
	headers := make(map[string]string)
	headers["Content-Type"] = contentType
	headers["X-Request-ID"] = uuid.New().String()
	headers["TPP-Redirect-URI"] = os.Getenv("PT_TPPREDIRECTURI")
	headers["TPP-Redirect-Preferred"] = "true"
	url := BuildURL("/consents")
	log.Print(string(data))

	res, err := EncryptedPost(url, contentType, reader, headers)

	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(consent)
	return nil
}

func getEndpoints(target interface{}) error {
	res, err := EncryptedGet(os.Getenv("PT_WELLKNOWN"))
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

// Based on https://gist.github.com/michaljemala/d6f4e01c4834bf47a9c4
func setupClient() {
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
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client = &http.Client{Transport: transport}
}

// EncryptedGet uses the certificates for connecting to the API
func EncryptedGet(url string) (*http.Response, error) {
	// Do GET something
	return client.Get(url)
}

// EncryptedPost uses the certificates for connecting to the API
func EncryptedPost(url string, contenttype string, body io.Reader, header map[string]string) (*http.Response, error) {
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
