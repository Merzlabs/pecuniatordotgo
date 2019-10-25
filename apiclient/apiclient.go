package apiclient

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

var (
	client *http.Client
)

// Setup is based on https://gist.github.com/michaljemala/d6f4e01c4834bf47a9c4
func Setup(certFile *string, keyFile *string) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client = &http.Client{Transport: transport}
}

// EncryptedGet uses the certificates for connecting to the API
func EncryptedGet(url string, header map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	return client.Do(req)
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
