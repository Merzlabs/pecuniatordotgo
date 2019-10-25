package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/Merzlabs/pecuniatordotgo/apiclient"
	"github.com/Merzlabs/pecuniatordotgo/oauth"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	certFile  = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile   = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	processID string
	tokens    *oauth.Tokens
	consent   *oauth.ConsentResponse
)

func main() {
	_ = godotenv.Load("secrets/sandbox.env")
	flag.Parse()
	apiclient.Setup(certFile, keyFile)
	// Get endpoints
	err := oauth.Init()
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Start server on localhost:8080")
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/redirect", authHandler)
	http.HandleFunc("/accounts", accountHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Handler

func indexHandler(w http.ResponseWriter, req *http.Request) {
	createConsent()
	processID = uuid.New().String()
	fmt.Fprintf(w, "<a href=\"%s\">Please login at your bank to proceed</a>", oauth.GetOAuthLink(consent.ID, processID))
}

func authHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Query().Get("state") == processID {
		code := req.URL.Query().Get("code")
		var err error
		tokens, err = oauth.GetToken(code)
		if err != nil {
			log.Fatalf("Failed to get token %s", err.Error())
		}

		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Authorization success. <a href=\"/accounts\">Get accounts</a>\n")
	} else {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Authorization failed\n")
	}
}

func accountHandler(w http.ResponseWriter, req *http.Request) {
	data, err := readAccountList()
	if err != nil {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Data error: <br> %s\n", err.Error())
		return
	}
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, data)
}

// Helper

// AIS Consent
func createConsent() {
	consent = new(oauth.ConsentResponse)
	err := oauth.StartConsent(consent)
	if err != nil {
		log.Fatal(err)
	}
}

func readAccountList() (string, error) {
	if consent == nil || tokens == nil {
		return "UNAUTHORIZED", errors.New("Please login first")
	}

	headers := make(map[string]string)
	headers["X-Request-ID"] = uuid.New().String()
	headers["Consent-ID"] = consent.ID
	headers["Authorization"] = tokens.TokenType + " " + tokens.AccessToken

	res, err := apiclient.EncryptedGet(apiclient.BuildURL("/accounts"), headers)

	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}
