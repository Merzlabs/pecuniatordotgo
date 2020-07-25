package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/Merzlabs/pecuniatordotgo/apiclient"
	"github.com/Merzlabs/pecuniatordotgo/oauth"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	certFile = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile  = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	states   map[string]*oauth.State
)

func main() {
	err := godotenv.Load("secrets/sandbox.env")
	if err != nil {
		log.Fatalf("Cannot load config %s", err.Error())
	}
	flag.Parse()
	apiclient.Setup(certFile, keyFile)
	// Get endpoints
	err = oauth.Init()
	if err != nil {
		log.Fatal(err)
	}
	states = make(map[string]*oauth.State)

	log.Print("Start server on localhost:8080")
	http.HandleFunc("/", redirectHandler)
	http.HandleFunc("/oauth/start", indexHandler)
	http.HandleFunc("/oauth/redirect", authHandler)
	http.HandleFunc("/accounts", accountHandler)
	http.HandleFunc("/accounts/balances", accountBalancesHandler)
	http.HandleFunc("/accounts/transactions", accountTransactionsHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// TODO use JSON marshalling. Now using strings because of simplicty

// Handlers
func indexHandler(w http.ResponseWriter, req *http.Request) {
	stateID := createConsent()
	state := states[stateID]
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, "{\"authUrl\": \"%s\"}", oauth.GetOAuthLink(state.Consent.ID, stateID, state.CodeVerifier))
}

func redirectHandler(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "/oauth/start", 301)
}

func authHandler(w http.ResponseWriter, req *http.Request) {
	stateID := req.URL.Query().Get("state")
	state := states[stateID]
	if state != nil {
		code := req.URL.Query().Get("code")
		var err error
		state.Tokens, err = oauth.GetToken(code, state.CodeVerifier)
		if err != nil {
			fmt.Fprintf(w, "{\"error\": \"Error while getting authorization token. Please try again later\"}")
		}

		u := os.Getenv("PT_APPLICATIONREDIRECT") + "?state=" + stateID
		http.Redirect(w, req, u, 301)
	} else {
		fmt.Fprintf(w, "{\"error\": \"Authorization failed\"}")
	}
}

func accountHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Content-Type", "application/json")
	state := states[req.URL.Query().Get("state")]
	if state == nil {
		fmt.Fprintf(w, "{\"error\": \"Invalid State\"}")
		return
	}
	data, err := readAccountList(state.Consent.ID, state.Tokens)
	if err != nil {
		fmt.Fprintf(w, "{\"error\": \"Data error: %s\"}", err.Error())
		return
	}
	fmt.Fprintf(w, data)
}

func accountBalancesHandler(w http.ResponseWriter, req *http.Request) {
	handleAccountDetails(w, req, "balances", nil)
}

func accountTransactionsHandler(w http.ResponseWriter, req *http.Request) {
	params := url.Values{}
	params.Add("dateFrom", "2019-0-01")
	params.Add("bookingStatus", "both")
	handleAccountDetails(w, req, "transactions", params)
}

func handleAccountDetails(w http.ResponseWriter, req *http.Request, path string, params url.Values) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Content-Type", "text/xml")
	state := states[req.URL.Query().Get("state")]
	resourceID := req.URL.Query().Get("resourceId")
	if state == nil {
		fmt.Fprintf(w, "{\"error\": \"Invalid State\"}")
		return
	}
	data, err := readAccountDetails(resourceID, path, state.Consent.ID, state.Tokens, params)
	if err != nil {
		fmt.Fprintf(w, "{\"error\": \"Data error: <br> %s\"}", err.Error())
		return
	}
	fmt.Fprintf(w, data)
}

// Helper

// AIS Consent
func createConsent() string {
	state := uuid.New().String()
	consent := new(oauth.ConsentResponse)

	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		log.Fatal(err)
	}

	err = oauth.StartConsent(consent)
	if err != nil {
		log.Fatal(err)
	}
	states[state] = &oauth.State{
		Consent:      consent,
		CodeVerifier: codeVerifier,
	}
	return state
}

func readAccountList(consentID string, tokens *oauth.Tokens) (string, error) {
	if states == nil || tokens == nil {
		return "UNAUTHORIZED", errors.New("Please login first")
	}

	headers := make(map[string]string)
	headers["X-Request-ID"] = uuid.New().String()
	headers["Consent-ID"] = consentID
	headers["Authorization"] = tokens.TokenType + " " + tokens.AccessToken

	res, err := apiclient.EncryptedGet(apiclient.BuildURL("/accounts"), headers, nil)

	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}

func readAccountDetails(resourceID string, path string, consentID string, tokens *oauth.Tokens, params url.Values) (string, error) {
	if states == nil || tokens == nil {
		return "UNAUTHORIZED", errors.New("Please login first")
	}

	headers := make(map[string]string)
	headers["X-Request-ID"] = uuid.New().String()
	headers["Consent-ID"] = consentID
	headers["Authorization"] = tokens.TokenType + " " + tokens.AccessToken

	path = fmt.Sprintf("/accounts/%s/%s", resourceID, path)
	res, err := apiclient.EncryptedGet(apiclient.BuildURL(path), headers, params)

	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}
