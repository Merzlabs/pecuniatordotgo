package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

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
	_ = godotenv.Load("secrets/sandbox.env")
	flag.Parse()
	apiclient.Setup(certFile, keyFile)
	// Get endpoints
	err := oauth.Init()
	if err != nil {
		log.Fatal(err)
	}
	states = make(map[string]*oauth.State)

	log.Print("Start server on localhost:8080")
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/oauth/redirect", authHandler)
	http.HandleFunc("/accounts", accountHandler)
	http.HandleFunc("/accounts/balances", accountBalancesHandler)
	http.HandleFunc("/accounts/transactions", accountTransactionsHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Handler

func indexHandler(w http.ResponseWriter, req *http.Request) {
	stateID := createConsent()
	state := states[stateID]
	fmt.Fprintf(w, "<a href=\"%s\">Please login at your bank to proceed</a>", oauth.GetOAuthLink(state.Consent.ID, stateID, state.CodeVerifier))
}

func authHandler(w http.ResponseWriter, req *http.Request) {
	stateID := req.URL.Query().Get("state")
	state := states[stateID]
	if state != nil {
		code := req.URL.Query().Get("code")
		var err error
		state.Tokens, err = oauth.GetToken(code, state.CodeVerifier)
		if err != nil {
			fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Error while getting authorization token. Please try again later.\n")
		}

		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Authorization success. <a href=\"/accounts?state=%s\">Get accounts</a>\n", stateID)
	} else {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Authorization failed\n")
	}
}

func accountHandler(w http.ResponseWriter, req *http.Request) {
	state := states[req.URL.Query().Get("state")]
	if state == nil {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Invalid State\n")
		return
	}
	data, err := readAccountList(state.Consent.ID, state.Tokens)
	if err != nil {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Data error: <br> %s\n", err.Error())
		return
	}
	//w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, "<a href=\"/index\">Start</a><br>"+data)
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
	state := states[req.URL.Query().Get("state")]
	resourceID := req.URL.Query().Get("resourceId")
	if state == nil {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Invalid State\n")
		return
	}
	data, err := readAccountDetails(resourceID, path, state.Consent.ID, state.Tokens, params)
	if err != nil {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Data error: <br> %s\n", err.Error())
		return
	}
	//w.Header().Add("Content-Type", "application/json")
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
