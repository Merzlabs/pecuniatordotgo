package oauth

import (
	"bytes"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/Merzlabs/pecuniatordotgo/apiclient"
	"github.com/google/uuid"
)

var (
	endpoints *Endpoints
)

// Init sets up the oauth client
func Init() error {
	endpoints = new(Endpoints)
	return getEndpoints(endpoints)
}

func getEndpoints(target interface{}) error {
	res, err := apiclient.EncryptedGet(os.Getenv("PT_WELLKNOWN"), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

// GetToken exchanges an auth code for tokens
func GetToken(code string) (*Tokens, error) {
	tokens := new(Tokens)

	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", "pecuniatordotgo")
	form.Add("code_verifier", "TODO") // TODO see PKCE (Proof  Key  for Code Exchange RFC 7636)
	form.Add("grant_type", "authorization_code")

	contentType := "application/x-www-form-urlencoded"
	headers := make(map[string]string)
	headers["Content-Type"] = contentType
	res, err := apiclient.EncryptedPost(endpoints.Token, contentType, strings.NewReader(form.Encode()), headers)
	if err != nil {
		return nil, err
	}

	return tokens, json.NewDecoder(res.Body).Decode(tokens)
}

// GetOAuthLink builds link to online banking with redirect
func GetOAuthLink(consentID string, state string) (link string) {
	u, err := url.Parse(endpoints.Authorization)
	if err != nil {
		log.Fatal(err)
	}
	params := url.Values{}
	params.Add("responseType", "code")
	params.Add("clientId", "pecuniatordotgo")
	params.Add("scope", "AIS: "+consentID)
	params.Add("state", state)
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", "vXVXiMA4CQ_Buik94dCNpfIfveWdNxMEwVtxGDz7xWg")

	u.RawQuery = params.Encode()
	return u.String()
}

// StartConsent starts a new flow with defined consent
func StartConsent(consent *ConsentResponse) error {
	accs := []Account{Account{IBAN: os.Getenv("PT_IBAN")}}
	access := &ConsentAccess{
		Balances:     accs,
		Transactions: accs,
	}
	creq := &ConsentRequest{
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
	requestID := uuid.New().String()
	headers := make(map[string]string)
	headers["Content-Type"] = contentType
	headers["X-Request-ID"] = requestID
	headers["TPP-Redirect-URI"] = os.Getenv("PT_TPPREDIRECTURI")
	headers["TPP-Redirect-Preferred"] = "true"
	url := apiclient.BuildURL("/consents")

	res, err := apiclient.EncryptedPost(url, contentType, reader, headers)

	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(consent)
}
