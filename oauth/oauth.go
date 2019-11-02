package oauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

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
	res, err := apiclient.EncryptedGet(os.Getenv("PT_WELLKNOWN"), nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

// GetToken exchanges an auth code for tokens
func GetToken(code string, codeVerifier string) (*Tokens, error) {
	tokens := new(Tokens)

	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", "pecuniatordotgo")
	form.Add("code_verifier", codeVerifier)
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
func GetOAuthLink(consentID string, stateID string, codeVerifier string) (link string) {
	u, err := url.Parse(endpoints.Authorization)
	if err != nil {
		log.Fatal(err)
	}
	hash := encode(Hash([]byte(codeVerifier)))
	params := url.Values{}
	params.Add("responseType", "code")
	params.Add("clientId", "pecuniatordotgo")
	params.Add("scope", "AIS: "+consentID)
	params.Add("state", stateID)
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", hash)

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
		ValidUntil:               time.Now().AddDate(0, 1, 0).Format("2006-01-02"),
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

//PKCE code. Derived from https://github.com/nirasan/go-oauth-pkce-code-verifier

// GenerateCodeVerifier builds a secret to be used for PKCE
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return encode(Hash(b)), nil
}

// Hash creates a SH246
func Hash(b []byte) []byte {
	hash := sha256.New()
	hash.Write(b)
	return hash.Sum(nil)
}

// encode converts to base64
func encode(msg []byte) string {
	encoded := base64.StdEncoding.EncodeToString(msg)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}
