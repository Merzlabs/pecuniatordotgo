package oauth

// Account are used for ConsentRequests
type Account struct {
	IBAN string `json:"iban,omitempty"`
}

// ConsentRequest is used for requesting to PSU
type ConsentRequest struct {
	Access                   ConsentAccess `json:"access"`
	RecurringIndicator       bool          `json:"recurringIndicator"`
	ValidUntil               string        `json:"validUntil"`
	FrequencyPerDay          int           `json:"frequencyPerDay"`
	CombinedServiceIndicator bool          `json:"combinedServiceIndicator"`
}

// ConsentAccess is used for requesting access to accounts
type ConsentAccess struct {
	Balances     []Account `json:"balances"`
	Transactions []Account `json:"transactions"`
}

// ConsentResponse TODO complete
type ConsentResponse struct {
	Status     string `json:"consentStatus,omitempty"`
	ID         string `json:"consentId,omitempty"`
	TPPMessage string `json:"tppMessages,omitempty"`
}
