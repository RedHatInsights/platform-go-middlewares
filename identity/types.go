package identity

type identityKey int

 // Internal is the "internal" field of an XRHID
type Internal struct {
	OrgID string `json:"org_id"`
}

// User is the "user" field of an XRHID
type User struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Active    bool   `json:"is_active"`
	OrgAdmin  bool   `json:"is_org_admin"`
	Internal  bool   `json:"is_internal"`
	Locale    string `json:"locale"`
}

// Associate is the "associate" field of an XRHID
type Associate struct {
	Role      []string `json:"Role"`
	Email     string   `json:"email"`
	GivenName string   `json:"givenName"`
	RHatUUID  string   `json:"rhatUUID"`
	Surname   string   `json:"surname"`
}

// X509 is the "x509" field of an XRHID
type X509 struct {
	SubjectDN string `json:"subject_dn"`
	IssuerDN  string `json:"issuer_dn"`
}

// Identity is the main body of the XRHID
type Identity struct {
	AccountNumber string                 `json:"account_number"`
	Internal      Internal               `json:"internal"`
	User          User                   `json:"user,omitempty"`
	System        map[string]interface{} `json:"system,omitempty"`
	Associate     Associate              `json:"associate,omitempty"`
	X509          X509                   `json:"x509,omitempty"`
	Type          string                 `json:"type"`
}

// XRHID is the "identity" pricipal object set by Cloud Platform 3scale
type XRHID struct {
	Identity Identity `json:"identity"`
}