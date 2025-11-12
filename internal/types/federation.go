package types

type FederationMetadata struct {
	EntityDescriptors []FederationEntityDescriptor `xml:"EntityDescriptor"`
}

type FederationEntityDescriptor struct {
	EntityID         string                               `xml:"entityID,attr"`
	Extensions       FederationEntityDescriptorExtensions `xml:"Extensions"`
	IDPSSODescriptor FederationIDPSSODescriptor           `xml:"IDPSSODescriptor"`
}

type FederationEntityDescriptorExtensions struct {
	RegistrationInfo FederationRegistrationInfo `xml:"urn:oasis:names:tc:SAML:metadata:rpi RegistrationInfo"`
}

type FederationRegistrationInfo struct {
	RegistrationAuthority string `xml:"registrationAuthority,attr"`
}

type FederationIDPSSODescriptor struct {
	Extensions           FederationIDPSSODescriptorExtensions `xml:"Extensions"`
	KeyDescriptors       []FederationKeyDescriptor            `xml:"KeyDescriptor"`
	SingleSignOnServices []FederationService                  `xml:"SingleSignOnService"`
	SingleLogoutServices []FederationService                  `xml:"SingleLogoutService"`
}

type FederationIDPSSODescriptorExtensions struct {
	UIInfo     FederationUIInfo     `xml:"urn:oasis:names:tc:SAML:metadata:ui UIInfo"`
	DiscoHints FederationDiscoHints `xml:"urn:oasis:names:tc:SAML:metadata:ui DiscoHints"`
}

type FederationUIInfo struct {
	DisplayNames         []FederationUIString `xml:"urn:oasis:names:tc:SAML:metadata:ui DisplayName"`
	Descriptions         []FederationUIString `xml:"urn:oasis:names:tc:SAML:metadata:ui Description"`
	InformationURLs      []FederationUIString `xml:"urn:oasis:names:tc:SAML:metadata:ui InformationURL"`
	PrivacyStatementURLs []FederationUIString `xml:"urn:oasis:names:tc:SAML:metadata:ui PrivacyStatementURL"`
	Keywords             []FederationUIString `xml:"urn:oasis:names:tc:SAML:metadata:ui Keywords"`
	Logos                []FederationUILogo   `xml:"urn:oasis:names:tc:SAML:metadata:ui Logo"`
}

type FederationUIString struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

type FederationUILogo struct {
	Width  int    `xml:"width,attr"`
	Height int    `xml:"height,attr"`
	URL    string `xml:",chardata"`
}

type FederationKeyDescriptor struct {
	Use     string            `xml:"use,attr"`
	KeyInfo FederationKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type FederationKeyInfo struct {
	X509Data FederationX509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type FederationX509Data struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type FederationService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type FederationDiscoHints struct {
	IPHints          []string `xml:"urn:oasis:names:tc:SAML:metadata:ui IPHint"`
	DomainHints      []string `xml:"urn:oasis:names:tc:SAML:metadata:ui DomainHint"`
	GeloocationHints []string `xml:"urn:oasis:names:tc:SAML:metadata:ui GeolocationHint"`
}
