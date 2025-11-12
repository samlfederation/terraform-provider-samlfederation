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
	RegistrationInfo FederationRegistrationInfo `xml:"mdrpi:RegistrationInfo"`
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
	UIInfo     FederationUIInfo     `xml:"mdui:UIInfo"`
	DiscoHints FederationDiscoHints `xml:"mdui:DiscoHints"`
}

type FederationUIInfo struct {
	DisplayNames         []FederationUIString `xml:"mdui:DisplayName"`
	Descriptions         []FederationUIString `xml:"mdui:Description"`
	InformationURLs      []FederationUIString `xml:"mdui:InformationURL"`
	PrivacyStatementURLs []FederationUIString `xml:"mdui:PrivacyStatementURL"`
	Keywords             []FederationUIString `xml:"mdui:Keywords"`
	Logos                []FederationUILogo   `xml:"mdui:Logo"`
}

type FederationUIString struct {
	Lang  string `xml:"xml:lang,attr"`
	Value string `xml:",chardata"`
}

type FederationUILogo struct {
	Width  int    `xml:"width,attr"`
	Height int    `xml:"height,attr"`
	URL    string `xml:",chardata"`
}

type FederationKeyDescriptor struct {
	Use     string            `xml:"use,attr"`
	KeyInfo FederationKeyInfo `xml:"ds:KeyInfo"`
}

type FederationKeyInfo struct {
	X509Data FederationX509Data `xml:"ds:X509Data"`
}

type FederationX509Data struct {
	X509Certificate string `xml:"ds:X509Certificate"`
}

type FederationService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type FederationDiscoHints struct {
	IPHints          []string `xml:"mdui:IPHint"`
	DomainHints      []string `xml:"mdui:DomainHint"`
	GeloocationHints []string `xml:"mdui:GeolocationHint"`
}
