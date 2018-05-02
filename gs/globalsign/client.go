package globalsign

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

// against "unused imports"
var _ time.Time
var _ xml.Name

type DVOrderWithoutCSR struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVOrderWithoutCSR"`

	Request *QbV1DvOrderWithoutCsrRequest `xml:"Request,omitempty"`
}

type QbV1DvOrderWithoutCsrRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvOrderWithoutCsrRequest"`

	OrderRequestHeader              *OrderRequestHeader              `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameterWithoutCSR *OrderRequestParameterWithoutCSR `xml:"OrderRequestParameterWithoutCSR,omitempty"`
	OrderID                         string                           `xml:"OrderID,omitempty"`
	SubID                           string                           `xml:"SubID,omitempty"`
	FQDN                            string                           `xml:"FQDN,omitempty"`
	DVCSRInfo                       *DVCSRInfo                       `xml:"DVCSRInfo,omitempty"`
	ApproverEmail                   string                           `xml:"ApproverEmail,omitempty"`
	ContactInfo                     *ContactInfo                     `xml:"ContactInfo,omitempty"`
	SecondContactInfo               *SecondContactInfo               `xml:"SecondContactInfo,omitempty"`
	SANEntries                      *SANEntries                      `xml:"SANEntries,omitempty"`
}

type OrderRequestHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrderRequestHeader"`

	AuthToken *AuthToken `xml:"AuthToken,omitempty"`
}

type AuthToken struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ AuthToken"`

	UserName string `xml:"UserName,omitempty"`
	Password string `xml:"Password,omitempty"`
}

type OrderRequestParameter struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrderRequestParameter"`

	ProductCode          string          `xml:"ProductCode,omitempty"`
	BaseOption           string          `xml:"BaseOption,omitempty"`
	OrderKind            string          `xml:"OrderKind,omitempty"`
	Licenses             string          `xml:"Licenses,omitempty"`
	Options              *Options        `xml:"Options,omitempty"`
	ValidityPeriod       *ValidityPeriod `xml:"ValidityPeriod,omitempty"`
	CSR                  string          `xml:"CSR,omitempty"`
	RenewalTargetOrderID string          `xml:"RenewalTargetOrderID,omitempty"`
	TargetCERT           string          `xml:"TargetCERT,omitempty"`
	SpecialInstructions  string          `xml:"SpecialInstructions,omitempty"`
	Coupon               string          `xml:"Coupon,omitempty"`
	Campaign             string          `xml:"Campaign,omitempty"`
}

type Options struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Options"`

	Option []*Option `xml:"Option,omitempty"`
}

type Option struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Option"`

	OptionName  string `xml:"OptionName,omitempty"`
	OptionValue string `xml:"OptionValue,omitempty"`
}

type ValidityPeriod struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ValidityPeriod"`

	Months    string `xml:"Months,omitempty"`
	NotBefore string `xml:"NotBefore,omitempty"`
	NotAfter  string `xml:"NotAfter,omitempty"`
}

type DVCSRInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVCSRInfo"`

	Country string `xml:"Country,omitempty"`
}

type ContactInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ContactInfo"`

	FirstName string `xml:"FirstName,omitempty"`
	LastName  string `xml:"LastName,omitempty"`
	Phone     string `xml:"Phone,omitempty"`
	Email     string `xml:"Email,omitempty"`
}

type SecondContactInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ SecondContactInfo"`

	FirstName string `xml:"FirstName,omitempty"`
	LastName  string `xml:"LastName,omitempty"`
	Email     string `xml:"Email,omitempty"`
}

type SANEntries struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ SANEntries"`

	SANEntry []*SANEntry `xml:"SANEntry,omitempty"`
}

type SANEntry struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ SANEntry"`

	SANOptionType  string `xml:"SANOptionType,omitempty"`
	SubjectAltName string `xml:"SubjectAltName,omitempty"`
}

type DVOrderWithoutCSRResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVOrderWithoutCSRResponse"`

	Response *QbV1DvOrderWithoutCsrResponse `xml:"Response,omitempty"`
}

type QbV1DvOrderWithoutCsrResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvOrderWithoutCsrResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type OrderResponseHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrderResponseHeader"`

	SuccessCode int32   `xml:"SuccessCode,omitempty"`
	Errors      *Errors `xml:"Errors,omitempty"`
	Timestamp   string  `xml:"Timestamp,omitempty"`
}

type Errors struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Errors"`

	Error []*Error `xml:"Error,omitempty"`
}

type Error struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Error"`

	ErrorCode    string `xml:"ErrorCode,omitempty"`
	ErrorField   string `xml:"ErrorField,omitempty"`
	ErrorMessage string `xml:"ErrorMessage,omitempty"`
}

type ModifyOrder struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ModifyOrder"`

	Request *QbV1ModifyOrderRequest `xml:"Request,omitempty"`
}

type QbV1ModifyOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1ModifyOrderRequest"`

	OrderRequestHeader   *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	OrderID              string              `xml:"OrderID,omitempty"`
	ModifyOrderOperation string              `xml:"ModifyOrderOperation,omitempty"`
}

type ModifyOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ModifyOrderResponse"`

	Response *QbV1ModifyOrderResponse `xml:"Response,omitempty"`
}

type QbV1ModifyOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1ModifyOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type EVOrder struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ EVOrder"`

	Request *QbV1EVOrderRequest `xml:"Request,omitempty"`
}

type QbV1EVOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1EVOrderRequest"`

	OrderRequestHeader    *OrderRequestHeader    `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter `xml:"OrderRequestParameter,omitempty"`
	SubId                 string                 `xml:"SubId,omitempty"`
	OrganizationInfoEV    *OrganizationInfoEV    `xml:"OrganizationInfoEV,omitempty"`
	RequestorInfo         *RequestorApproverInfo `xml:"RequestorInfo,omitempty"`
	ApproverInfo          *RequestorApproverInfo `xml:"ApproverInfo,omitempty"`
	AuthorizedSignerInfo  *AuthorizedSignerInfo  `xml:"AuthorizedSignerInfo,omitempty"`
	JurisdictionInfo      *JurisdictionInfo      `xml:"JurisdictionInfo,omitempty"`
	ContactInfo           *ContactInfo           `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfo     `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries            `xml:"SANEntries,omitempty"`
}

type OrganizationInfoEV struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrganizationInfoEV"`

	*BusinessEVInfo

	BusinessCategoryCode string                   `xml:"BusinessCategoryCode,omitempty"`
	OrganizationAddress  *OrganizationAddressInfo `xml:"OrganizationAddress,omitempty"`
}

type BusinessEVInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ BusinessEVInfo"`

	BusinessAssumedName string `xml:"BusinessAssumedName,omitempty"`
	CreditAgency        string `xml:"CreditAgency,omitempty"`
	OrganizationCode    string `xml:"OrganizationCode,omitempty"`
}

type OrganizationAddressInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrganizationAddressInfo"`

	AddressLine1 string `xml:"AddressLine1,omitempty"`
	AddressLine2 string `xml:"AddressLine2,omitempty"`
	AddressLine3 string `xml:"AddressLine3,omitempty"`
	City         string `xml:"City,omitempty"`
	Region       string `xml:"Region,omitempty"`
	PostalCode   string `xml:"PostalCode,omitempty"`
	Country      string `xml:"Country,omitempty"`
	Phone        string `xml:"Phone,omitempty"`
	Fax          string `xml:"Fax,omitempty"`
}

type RequestorApproverInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ RequestorApproverInfo"`

	FirstName        string `xml:"FirstName,omitempty"`
	LastName         string `xml:"LastName,omitempty"`
	Function         string `xml:"Function,omitempty"`
	OrganizationName string `xml:"OrganizationName,omitempty"`
	OrganizationUnit string `xml:"OrganizationUnit,omitempty"`
	Phone            string `xml:"Phone,omitempty"`
	Email            string `xml:"Email,omitempty"`
}

type AuthorizedSignerInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ AuthorizedSignerInfo"`

	OrganizationName string `xml:"OrganizationName,omitempty"`
	FirstName        string `xml:"FirstName,omitempty"`
	LastName         string `xml:"LastName,omitempty"`
	Function         string `xml:"Function,omitempty"`
	Phone            string `xml:"Phone,omitempty"`
	Email            string `xml:"Email,omitempty"`
}

type JurisdictionInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ JurisdictionInfo"`

	JurisdictionCountry                   string `xml:"JurisdictionCountry,omitempty"`
	JurisdictionState                     string `xml:"JurisdictionState,omitempty"`
	JurisdictionLocality                  string `xml:"JurisdictionLocality,omitempty"`
	IncorporationAgencyRegistrationNumber string `xml:"IncorporationAgencyRegistrationNumber,omitempty"`
}

type EVOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ EVOrderResponse"`

	Response *QbV1EVOrderResponse `xml:"Response,omitempty"`
}

type QbV1EVOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1EVOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderId             string               `xml:"OrderId,omitempty"`
}

type URLVerificationForIssue struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ URLVerificationForIssue"`

	Request *QbV1UrlVerificationForIssueRequest `xml:"Request,omitempty"`
}

type QbV1UrlVerificationForIssueRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1UrlVerificationForIssueRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	ApproverURL        string              `xml:"ApproverURL,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
}

type URLVerificationForIssueResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ URLVerificationForIssueResponse"`

	Response *QbV1UrlVerificationForIssueResponse `xml:"Response,omitempty"`
}

type QbV1UrlVerificationForIssueResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1UrlVerificationForIssueResponse"`

	OrderResponseHeader     *OrderResponseHeader           `xml:"OrderResponseHeader,omitempty"`
	URLVerificationForIssue *UrlVerificationForIssueObject `xml:"URLVerificationForIssue,omitempty"`
}

type UrlVerificationForIssueObject struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ UrlVerificationForIssueObject"`

	CertificateInfo *CertificateInfo `xml:"CertificateInfo,omitempty"`
	Fulfillment     *Fulfillment     `xml:"Fulfillment,omitempty"`
}

type CertificateInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CertificateInfo"`

	CertificateStatus string `xml:"CertificateStatus,omitempty"`
	StartDate         string `xml:"StartDate,omitempty"`
	EndDate           string `xml:"EndDate,omitempty"`
	CommonName        string `xml:"CommonName,omitempty"`
	SerialNumber      string `xml:"SerialNumber,omitempty"`
	SubjectName       string `xml:"SubjectName,omitempty"`
	DNSNames          string `xml:"DNSNames,omitempty"`
}

type Fulfillment struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Fulfillment"`

	CACertificates    *CACertificates    `xml:"CACertificates,omitempty"`
	ServerCertificate *ServerCertificate `xml:"ServerCertificate,omitempty"`
}

type CACertificates struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CACertificates"`

	CACertificate []*CACertificate `xml:"CACertificate,omitempty"`
}

type CACertificate struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CACertificate"`

	CACertType string `xml:"CACertType,omitempty"`
	CACert     string `xml:"CACert,omitempty"`
}

type ServerCertificate struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ServerCertificate"`

	X509Cert  string `xml:"X509Cert,omitempty"`
	PKCS7Cert string `xml:"PKCS7Cert,omitempty"`
}

type GetApproverList struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ GetApproverList"`

	Request *QbV1GetApproverListRequest `xml:"Request,omitempty"`
}

type QbV1GetApproverListRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1GetApproverListRequest"`

	QueryRequestHeader *QueryRequestHeader `xml:"QueryRequestHeader,omitempty"`
	FQDN               string              `xml:"FQDN,omitempty"`
	SANEntries         *SANEntries         `xml:"SANEntries,omitempty"`
}

type QueryRequestHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QueryRequestHeader"`

	AuthToken *AuthToken `xml:"AuthToken,omitempty"`
}

type GetApproverListResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ GetApproverListResponse"`

	Response *QbV1GetApproverListResponse `xml:"Response,omitempty"`
}

type QbV1GetApproverListResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1GetApproverListResponse"`

	QueryResponseHeader *QueryResponseHeader `xml:"QueryResponseHeader,omitempty"`
	Approvers           *Approvers           `xml:"Approvers,omitempty"`
}

type QueryResponseHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QueryResponseHeader"`

	SuccessCode int32   `xml:"SuccessCode,omitempty"`
	Errors      *Errors `xml:"Errors,omitempty"`
	Timestamp   string  `xml:"Timestamp,omitempty"`
}

type Approvers struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Approvers"`

	SearchOrderDetail []*Approver `xml:"SearchOrderDetail,omitempty"`
}

type Approver struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Approver"`

	ApproverType  string `xml:"ApproverType,omitempty"`
	ApproverEmail string `xml:"ApproverEmail,omitempty"`
}

type EVOrderJP struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ EVOrderJP"`

	Request *QbV1EVOrderJPRequest `xml:"Request,omitempty"`
}

type QbV1EVOrderJPRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1EVOrderJPRequest"`

	OrderRequestHeader    *OrderRequestHeader          `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter       `xml:"OrderRequestParameter,omitempty"`
	SubId                 string                       `xml:"SubId,omitempty"`
	OrganizationInfoEV    *OrganizationInfoEVNative    `xml:"OrganizationInfoEV,omitempty"`
	RequestorInfo         *RequestorApproverInfoNative `xml:"RequestorInfo,omitempty"`
	ApproverInfo          *RequestorApproverInfoNative `xml:"ApproverInfo,omitempty"`
	AuthorizedSignerInfo  *AuthorizedSignerInfoNative  `xml:"AuthorizedSignerInfo,omitempty"`
	JurisdictionInfo      *JurisdictionInfo            `xml:"JurisdictionInfo,omitempty"`
	ContactInfo           *ContactInfoNative           `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfoNative     `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries                  `xml:"SANEntries,omitempty"`
}

type OrganizationInfoEVNative struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrganizationInfoEVNative"`

	*BusinessEVInfo

	OrganizationNameNative string                         `xml:"OrganizationNameNative,omitempty"`
	BusinessCategoryCode   string                         `xml:"BusinessCategoryCode,omitempty"`
	OrganizationAddress    *OrganizationAddressInfoNative `xml:"OrganizationAddress,omitempty"`
}

type OrganizationAddressInfoNative struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrganizationAddressInfoNative"`

	AddressLine1       string `xml:"AddressLine1,omitempty"`
	AddressLine1Native string `xml:"AddressLine1Native,omitempty"`
	AddressLine2       string `xml:"AddressLine2,omitempty"`
	AddressLine2Native string `xml:"AddressLine2Native,omitempty"`
	AddressLine3       string `xml:"AddressLine3,omitempty"`
	City               string `xml:"City,omitempty"`
	CityNative         string `xml:"CityNative,omitempty"`
	Region             string `xml:"Region,omitempty"`
	RegionNative       string `xml:"RegionNative,omitempty"`
	PostalCode         string `xml:"PostalCode,omitempty"`
	Country            string `xml:"Country,omitempty"`
	Phone              string `xml:"Phone,omitempty"`
	Fax                string `xml:"Fax,omitempty"`
}

type RequestorApproverInfoNative struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ RequestorApproverInfoNative"`

	FirstName              string `xml:"FirstName,omitempty"`
	FirstNameNative        string `xml:"FirstNameNative,omitempty"`
	LastName               string `xml:"LastName,omitempty"`
	LastNameNative         string `xml:"LastNameNative,omitempty"`
	Function               string `xml:"Function,omitempty"`
	OrganizationName       string `xml:"OrganizationName,omitempty"`
	OrganizationNameNative string `xml:"OrganizationNameNative,omitempty"`
	OrganizationUnitNative string `xml:"OrganizationUnitNative,omitempty"`
	Phone                  string `xml:"Phone,omitempty"`
	Email                  string `xml:"Email,omitempty"`
}

type AuthorizedSignerInfoNative struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ AuthorizedSignerInfoNative"`

	OrganizationName       string `xml:"OrganizationName,omitempty"`
	OrganizationNameNative string `xml:"OrganizationNameNative,omitempty"`
	FirstName              string `xml:"FirstName,omitempty"`
	FirstNameNative        string `xml:"FirstNameNative,omitempty"`
	LastName               string `xml:"LastName,omitempty"`
	LastNameNative         string `xml:"LastNameNative,omitempty"`
	Function               string `xml:"Function,omitempty"`
	OrganizationUnitNative string `xml:"OrganizationUnitNative,omitempty"`
	Phone                  string `xml:"Phone,omitempty"`
	Email                  string `xml:"Email,omitempty"`
}

type ContactInfoNative struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ContactInfoNative"`

	FirstName              string `xml:"FirstName,omitempty"`
	FirstNameNative        string `xml:"FirstNameNative,omitempty"`
	LastName               string `xml:"LastName,omitempty"`
	LastNameNative         string `xml:"LastNameNative,omitempty"`
	OrganizationNameNative string `xml:"OrganizationNameNative,omitempty"`
	OrganizationUnitNative string `xml:"OrganizationUnitNative,omitempty"`
	Phone                  string `xml:"Phone,omitempty"`
	Email                  string `xml:"Email,omitempty"`
}

type SecondContactInfoNative struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ SecondContactInfoNative"`

	FirstNameNative string `xml:"FirstNameNative,omitempty"`
	LastNameNative  string `xml:"LastNameNative,omitempty"`
	Email           string `xml:"Email,omitempty"`
}

type EVOrderJPResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ EVOrderJPResponse"`

	Response *QbV1EVOrderResponse `xml:"Response,omitempty"`
}

type DVDNSVerificationForIssue struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVDNSVerificationForIssue"`

	Request *QbV1DnsVerificationForIssueRequest `xml:"Request,omitempty"`
}

type QbV1DnsVerificationForIssueRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DnsVerificationForIssueRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	ApproverFQDN       string              `xml:"ApproverFQDN,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
}

type DVDNSVerificationForIssueResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVDNSVerificationForIssueResponse"`

	Response *QbV1DnsVerificationForIssueResponse `xml:"Response,omitempty"`
}

type QbV1DnsVerificationForIssueResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DnsVerificationForIssueResponse"`

	OrderResponseHeader     *OrderResponseHeader           `xml:"OrderResponseHeader,omitempty"`
	URLVerificationForIssue *UrlVerificationForIssueObject `xml:"URLVerificationForIssue,omitempty"`
}

type DVDNSOrderWithoutCsr struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVDNSOrderWithoutCsr"`

	Request *QbV1DvDnsOrderWithoutCsrRequest `xml:"Request,omitempty"`
}

type QbV1DvDnsOrderWithoutCsrRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvDnsOrderWithoutCsrRequest"`

	OrderRequestHeader              *OrderRequestHeader              `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameterWithoutCSR *OrderRequestParameterWithoutCSR `xml:"OrderRequestParameterWithoutCSR,omitempty"`
	SubID                           string                           `xml:"SubID,omitempty"`
	FQDN                            string                           `xml:"FQDN,omitempty"`
	DVCSRInfo                       *DVCSRInfo                       `xml:"DVCSRInfo,omitempty"`
	ContactInfo                     *ContactInfo                     `xml:"ContactInfo,omitempty"`
	SecondContactInfo               *SecondContactInfo               `xml:"SecondContactInfo,omitempty"`
	SANEntries                      *SANEntries                      `xml:"SANEntries,omitempty"`
}

type DVDNSOrderWithoutCsrResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVDNSOrderWithoutCsrResponse"`

	Response *QbV1DvDnsOrderWithoutCsrResponse `xml:"Response,omitempty"`
}

type QbV1DvDnsOrderWithoutCsrResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvDnsOrderWithoutCsrResponse"`

	OrderResponseHeader  *OrderResponseHeader  `xml:"OrderResponseHeader,omitempty"`
	OrderID              string                `xml:"OrderID,omitempty"`
	DNSTXT               string                `xml:"DNSTXT,omitempty"`
	VerificationFQDNList *VerificationFQDNList `xml:"VerificationFQDNList,omitempty"`
}

type VerificationFQDNList struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ VerificationFQDNList"`

	VerificationFQDN []string `xml:"VerificationFQDN,omitempty"`
}

type GetDVApproverList struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ GetDVApproverList"`

	Request *QbV1GetDVApproverListRequest `xml:"Request,omitempty"`
}

type GetDVApproverListResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ GetDVApproverListResponse"`

	Response *QbV1GetDVApproverListResponse `xml:"Response,omitempty"`
}

type CertInviteOrder struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CertInviteOrder"`

	Request *QbV1CertInviteOrderRequest `xml:"Request,omitempty"`
}

type QbV1CertInviteOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1CertInviteOrderRequest"`

	OrderRequestHeader       *OrderRequestHeader              `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter    *CertInviteOrderRequestParameter `xml:"OrderRequestParameter,omitempty"`
	SANEntries               *CertInviteSANEntries            `xml:"SANEntries,omitempty"`
	CertInviteExpirationDate string                           `xml:"CertInviteExpirationDate,omitempty"`
	RecipientDeliveryOption  string                           `xml:"RecipientDeliveryOption,omitempty"`
	CertInviteRecipientEmail string                           `xml:"CertInviteRecipientEmail,omitempty"`
}

type CertInviteOrderRequestParameter struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CertInviteOrderRequestParameter"`

	ProductCode          string          `xml:"ProductCode,omitempty"`
	BaseOption           string          `xml:"BaseOption,omitempty"`
	OrderKind            string          `xml:"OrderKind,omitempty"`
	Options              *Options        `xml:"Options,omitempty"`
	ValidityPeriod       *ValidityPeriod `xml:"ValidityPeriod,omitempty"`
	RenewalTargetOrderID string          `xml:"RenewalTargetOrderID,omitempty"`
	Coupon               string          `xml:"Coupon,omitempty"`
	Campaign             string          `xml:"Campaign,omitempty"`
}

type CertInviteSANEntries struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CertInviteSANEntries"`

	SANEntry []*CertInviteSANEntry `xml:"SANEntry,omitempty"`
}

type CertInviteSANEntry struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CertInviteSANEntry"`

	SANOptionType string `xml:"SANOptionType,omitempty"`
}

type CertInviteOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ CertInviteOrderResponse"`

	Response *QbV1CertInviteOrderResponse `xml:"Response,omitempty"`
}

type QbV1CertInviteOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1CertInviteOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	PIN                 string               `xml:"PIN,omitempty"`
}

type ResendEmail struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ResendEmail"`

	Request *QbV1ResendEmailRequest `xml:"Request,omitempty"`
}

type QbV1ResendEmailRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1ResendEmailRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
	ResendEmailType    string              `xml:"ResendEmailType,omitempty"`
}

type ResendEmailResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ResendEmailResponse"`

	Response *QbV1ResendEmailResponse `xml:"Response,omitempty"`
}

type QbV1ResendEmailResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1ResendEmailResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderId             string               `xml:"OrderId,omitempty"`
}

type OVOrderWithoutCSR struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderWithoutCSR"`

	Request *QbV1OVOrderWithoutCSRRequest `xml:"Request,omitempty"`
}

type QbV1OVOrderWithoutCSRRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1OVOrderWithoutCSRRequest"`

	OrderRequestHeader              *OrderRequestHeader              `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameterWithoutCSR *OrderRequestParameterWithoutCSR `xml:"OrderRequestParameterWithoutCSR,omitempty"`
	OrganizationInfo                *OrganizationInfo                `xml:"OrganizationInfo,omitempty"`
	SubID                           string                           `xml:"SubID,omitempty"`
	OVCSRInfo                       *OVCSRInfo                       `xml:"OVCSRInfo,omitempty"`
	FQDN                            string                           `xml:"FQDN,omitempty"`
	ContactInfo                     *ContactInfo                     `xml:"ContactInfo,omitempty"`
	SecondContactInfo               *SecondContactInfo               `xml:"SecondContactInfo,omitempty"`
	SANEntries                      *SANEntries                      `xml:"SANEntries,omitempty"`
	Extensions                      *Extensions                      `xml:"Extensions,omitempty"`
}

type OrganizationInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrganizationInfo"`

	OrganizationName    string               `xml:"OrganizationName,omitempty"`
	CreditAgency        string               `xml:"CreditAgency,omitempty"`
	OrganizationCode    string               `xml:"OrganizationCode,omitempty"`
	OrganizationAddress *OrganizationAddress `xml:"OrganizationAddress,omitempty"`
}

type OrganizationAddress struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OrganizationAddress"`

	AddressLine1 string `xml:"AddressLine1,omitempty"`
	AddressLine2 string `xml:"AddressLine2,omitempty"`
	AddressLine3 string `xml:"AddressLine3,omitempty"`
	City         string `xml:"City,omitempty"`
	Region       string `xml:"Region,omitempty"`
	PostalCode   string `xml:"PostalCode,omitempty"`
	Country      string `xml:"Country,omitempty"`
	Phone        string `xml:"Phone,omitempty"`
	Fax          string `xml:"Fax,omitempty"`
}

type OVCSRInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVCSRInfo"`

	OrganizationName string `xml:"OrganizationName,omitempty"`
	OrganizationUnit string `xml:"OrganizationUnit,omitempty"`
	Locality         string `xml:"Locality,omitempty"`
	StateOrProvince  string `xml:"StateOrProvince,omitempty"`
	Country          string `xml:"Country,omitempty"`
}

type Extensions struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Extensions"`

	Extension []*Extension `xml:"Extension,omitempty"`
}

type Extension struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ Extension"`

	Name  string `xml:"Name,omitempty"`
	Value string `xml:"Value,omitempty"`
}

type OVOrderWithoutCSRResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderWithoutCSRResponse"`

	Response *QbV1OVOrderWithoutCSRResponse `xml:"Response,omitempty"`
}

type QbV1OVOrderWithoutCSRResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1OVOrderWithoutCSRResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type DVOrder struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVOrder"`

	Request *QbV1DvOrderRequest `xml:"Request,omitempty"`
}

type QbV1DvOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvOrderRequest"`

	OrderRequestHeader    *OrderRequestHeader    `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter `xml:"OrderRequestParameter,omitempty"`
	SubID                 string                 `xml:"SubID,omitempty"`
	OrderID               string                 `xml:"OrderID,omitempty"`
	ApproverEmail         string                 `xml:"ApproverEmail,omitempty"`
	ContactInfo           *ContactInfo           `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfo     `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries            `xml:"SANEntries,omitempty"`
}

type DVOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVOrderResponse"`

	Response *QbV1DvOrderResponse `xml:"Response,omitempty"`
}

type QbV1DvOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type URLVerification struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ URLVerification"`

	Request *QbV1UrlVerificationRequest `xml:"Request,omitempty"`
}

type QbV1UrlVerificationRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1UrlVerificationRequest"`

	OrderRequestHeader    *OrderRequestHeader    `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter `xml:"OrderRequestParameter,omitempty"`
	SubID                 string                 `xml:"SubID,omitempty"`
	ContactInfo           *ContactInfo           `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfo     `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries            `xml:"SANEntries,omitempty"`
}

type URLVerificationResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ URLVerificationResponse"`

	Response *QbV1UrlVerificationResponse `xml:"Response,omitempty"`
}

type QbV1UrlVerificationResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1UrlVerificationResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
	MetaTag             string               `xml:"MetaTag,omitempty"`
	VerificationURLList *VerificationUrlList `xml:"VerificationURLList,omitempty"`
}

type VerificationUrlList struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ VerificationUrlList"`

	VerificationURL []string `xml:"VerificationURL,omitempty"`
}

type OVOrderJPWithoutCSR struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderJPWithoutCSR"`

	Request *QbV1OVOrderJPWithoutCSRRequest `xml:"Request,omitempty"`
}

type QbV1OVOrderJPWithoutCSRRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1OVOrderJPWithoutCSRRequest"`

	OrderRequestHeader              *OrderRequestHeader              `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameterWithoutCSR *OrderRequestParameterWithoutCSR `xml:"OrderRequestParameterWithoutCSR,omitempty"`
	OrganizationInfo                *OrganizationInfo                `xml:"OrganizationInfo,omitempty"`
	SubID                           string                           `xml:"SubID,omitempty"`
	OVCSRInfo                       *OVCSRInfo                       `xml:"OVCSRInfo,omitempty"`
	FQDN                            string                           `xml:"FQDN,omitempty"`
	ContactInfo                     *ContactInfoNative               `xml:"ContactInfo,omitempty"`
	SecondContactInfo               *SecondContactInfoNative         `xml:"SecondContactInfo,omitempty"`
	SANEntries                      *SANEntries                      `xml:"SANEntries,omitempty"`
	Extensions                      *Extensions                      `xml:"Extensions,omitempty"`
}

type OVOrderJPWithoutCSRResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderJPWithoutCSRResponse"`

	Response *QbV1OVOrderWithoutCSRResponse `xml:"Response,omitempty"`
}

type DVDNSOrder struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVDNSOrder"`

	Request *QbV1DvDnsOrderRequest `xml:"Request,omitempty"`
}

type QbV1DvDnsOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvDnsOrderRequest"`

	OrderRequestHeader    *OrderRequestHeader    `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter `xml:"OrderRequestParameter,omitempty"`
	SubID                 string                 `xml:"SubID,omitempty"`
	ContactInfo           *ContactInfo           `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfo     `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries            `xml:"SANEntries,omitempty"`
}

type DVDNSOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ DVDNSOrderResponse"`

	Response *QbV1DvDnsOrderResponse `xml:"Response,omitempty"`
}

type QbV1DvDnsOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1DvDnsOrderResponse"`

	OrderResponseHeader  *OrderResponseHeader  `xml:"OrderResponseHeader,omitempty"`
	OrderID              string                `xml:"OrderID,omitempty"`
	DNSTXT               string                `xml:"DNSTXT,omitempty"`
	VerificationFQDNList *VerificationFQDNList `xml:"VerificationFQDNList,omitempty"`
}

type ChangeSubjectAltName struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ChangeSubjectAltName"`

	Request *QbV1ChangeSubjectAltNameRequest `xml:"Request,omitempty"`
}

type QbV1ChangeSubjectAltNameRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1ChangeSubjectAltNameRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
	TargetOrderID      string              `xml:"TargetOrderID,omitempty"`
	ApproverEmail      string              `xml:"ApproverEmail,omitempty"`
	SANEntries         *SANEntries         `xml:"SANEntries,omitempty"`
	PIN                string              `xml:"PIN,omitempty"`
}

type ChangeSubjectAltNameResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ChangeSubjectAltNameResponse"`

	Response *QbV1ChangeSubjectAltNameResponse `xml:"Response,omitempty"`
}

type QbV1ChangeSubjectAltNameResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1ChangeSubjectAltNameResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
	TargetOrderID       string               `xml:"TargetOrderID,omitempty"`
}

type ChangeApproverEmail struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ChangeApproverEmail"`

	Request *QbV1ChangeApproverEmailsRequest `xml:"Request,omitempty"`
}

type ChangeApproverEmailResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ ChangeApproverEmailResponse"`

	Response *QbV1ChangeApproverEmailsResponse `xml:"Response,omitempty"`
}

type OVOrderJP struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderJP"`

	Request *QbV1OVOrderJPRequest `xml:"Request,omitempty"`
}

type QbV1OVOrderJPRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1OVOrderJPRequest"`

	OrderRequestHeader    *OrderRequestHeader      `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter   `xml:"OrderRequestParameter,omitempty"`
	SubID                 string                   `xml:"SubID,omitempty"`
	OrganizationInfo      *OrganizationInfo        `xml:"OrganizationInfo,omitempty"`
	ContactInfo           *ContactInfoNative       `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfoNative `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries              `xml:"SANEntries,omitempty"`
	Extensions            *Extensions              `xml:"Extensions,omitempty"`
}

type OVOrderJPResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderJPResponse"`

	Response *QbV1OVOrderResponse `xml:"Response,omitempty"`
}

type QbV1OVOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1OVOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type URLVerificationWithoutCSR struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ URLVerificationWithoutCSR"`

	Request *QbV1UrlVerificationWithoutCsrRequest `xml:"Request,omitempty"`
}

type QbV1UrlVerificationWithoutCsrRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1UrlVerificationWithoutCsrRequest"`

	OrderRequestHeader              *OrderRequestHeader              `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameterWithoutCSR *OrderRequestParameterWithoutCSR `xml:"OrderRequestParameterWithoutCSR,omitempty"`
	SubID                           string                           `xml:"SubID,omitempty"`
	FQDN                            string                           `xml:"FQDN,omitempty"`
	DVCSRInfo                       *DVCSRInfo                       `xml:"DVCSRInfo,omitempty"`
	ContactInfo                     *ContactInfo                     `xml:"ContactInfo,omitempty"`
	SecondContactInfo               *SecondContactInfo               `xml:"SecondContactInfo,omitempty"`
	SANEntries                      *SANEntries                      `xml:"SANEntries,omitempty"`
}

type URLVerificationWithoutCSRResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ URLVerificationWithoutCSRResponse"`

	Response *QbV1UrlVerificationWithoutCsrResponse `xml:"Response,omitempty"`
}

type QbV1UrlVerificationWithoutCsrResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1UrlVerificationWithoutCsrResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
	MetaTag             string               `xml:"MetaTag,omitempty"`
	VerificationURLList *VerificationUrlList `xml:"VerificationURLList,omitempty"`
}

type OVOrder struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrder"`

	Request *QbV1OVOrderRequest `xml:"Request,omitempty"`
}

type QbV1OVOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ QbV1OVOrderRequest"`

	OrderRequestHeader    *OrderRequestHeader    `xml:"OrderRequestHeader,omitempty"`
	OrderRequestParameter *OrderRequestParameter `xml:"OrderRequestParameter,omitempty"`
	SubID                 string                 `xml:"SubID,omitempty"`
	OrganizationInfo      *OrganizationInfo      `xml:"OrganizationInfo,omitempty"`
	ContactInfo           *ContactInfo           `xml:"ContactInfo,omitempty"`
	SecondContactInfo     *SecondContactInfo     `xml:"SecondContactInfo,omitempty"`
	SANEntries            *SANEntries            `xml:"SANEntries,omitempty"`
	Extensions            *Extensions            `xml:"Extensions,omitempty"`
}

type OVOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/v1/ OVOrderResponse"`

	Response *QbV1OVOrderResponse `xml:"Response,omitempty"`
}

type OrderRequestParameterWithoutCSR struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/ OrderRequestParameterWithoutCSR"`

	*OrderRequestParameter

	Pin       string `xml:"Pin,omitempty"`
	KeyLength string `xml:"KeyLength,omitempty"`
}

type QbV1GetDVApproverListRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/ QbV1GetDVApproverListRequest"`

	QueryRequestHeader *QueryRequestHeader `xml:"QueryRequestHeader,omitempty"`
	FQDN               string              `xml:"FQDN,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
	SANEntries         *SANEntries         `xml:"SANEntries,omitempty"`
}

type QbV1GetDVApproverListResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/ QbV1GetDVApproverListResponse"`

	QueryResponseHeader *QueryResponseHeader `xml:"QueryResponseHeader,omitempty"`
	Approvers           *Approvers           `xml:"Approvers,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type QbV1ChangeApproverEmailsRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/ QbV1ChangeApproverEmailsRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
	ApproverEmail      string              `xml:"ApproverEmail,omitempty"`
	FQDN               string              `xml:"FQDN,omitempty"`
}

type QbV1ChangeApproverEmailsResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/kb/ws/ QbV1ChangeApproverEmailsResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type ServerSSLV1 struct {
	client *SOAPClient
}

func NewServerSSLV1(url string, tls bool, auth *BasicAuth) *ServerSSLV1 {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &ServerSSLV1{
		client: client,
	}
}

func (service *ServerSSLV1) DVOrderWithoutCSR(request *DVOrderWithoutCSR) (*DVOrderWithoutCSRResponse, error) {
	response := new(DVOrderWithoutCSRResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) ModifyOrder(request *ModifyOrder) (*ModifyOrderResponse, error) {
	response := new(ModifyOrderResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) EVOrder(request *EVOrder) (*EVOrderResponse, error) {
	response := new(EVOrderResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) URLVerificationForIssue(request *URLVerificationForIssue) (*URLVerificationForIssueResponse, error) {
	response := new(URLVerificationForIssueResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) GetApproverList(request *GetApproverList) (*GetApproverListResponse, error) {
	response := new(GetApproverListResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) EVOrderJP(request *EVOrderJP) (*EVOrderJPResponse, error) {
	response := new(EVOrderJPResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) DVDNSVerificationForIssue(request *DVDNSVerificationForIssue) (*DVDNSVerificationForIssueResponse, error) {
	response := new(DVDNSVerificationForIssueResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) DVDNSOrderWithoutCsr(request *DVDNSOrderWithoutCsr) (*DVDNSOrderWithoutCsrResponse, error) {
	response := new(DVDNSOrderWithoutCsrResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) GetDVApproverList(request *GetDVApproverList) (*GetDVApproverListResponse, error) {
	response := new(GetDVApproverListResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) CertInviteOrder(request *CertInviteOrder) (*CertInviteOrderResponse, error) {
	response := new(CertInviteOrderResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) ResendEmail(request *ResendEmail) (*ResendEmailResponse, error) {
	response := new(ResendEmailResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) OVOrderWithoutCSR(request *OVOrderWithoutCSR) (*OVOrderWithoutCSRResponse, error) {
	response := new(OVOrderWithoutCSRResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) DVOrder(request *DVOrder) (*DVOrderResponse, error) {
	response := new(DVOrderResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) URLVerification(request *URLVerification) (*URLVerificationResponse, error) {
	response := new(URLVerificationResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) OVOrderJPWithoutCSR(request *OVOrderJPWithoutCSR) (*OVOrderJPWithoutCSRResponse, error) {
	response := new(OVOrderJPWithoutCSRResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) DVDNSOrder(request *DVDNSOrder) (*DVDNSOrderResponse, error) {
	response := new(DVDNSOrderResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) ChangeSubjectAltName(request *ChangeSubjectAltName) (*ChangeSubjectAltNameResponse, error) {
	response := new(ChangeSubjectAltNameResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) ChangeApproverEmail(request *ChangeApproverEmail) (*ChangeApproverEmailResponse, error) {
	response := new(ChangeApproverEmailResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) OVOrderJP(request *OVOrderJP) (*OVOrderJPResponse, error) {
	response := new(OVOrderJPResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) URLVerificationWithoutCSR(request *URLVerificationWithoutCSR) (*URLVerificationWithoutCSRResponse, error) {
	response := new(URLVerificationWithoutCSRResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ServerSSLV1) OVOrder(request *OVOrder) (*OVOrderResponse, error) {
	response := new(OVOrderResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`

	Body SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`

	Header interface{}
}

type SOAPBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

type BasicAuth struct {
	Login    string
	Password string
}

type SOAPClient struct {
	url  string
	tls  bool
	auth *BasicAuth
}

func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (f *SOAPFault) Error() string {
	return f.String
}

func NewSOAPClient(url string, tls bool, auth *BasicAuth) *SOAPClient {
	return &SOAPClient{
		url:  url,
		tls:  tls,
		auth: auth,
	}
}

func (s *SOAPClient) Call(soapAction string, request, response interface{}) error {
	envelope := SOAPEnvelope{
	//Header:        SoapHeader{},
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)

	encoder := xml.NewEncoder(buffer)
	//encoder.Indent("  ", "    ")

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}

	log.Println(buffer.String())

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.auth != nil {
		req.SetBasicAuth(s.auth.Login, s.auth.Password)
	}

	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	if soapAction != "" {
		req.Header.Add("SOAPAction", soapAction)
	}

	req.Header.Set("User-Agent", "gowsdl/0.1")
	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		log.Println("empty response")
		return nil
	}

	log.Println(string(rawbody))
	respEnvelope := new(SOAPEnvelope)
	respEnvelope.Body = SOAPBody{Content: response}
	err = xml.Unmarshal(rawbody, respEnvelope)
	if err != nil {
		return err
	}

	fault := respEnvelope.Body.Fault
	if fault != nil {
		return fault
	}

	return nil
}
