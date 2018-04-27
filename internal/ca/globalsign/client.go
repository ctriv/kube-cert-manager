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

type GetProfiles struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetProfiles"`

	Request *GetCrProfileRequest `xml:"Request,omitempty"`
}

type GetCrProfileRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetCrProfileRequest"`

	QueryRequestHeader *QueryRequestHeader `xml:"QueryRequestHeader,omitempty"`
	ProfileQueryParam  *ProfileQueryParam  `xml:"ProfileQueryParam,omitempty"`
}

type QueryRequestHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ QueryRequestHeader"`

	AuthToken *AuthToken `xml:"AuthToken,omitempty"`
}

type AuthToken struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ AuthToken"`

	UserName string `xml:"UserName,omitempty"`
	Password string `xml:"Password,omitempty"`
}

type ProfileQueryParam struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ProfileQueryParam"`

	ProfileOrderNo    string `xml:"ProfileOrderNo,omitempty"`
	ProfileOrderState string `xml:"ProfileOrderState,omitempty"`
	RequestDateFrom   string `xml:"RequestDateFrom,omitempty"`
	RequestDateTo     string `xml:"RequestDateTo,omitempty"`
	IssueDateFrom     string `xml:"IssueDateFrom,omitempty"`
	IssueDateTo       string `xml:"IssueDateTo,omitempty"`
	Locality          string `xml:"Locality,omitempty"`
	StateOrProvince   string `xml:"StateOrProvince,omitempty"`
	Organization      string `xml:"Organization,omitempty"`
	OrganizationUnit  string `xml:"OrganizationUnit,omitempty"`
	ContractorUserId  string `xml:"ContractorUserId,omitempty"`
}

type GetProfilesResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetProfilesResponse"`

	Response *GetCrProfileResponse `xml:"Response,omitempty"`
}

type GetCrProfileResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetCrProfileResponse"`

	QueryResponseHeader *QueryResponseHeader `xml:"QueryResponseHeader,omitempty"`
	TotalCount          int32                `xml:"TotalCount,omitempty"`
	ProfileDetails      *ProfileDetails      `xml:"ProfileDetails,omitempty"`
}

type QueryResponseHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ QueryResponseHeader"`

	SuccessCode int32     `xml:"SuccessCode,omitempty"`
	Errors      *Errors   `xml:"Errors,omitempty"`
	Timestamp   time.Time `xml:"Timestamp,omitempty"`
}

type Errors struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Errors"`

	Error []*Error `xml:"Error,omitempty"`
}

type Error struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Error"`

	ErrorCode    string `xml:"ErrorCode,omitempty"`
	ErrorField   string `xml:"ErrorField,omitempty"`
	ErrorMessage string `xml:"ErrorMessage,omitempty"`
}

type ProfileDetails struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ProfileDetails"`

	ProfileDetail []*ProfileDetail `xml:"ProfileDetail,omitempty"`
}

type ProfileDetail struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ProfileDetail"`

	ProfileInfo         *ProfileInfo         `xml:"ProfileInfo,omitempty"`
	ProfileDnAttributes *ProfileDnAttributes `xml:"ProfileDnAttributes,omitempty"`
	ProfileAttributes   *ProfileAttributes   `xml:"ProfileAttributes,omitempty"`
}

type ProfileInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ProfileInfo"`

	ProfileOrderNo     string          `xml:"ProfileOrderNo,omitempty"`
	ProfileOrderState  string          `xml:"ProfileOrderState,omitempty"`
	RequestDate        string          `xml:"RequestDate,omitempty"`
	RequestBeforeDate  string          `xml:"RequestBeforeDate,omitempty"`
	RequestAfterDate   string          `xml:"RequestAfterDate,omitempty"`
	OrderDate          string          `xml:"OrderDate,omitempty"`
	IssueDate          string          `xml:"IssueDate,omitempty"`
	CancelRequestDate  string          `xml:"CancelRequestDate,omitempty"`
	CancelDate         string          `xml:"CancelDate,omitempty"`
	SuspendRequestDate string          `xml:"SuspendRequestDate,omitempty"`
	SuspendDate        string          `xml:"SuspendDate,omitempty"`
	ValidityPeriod     *ValidityPeriod `xml:"ValidityPeriod,omitempty"`
}

type ValidityPeriod struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ValidityPeriod"`

	NotBefore string `xml:"NotBefore,omitempty"`
	NotAfter  string `xml:"NotAfter,omitempty"`
}

type ProfileDnAttributes struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ProfileDnAttributes"`

	CommonName        string             `xml:"CommonName,omitempty"`
	Organization      string             `xml:"Organization,omitempty"`
	OrganizationUnits *OrganizationUnits `xml:"OrganizationUnits,omitempty"`
	StateOrProvince   string             `xml:"StateOrProvince,omitempty"`
	Locality          string             `xml:"Locality,omitempty"`
	Country           string             `xml:"Country,omitempty"`
}

type OrganizationUnits struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrganizationUnits"`

	OrganizationUnit []string `xml:"OrganizationUnit,omitempty"`
}

type ProfileAttributes struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ProfileAttributes"`

	HashType       string `xml:"HashType,omitempty"`
	EFSOption      string `xml:"EFSOption,omitempty"`
	UPN            string `xml:"UPN,omitempty"`
	RenewalType    string `xml:"RenewalType,omitempty"`
	NonExportable  string `xml:"NonExportable,omitempty"`
	NonRepudiation string `xml:"NonRepudiation,omitempty"`
	OCSPOption     string `xml:"OCSPOption,omitempty"`
}

type OrderPkcs12 struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderPkcs12"`

	Request *Pkcs12OrderRequest `xml:"Request,omitempty"`
}

type Pkcs12OrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Pkcs12OrderRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	ProfileID          string              `xml:"ProfileID,omitempty"`
	PKCS12PIN          string              `xml:"PKCS12PIN,omitempty"`
	ProductCode        string              `xml:"ProductCode,omitempty"`
	Year               int32               `xml:"Year,omitempty"`
	EFSOption          bool                `xml:"EFSOption,omitempty"`
	Renew              bool                `xml:"Renew,omitempty"`
	UPN                string              `xml:"UPN,omitempty"`
	DnAttributes       *DnAttributes       `xml:"DnAttributes,omitempty"`
	EmailLanguage      string              `xml:"EmailLanguage,omitempty"`
}

type OrderRequestHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderRequestHeader"`

	AuthToken *AuthToken `xml:"AuthToken,omitempty"`
}

type DnAttributes struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ DnAttributes"`

	*AbstractDnAttributes

	Email string `xml:"Email,omitempty"`
}

type AbstractDnAttributes struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ abstractDnAttributes"`

	CommonName       string   `xml:"CommonName,omitempty"`
	OrganizationUnit []string `xml:"OrganizationUnit,omitempty"`
}

type OrderPkcs12Response struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderPkcs12Response"`

	Response *Pkcs12OrderResponse `xml:"Response,omitempty"`
}

type Pkcs12OrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Pkcs12OrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
	BASE64PKCS12        string               `xml:"BASE64PKCS12,omitempty"`
	PKCS12              []byte               `xml:"PKCS12,omitempty"`
}

type OrderResponseHeader struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderResponseHeader"`

	SuccessCode int32     `xml:"SuccessCode,omitempty"`
	Errors      *Errors   `xml:"Errors,omitempty"`
	Timestamp   time.Time `xml:"Timestamp,omitempty"`
}

type OrderAndIssueCertificate struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderAndIssueCertificate"`

	Request *OrderAndIssueRequest `xml:"Request,omitempty"`
}

type OrderAndIssueRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderAndIssueRequest"`

	OrderRequestHeader  *OrderRequestHeader  `xml:"OrderRequestHeader,omitempty"`
	ProfileID           string               `xml:"ProfileID,omitempty"`
	ProductCode         string               `xml:"ProductCode,omitempty"`
	Year                int32                `xml:"Year,omitempty"`
	CSR                 string               `xml:"CSR,omitempty"`
	EFSOption           bool                 `xml:"EFSOption,omitempty"`
	UPN                 string               `xml:"UPN,omitempty"`
	DnAttributes        *DnAttributes        `xml:"DnAttributes,omitempty"`
	PickupPassword      string               `xml:"PickupPassword,omitempty"`
	CertificateTemplate *CertificateTemplate `xml:"CertificateTemplate,omitempty"`
	EmailLanguage       string               `xml:"EmailLanguage,omitempty"`
}

type CertificateTemplate struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ CertificateTemplate"`

	Template     string `xml:"Template,omitempty"`
	MajorVersion string `xml:"MajorVersion,omitempty"`
	MinorVersion string `xml:"MinorVersion,omitempty"`
}

type OrderAndIssueCertificateResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderAndIssueCertificateResponse"`

	Response *OrderAndIssueResponse `xml:"Response,omitempty"`
}

type OrderAndIssueResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderAndIssueResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
	CERT                string               `xml:"CERT,omitempty"`
}

type OrderCertificate struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderCertificate"`

	Request *OrderRequest `xml:"Request,omitempty"`
}

type OrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderRequest"`

	OrderRequestHeader *OrderRequestHeader     `xml:"OrderRequestHeader,omitempty"`
	ProfileID          string                  `xml:"ProfileID,omitempty"`
	ProductCode        string                  `xml:"ProductCode,omitempty"`
	Year               int32                   `xml:"Year,omitempty"`
	HasCSR             bool                    `xml:"HasCSR,omitempty"`
	PKCS12Option       bool                    `xml:"PKCS12Option,omitempty"`
	EFSOption          bool                    `xml:"EFSOption,omitempty"`
	UPN                string                  `xml:"UPN,omitempty"`
	DnAttributes       *DnAttributes4OrderCert `xml:"DnAttributes,omitempty"`
	PickupPassword     string                  `xml:"PickupPassword,omitempty"`
	EmailLanguage      string                  `xml:"EmailLanguage,omitempty"`
}

type DnAttributes4OrderCert struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ DnAttributes4OrderCert"`

	*AbstractDnAttributes

	Email string `xml:"Email,omitempty"`
}

type OrderCertificateResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderCertificateResponse"`

	Response *OrderResponse `xml:"Response,omitempty"`
}

type OrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type Cancel struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Cancel"`

	Request *CancelOrderRequest `xml:"Request,omitempty"`
}

type CancelOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ CancelOrderRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
}

type CancelResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ CancelResponse"`

	Response *CancelOrderResponse `xml:"Response,omitempty"`
}

type CancelOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ CancelOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type Revoke struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Revoke"`

	Request *RevokeOrderRequest `xml:"Request,omitempty"`
}

type RevokeOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ RevokeOrderRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	OrderID            string              `xml:"OrderID,omitempty"`
}

type RevokeResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ RevokeResponse"`

	Response *RevokeOrderResponse `xml:"Response,omitempty"`
}

type RevokeOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ RevokeOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"orderResponseHeader,omitempty"`
	OrderNo             string               `xml:"orderNo,omitempty"`
}

type OrderDS struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderDS"`

	Request *OrderRequest4DS `xml:"Request,omitempty"`
}

type OrderRequest4DS struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderRequest4DS"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	ProfileOrderNo     string              `xml:"ProfileOrderNo,omitempty"`
	ProductCode        string              `xml:"ProductCode,omitempty"`
	IssueType          string              `xml:"IssueType,omitempty"`
	Year               int32               `xml:"Year,omitempty"`
	CSR                string              `xml:"CSR,omitempty"`
	PickupPassword     string              `xml:"PickupPassword,omitempty"`
	DnAttributes       *DnAttributes       `xml:"DnAttributes,omitempty"`
	EmailLanguage      string              `xml:"EmailLanguage,omitempty"`
}

type OrderDSResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderDSResponse"`

	Response *OrderResponse4DS `xml:"Response,omitempty"`
}

type OrderResponse4DS struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderResponse4DS"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
	Certificate         string               `xml:"Certificate,omitempty"`
}

type GetOrders struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetOrders"`

	Request *GetCrOrdersRequest `xml:"Request,omitempty"`
}

type GetCrOrdersRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetCrOrdersRequest"`

	QueryRequestHeader *QueryRequestHeader `xml:"QueryRequestHeader,omitempty"`
	OrderQueryParam    *OrderQueryParam    `xml:"OrderQueryParam,omitempty"`
	OrdersQueryOption  *OrdersQueryOption  `xml:"OrdersQueryOption,omitempty"`
}

type OrderQueryParam struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderQueryParam"`

	ProductCode     string `xml:"ProductCode,omitempty"`
	ProfileOrderNo  string `xml:"ProfileOrderNo,omitempty"`
	LicenseOrderNo  string `xml:"LicenseOrderNo,omitempty"`
	OrderState      string `xml:"OrderState,omitempty"`
	CertState       string `xml:"CertState,omitempty"`
	RequestDateFrom string `xml:"RequestDateFrom,omitempty"`
	RequestDateTo   string `xml:"RequestDateTo,omitempty"`
	IssueDateFrom   string `xml:"IssueDateFrom,omitempty"`
	IssueDateTo     string `xml:"IssueDateTo,omitempty"`
	CommonName      string `xml:"CommonName,omitempty"`
}

type OrdersQueryOption struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrdersQueryOption"`

	ReturnCertificateInfo string `xml:"ReturnCertificateInfo,omitempty"`
	ReturnFulfillment     string `xml:"ReturnFulfillment,omitempty"`
}

type GetOrdersResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetOrdersResponse"`

	Response *GetCrOrdersResponse `xml:"Response,omitempty"`
}

type GetCrOrdersResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetCrOrdersResponse"`

	QueryResponseHeader *QueryResponseHeader `xml:"QueryResponseHeader,omitempty"`
	TotalCount          int32                `xml:"TotalCount,omitempty"`
	OrderDetails        *OrderDetails        `xml:"OrderDetails,omitempty"`
}

type OrderDetails struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderDetails"`

	OrderDetail []*OrderDetail `xml:"OrderDetail,omitempty"`
}

type OrderDetail struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderDetail"`

	OrderInfo          *OrderInfo          `xml:"OrderInfo,omitempty"`
	CrCertificateInfo  *CertificateInfo    `xml:"CrCertificateInfo,omitempty"`
	Fulfillment        *Fulfillment        `xml:"Fulfillment,omitempty"`
	ModificationEvents *ModificationEvents `xml:"ModificationEvents,omitempty"`
}

type OrderInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderInfo"`

	OrderNo                   string          `xml:"OrderNo,omitempty"`
	OrderStatus               string          `xml:"OrderStatus,omitempty"`
	ProductCode               string          `xml:"ProductCode,omitempty"`
	OriginalOrderIDForReIssue string          `xml:"OriginalOrderIDForReIssue,omitempty"`
	ProfileNo                 string          `xml:"ProfileNo,omitempty"`
	LicenseNo                 string          `xml:"LicenseNo,omitempty"`
	RequestDate               string          `xml:"RequestDate,omitempty"`
	RequestBeforeDate         string          `xml:"RequestBeforeDate,omitempty"`
	RequestAfterDate          string          `xml:"RequestAfterDate,omitempty"`
	OrderDate                 string          `xml:"OrderDate,omitempty"`
	IssueDate                 string          `xml:"IssueDate,omitempty"`
	CancelRequestDate         string          `xml:"CancelRequestDate,omitempty"`
	CancelRequestUser         string          `xml:"CancelRequestUser,omitempty"`
	CancelDate                string          `xml:"CancelDate,omitempty"`
	RevokeRequestDate         string          `xml:"RevokeRequestDate,omitempty"`
	RevokeRequestUser         string          `xml:"RevokeRequestUser,omitempty"`
	RevokeDate                string          `xml:"RevokeDate,omitempty"`
	ValidityPeriod            *ValidityPeriod `xml:"ValidityPeriod,omitempty"`
}

type CertificateInfo struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ CertificateInfo"`

	CertificateStatus string             `xml:"CertificateStatus,omitempty"`
	SerialNumber      string             `xml:"SerialNumber,omitempty"`
	StartDate         string             `xml:"StartDate,omitempty"`
	EndDate           string             `xml:"EndDate,omitempty"`
	Email             string             `xml:"Email,omitempty"`
	CommonName        string             `xml:"CommonName,omitempty"`
	OrganizationUnits *OrganizationUnits `xml:"OrganizationUnits,omitempty"`
	Organization      string             `xml:"Organization,omitempty"`
	Locality          string             `xml:"Locality,omitempty"`
	State             string             `xml:"State,omitempty"`
	Country           string             `xml:"Country,omitempty"`
}

type Fulfillment struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Fulfillment"`

	CrCertificate *CrCertificate `xml:"CrCertificate,omitempty"`
}

type CrCertificate struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ CrCertificate"`

	Certificate string `xml:"Certificate,omitempty"`
	PKCS7Cert   string `xml:"PKCS7Cert,omitempty"`
}

type ModificationEvents struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ModificationEvents"`

	ModificationEvent []*ModificationEvent `xml:"ModificationEvent,omitempty"`
}

type ModificationEvent struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ModificationEvent"`

	ModificationEventName      string `xml:"ModificationEventName,omitempty"`
	ModificationEventTimestamp string `xml:"ModificationEventTimestamp,omitempty"`
}

type GetOrderByOrderId struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetOrderByOrderId"`

	Request *GetCrOrderByOrderIdRequest `xml:"Request,omitempty"`
}

type GetCrOrderByOrderIdRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetCrOrderByOrderIdRequest"`

	QueryRequestHeader *QueryRequestHeader `xml:"QueryRequestHeader,omitempty"`
	OrderNo            string              `xml:"OrderNo,omitempty"`
	OrderQueryOption   *OrderQueryOption   `xml:"OrderQueryOption,omitempty"`
}

type OrderQueryOption struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ OrderQueryOption"`

	ReturnCertificateInfo string `xml:"ReturnCertificateInfo,omitempty"`
	ReturnFulfillment     string `xml:"ReturnFulfillment,omitempty"`
	ReturnP7              string `xml:"ReturnP7,omitempty"`
	ReturnModEvents       string `xml:"ReturnModEvents,omitempty"`
}

type GetOrderByOrderIdResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetOrderByOrderIdResponse"`

	Response *GetCrOrderByOrderIdResponse `xml:"Response,omitempty"`
}

type GetCrOrderByOrderIdResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ GetCrOrderByOrderIdResponse"`

	QueryResponseHeader *QueryResponseHeader `xml:"QueryResponseHeader,omitempty"`
	OrderNo             string               `xml:"OrderNo,omitempty"`
	OrderDetail         *OrderDetail         `xml:"OrderDetail,omitempty"`
}

type Reissue struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ Reissue"`

	Request *ReissueOrderRequest `xml:"Request,omitempty"`
}

type ReissueOrderRequest struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ReissueOrderRequest"`

	OrderRequestHeader *OrderRequestHeader `xml:"OrderRequestHeader,omitempty"`
	TargetOrderID      string              `xml:"TargetOrderID,omitempty"`
	PickupPassword     string              `xml:"PickupPassword,omitempty"`
}

type ReissueResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ReissueResponse"`

	Response *ReissueOrderResponse `xml:"Response,omitempty"`
}

type ReissueOrderResponse struct {
	XMLName xml.Name `xml:"https://system.globalsign.com/cr/ws/ ReissueOrderResponse"`

	OrderResponseHeader *OrderResponseHeader `xml:"OrderResponseHeader,omitempty"`
	OrderID             string               `xml:"OrderID,omitempty"`
}

type GasOrderService struct {
	client *SOAPClient
}

func NewGasOrderService(url string, tls bool, auth *BasicAuth) *GasOrderService {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &GasOrderService{
		client: client,
	}
}

func (service *GasOrderService) GetProfiles(request *GetProfiles) (*GetProfilesResponse, error) {
	response := new(GetProfilesResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) OrderPkcs12(request *OrderPkcs12) (*OrderPkcs12Response, error) {
	response := new(OrderPkcs12Response)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) OrderAndIssueCertificate(request *OrderAndIssueCertificate) (*OrderAndIssueCertificateResponse, error) {
	response := new(OrderAndIssueCertificateResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) OrderCertificate(request *OrderCertificate) (*OrderCertificateResponse, error) {
	response := new(OrderCertificateResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) Cancel(request *Cancel) (*CancelResponse, error) {
	response := new(CancelResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) Revoke(request *Revoke) (*RevokeResponse, error) {
	response := new(RevokeResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) OrderDS(request *OrderDS) (*OrderDSResponse, error) {
	response := new(OrderDSResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) GetOrders(request *GetOrders) (*GetOrdersResponse, error) {
	response := new(GetOrdersResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) GetOrderByOrderId(request *GetOrderByOrderId) (*GetOrderByOrderIdResponse, error) {
	response := new(GetOrderByOrderIdResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *GasOrderService) Reissue(request *Reissue) (*ReissueResponse, error) {
	response := new(ReissueResponse)
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
