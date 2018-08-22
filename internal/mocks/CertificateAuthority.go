// Code generated by mockery v1.0.0. DO NOT EDIT.
package mocks

import k8s "github.com/liquidweb/kube-cert-manager/internal/k8s"
import mock "github.com/stretchr/testify/mock"
import mux "github.com/gorilla/mux"

import tls "github.com/liquidweb/kube-cert-manager/internal/tls"

// CertificateAuthority is an autogenerated mock type for the CertificateAuthority type
type CertificateAuthority struct {
	mock.Mock
}

// ProvisionCert provides a mock function with given fields: _a0
func (_m *CertificateAuthority) ProvisionCert(_a0 *k8s.Certificate) (*tls.Bundle, error) {
	ret := _m.Called(_a0)

	var r0 *tls.Bundle
	if rf, ok := ret.Get(0).(func(*k8s.Certificate) *tls.Bundle); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tls.Bundle)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*k8s.Certificate) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RenewCert provides a mock function with given fields: _a0, _a1
func (_m *CertificateAuthority) RenewCert(_a0 *k8s.Certificate, _a1 *tls.Bundle) (*tls.Bundle, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *tls.Bundle
	if rf, ok := ret.Get(0).(func(*k8s.Certificate, *tls.Bundle) *tls.Bundle); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tls.Bundle)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*k8s.Certificate, *tls.Bundle) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetupRoute provides a mock function with given fields: _a0
func (_m *CertificateAuthority) SetupRoute(_a0 *mux.Router) {
	_m.Called(_a0)
}