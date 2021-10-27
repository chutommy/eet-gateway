// Code generated by mockery v2.9.4. DO NOT EDIT.

// EETGateway - Tommy Chu

package mocks

import (
	rsa "crypto/rsa"

	mock "github.com/stretchr/testify/mock"

	x509 "crypto/x509"
)

// CAService is an autogenerated mock type for the CAService type
type CAService struct {
	mock.Mock
}

// ParseTaxpayerCertificate provides a mock function with given fields: data, password
func (_m *CAService) ParseTaxpayerCertificate(data []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	ret := _m.Called(data, password)

	var r0 *x509.Certificate
	if rf, ok := ret.Get(0).(func([]byte, string) *x509.Certificate); ok {
		r0 = rf(data, password)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*x509.Certificate)
		}
	}

	var r1 *rsa.PrivateKey
	if rf, ok := ret.Get(1).(func([]byte, string) *rsa.PrivateKey); ok {
		r1 = rf(data, password)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*rsa.PrivateKey)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func([]byte, string) error); ok {
		r2 = rf(data, password)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// VerifyDSig provides a mock function with given fields: cert
func (_m *CAService) VerifyDSig(cert *x509.Certificate) error {
	ret := _m.Called(cert)

	var r0 error
	if rf, ok := ret.Get(0).(func(*x509.Certificate) error); ok {
		r0 = rf(cert)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}