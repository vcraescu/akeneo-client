// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ErrorByLine error by line
//
// swagger:model ErrorByLine
type ErrorByLine struct {

	// Resource code, only filled when the resource is not a product
	Code string `json:"code,omitempty"`

	// Resource identifier, only filled when the resource is a product
	Identifier string `json:"identifier,omitempty"`

	// Line number
	Line int64 `json:"line,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`

	// HTTP status code, see <a href="/documentation/responses.html#client-errors">Client errors</a> to understand the meaning of each code
	StatusCode int64 `json:"status_code,omitempty"`
}

// Validate validates this error by line
func (m *ErrorByLine) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ErrorByLine) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ErrorByLine) UnmarshalBinary(b []byte) error {
	var res ErrorByLine
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}