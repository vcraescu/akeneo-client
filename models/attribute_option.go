// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AttributeOption attribute option
//
// swagger:model AttributeOption
type AttributeOption struct {

	// Code of attribute related to the attribute option
	Attribute string `json:"attribute,omitempty"`

	// Code of option
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *AttributeOptionLabels `json:"labels,omitempty"`

	// Order of attribute option
	SortOrder int64 `json:"sort_order,omitempty"`
}

// Validate validates this attribute option
func (m *AttributeOption) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AttributeOption) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *AttributeOption) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(m.Labels) { // not required
		return nil
	}

	if m.Labels != nil {
		if err := m.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("labels")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AttributeOption) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeOption) UnmarshalBinary(b []byte) error {
	var res AttributeOption
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AttributeOptionLabels Attribute option labels for each locale
//
// swagger:model AttributeOptionLabels
type AttributeOptionLabels struct {

	// Attribute option label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this attribute option labels
func (m *AttributeOptionLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AttributeOptionLabels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeOptionLabels) UnmarshalBinary(b []byte) error {
	var res AttributeOptionLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
