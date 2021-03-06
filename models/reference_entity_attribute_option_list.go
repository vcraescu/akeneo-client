// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ReferenceEntityAttributeOptionList reference entity attribute option list
//
// swagger:model ReferenceEntityAttributeOptionList
type ReferenceEntityAttributeOptionList []*ReferenceEntityAttributeOptionListItems0

// Validate validates this reference entity attribute option list
func (m ReferenceEntityAttributeOptionList) Validate(formats strfmt.Registry) error {
	var res []error

	for i := 0; i < len(m); i++ {
		if swag.IsZero(m[i]) { // not required
			continue
		}

		if m[i] != nil {
			if err := m[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName(strconv.Itoa(i))
				}
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ReferenceEntityAttributeOptionListItems0 reference entity attribute option list items0
//
// swagger:model ReferenceEntityAttributeOptionListItems0
type ReferenceEntityAttributeOptionListItems0 struct {

	// Attribute's option code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *ReferenceEntityAttributeOptionListItems0Labels `json:"labels,omitempty"`
}

// Validate validates this reference entity attribute option list items0
func (m *ReferenceEntityAttributeOptionListItems0) Validate(formats strfmt.Registry) error {
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

func (m *ReferenceEntityAttributeOptionListItems0) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *ReferenceEntityAttributeOptionListItems0) validateLabels(formats strfmt.Registry) error {

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
func (m *ReferenceEntityAttributeOptionListItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReferenceEntityAttributeOptionListItems0) UnmarshalBinary(b []byte) error {
	var res ReferenceEntityAttributeOptionListItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ReferenceEntityAttributeOptionListItems0Labels Attribute labels for each locale
//
// swagger:model ReferenceEntityAttributeOptionListItems0Labels
type ReferenceEntityAttributeOptionListItems0Labels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this reference entity attribute option list items0 labels
func (m *ReferenceEntityAttributeOptionListItems0Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ReferenceEntityAttributeOptionListItems0Labels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReferenceEntityAttributeOptionListItems0Labels) UnmarshalBinary(b []byte) error {
	var res ReferenceEntityAttributeOptionListItems0Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
