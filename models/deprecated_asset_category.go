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

// DeprecatedAssetCategory deprecated asset category
//
// swagger:model DeprecatedAssetCategory
type DeprecatedAssetCategory struct {

	// PAM asset category code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *DeprecatedAssetCategoryLabels `json:"labels,omitempty"`

	// PAM ssset category code of the parent's asset category
	Parent *string `json:"parent,omitempty"`
}

// Validate validates this deprecated asset category
func (m *DeprecatedAssetCategory) Validate(formats strfmt.Registry) error {
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

func (m *DeprecatedAssetCategory) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *DeprecatedAssetCategory) validateLabels(formats strfmt.Registry) error {

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
func (m *DeprecatedAssetCategory) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetCategory) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetCategory
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetCategoryLabels PAM asset category labels for each locale
//
// swagger:model DeprecatedAssetCategoryLabels
type DeprecatedAssetCategoryLabels struct {

	// PAM asset category label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this deprecated asset category labels
func (m *DeprecatedAssetCategoryLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetCategoryLabels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetCategoryLabels) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetCategoryLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}