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

// Channel channel
//
// swagger:model Channel
type Channel struct {

	// Code of the category tree linked to the channel
	// Required: true
	CategoryTree *string `json:"category_tree"`

	// Channel code
	// Required: true
	Code *string `json:"code"`

	// conversion units
	ConversionUnits *ChannelConversionUnits `json:"conversion_units,omitempty"`

	// Codes of activated currencies for the channel
	// Required: true
	Currencies []string `json:"currencies"`

	// labels
	Labels *ChannelLabels `json:"labels,omitempty"`

	// Codes of activated locales for the channel
	// Required: true
	Locales []string `json:"locales"`
}

// Validate validates this channel
func (m *Channel) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCategoryTree(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConversionUnits(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCurrencies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocales(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Channel) validateCategoryTree(formats strfmt.Registry) error {

	if err := validate.Required("category_tree", "body", m.CategoryTree); err != nil {
		return err
	}

	return nil
}

func (m *Channel) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *Channel) validateConversionUnits(formats strfmt.Registry) error {

	if swag.IsZero(m.ConversionUnits) { // not required
		return nil
	}

	if m.ConversionUnits != nil {
		if err := m.ConversionUnits.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("conversion_units")
			}
			return err
		}
	}

	return nil
}

func (m *Channel) validateCurrencies(formats strfmt.Registry) error {

	if err := validate.Required("currencies", "body", m.Currencies); err != nil {
		return err
	}

	return nil
}

func (m *Channel) validateLabels(formats strfmt.Registry) error {

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

func (m *Channel) validateLocales(formats strfmt.Registry) error {

	if err := validate.Required("locales", "body", m.Locales); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Channel) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Channel) UnmarshalBinary(b []byte) error {
	var res Channel
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ChannelConversionUnits Units to which the given metric attributes should be converted when exporting products
//
// swagger:model ChannelConversionUnits
type ChannelConversionUnits struct {

	// Conversion unit code used to convert the values of the attribute `attributeCode` when exporting via the channel
	AttributeCode string `json:"attributeCode,omitempty"`
}

// Validate validates this channel conversion units
func (m *ChannelConversionUnits) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ChannelConversionUnits) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ChannelConversionUnits) UnmarshalBinary(b []byte) error {
	var res ChannelConversionUnits
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ChannelLabels Channel labels for each locale
//
// swagger:model ChannelLabels
type ChannelLabels struct {

	// Channel label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this channel labels
func (m *ChannelLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ChannelLabels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ChannelLabels) UnmarshalBinary(b []byte) error {
	var res ChannelLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
