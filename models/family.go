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

// Family family
//
// swagger:model Family
type Family struct {

	// Attribute code used as the main picture in the user interface (only since v2.0)
	AttributeAsImage *string `json:"attribute_as_image,omitempty"`

	// Attribute code used as label
	// Required: true
	AttributeAsLabel *string `json:"attribute_as_label"`

	// attribute requirements
	AttributeRequirements *FamilyAttributeRequirements `json:"attribute_requirements,omitempty"`

	// Attributes codes that compose the family
	Attributes []string `json:"attributes"`

	// Family code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *FamilyLabels `json:"labels,omitempty"`
}

// Validate validates this family
func (m *Family) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttributeAsLabel(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAttributeRequirements(formats); err != nil {
		res = append(res, err)
	}

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

func (m *Family) validateAttributeAsLabel(formats strfmt.Registry) error {

	if err := validate.Required("attribute_as_label", "body", m.AttributeAsLabel); err != nil {
		return err
	}

	return nil
}

func (m *Family) validateAttributeRequirements(formats strfmt.Registry) error {

	if swag.IsZero(m.AttributeRequirements) { // not required
		return nil
	}

	if m.AttributeRequirements != nil {
		if err := m.AttributeRequirements.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attribute_requirements")
			}
			return err
		}
	}

	return nil
}

func (m *Family) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *Family) validateLabels(formats strfmt.Registry) error {

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
func (m *Family) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Family) UnmarshalBinary(b []byte) error {
	var res Family
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FamilyAttributeRequirements Attributes codes of the family that are required for the completeness calculation for each channel
//
// swagger:model FamilyAttributeRequirements
type FamilyAttributeRequirements struct {

	// channel code
	ChannelCode []string `json:"channelCode"`
}

// Validate validates this family attribute requirements
func (m *FamilyAttributeRequirements) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FamilyAttributeRequirements) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyAttributeRequirements) UnmarshalBinary(b []byte) error {
	var res FamilyAttributeRequirements
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FamilyLabels Family labels for each locale
//
// swagger:model FamilyLabels
type FamilyLabels struct {

	// Family label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this family labels
func (m *FamilyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FamilyLabels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyLabels) UnmarshalBinary(b []byte) error {
	var res FamilyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
