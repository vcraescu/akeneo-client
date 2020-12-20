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

// DeprecatedAssetCategoryList deprecated asset category list
//
// swagger:model DeprecatedAssetCategoryList
type DeprecatedAssetCategoryList struct {

	// links
	Links *DeprecatedAssetCategoryListAO0Links `json:"_links,omitempty"`

	// PAM asset category code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *DeprecatedAssetCategoryListAO1Labels `json:"labels,omitempty"`

	// PAM ssset category code of the parent's asset category
	Parent *string `json:"parent,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *DeprecatedAssetCategoryList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *DeprecatedAssetCategoryListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Labels *DeprecatedAssetCategoryListAO1Labels `json:"labels,omitempty"`

		Parent *string `json:"parent,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.Labels = dataAO1.Labels

	m.Parent = dataAO1.Parent

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m DeprecatedAssetCategoryList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *DeprecatedAssetCategoryListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Labels *DeprecatedAssetCategoryListAO1Labels `json:"labels,omitempty"`

		Parent *string `json:"parent,omitempty"`
	}

	dataAO1.Code = m.Code

	dataAO1.Labels = m.Labels

	dataAO1.Parent = m.Parent

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this deprecated asset category list
func (m *DeprecatedAssetCategoryList) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
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

func (m *DeprecatedAssetCategoryList) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(m.Links) { // not required
		return nil
	}

	if m.Links != nil {
		if err := m.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links")
			}
			return err
		}
	}

	return nil
}

func (m *DeprecatedAssetCategoryList) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *DeprecatedAssetCategoryList) validateLabels(formats strfmt.Registry) error {

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
func (m *DeprecatedAssetCategoryList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetCategoryList) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetCategoryList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetCategoryListAO0Links deprecated asset category list a o0 links
//
// swagger:model DeprecatedAssetCategoryListAO0Links
type DeprecatedAssetCategoryListAO0Links struct {

	// self
	Self *DeprecatedAssetCategoryListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this deprecated asset category list a o0 links
func (m *DeprecatedAssetCategoryListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeprecatedAssetCategoryListAO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(m.Self) { // not required
		return nil
	}

	if m.Self != nil {
		if err := m.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetCategoryListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetCategoryListAO0Links) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetCategoryListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetCategoryListAO0LinksSelf deprecated asset category list a o0 links self
//
// swagger:model DeprecatedAssetCategoryListAO0LinksSelf
type DeprecatedAssetCategoryListAO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this deprecated asset category list a o0 links self
func (m *DeprecatedAssetCategoryListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetCategoryListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetCategoryListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetCategoryListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetCategoryListAO1Labels PAM asset category labels for each locale
//
// swagger:model DeprecatedAssetCategoryListAO1Labels
type DeprecatedAssetCategoryListAO1Labels struct {

	// PAM asset category label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this deprecated asset category list a o1 labels
func (m *DeprecatedAssetCategoryListAO1Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetCategoryListAO1Labels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetCategoryListAO1Labels) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetCategoryListAO1Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}