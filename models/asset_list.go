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

// AssetList asset list
//
// swagger:model AssetList
type AssetList struct {

	// links
	Links *AssetListAO0Links `json:"_links,omitempty"`

	// Code of the asset
	// Required: true
	Code *string `json:"code"`

	// values
	Values *AssetListAO1Values `json:"values,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *AssetList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *AssetListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Values *AssetListAO1Values `json:"values,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.Values = dataAO1.Values

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m AssetList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *AssetListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Values *AssetListAO1Values `json:"values,omitempty"`
	}

	dataAO1.Code = m.Code

	dataAO1.Values = m.Values

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this asset list
func (m *AssetList) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValues(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AssetList) validateLinks(formats strfmt.Registry) error {

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

func (m *AssetList) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *AssetList) validateValues(formats strfmt.Registry) error {

	if swag.IsZero(m.Values) { // not required
		return nil
	}

	if m.Values != nil {
		if err := m.Values.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("values")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AssetList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AssetList) UnmarshalBinary(b []byte) error {
	var res AssetList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AssetListAO0Links asset list a o0 links
//
// swagger:model AssetListAO0Links
type AssetListAO0Links struct {

	// self
	Self *AssetListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this asset list a o0 links
func (m *AssetListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AssetListAO0Links) validateSelf(formats strfmt.Registry) error {

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
func (m *AssetListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AssetListAO0Links) UnmarshalBinary(b []byte) error {
	var res AssetListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AssetListAO0LinksSelf asset list a o0 links self
//
// swagger:model AssetListAO0LinksSelf
type AssetListAO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this asset list a o0 links self
func (m *AssetListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AssetListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AssetListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res AssetListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AssetListAO1Values Asset attributes values, see the <a href='/concepts/asset-manager.html#focus-on-the-asset-values'>Focus on the asset values</a> section for more details.
//
// swagger:model AssetListAO1Values
type AssetListAO1Values struct {

	// attribute code
	AttributeCode []*AssetListAO1ValuesAttributeCodeItems0 `json:"attributeCode"`
}

// Validate validates this asset list a o1 values
func (m *AssetListAO1Values) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttributeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AssetListAO1Values) validateAttributeCode(formats strfmt.Registry) error {

	if swag.IsZero(m.AttributeCode) { // not required
		return nil
	}

	for i := 0; i < len(m.AttributeCode); i++ {
		if swag.IsZero(m.AttributeCode[i]) { // not required
			continue
		}

		if m.AttributeCode[i] != nil {
			if err := m.AttributeCode[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("values" + "." + "attributeCode" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *AssetListAO1Values) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AssetListAO1Values) UnmarshalBinary(b []byte) error {
	var res AssetListAO1Values
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AssetListAO1ValuesAttributeCodeItems0 asset list a o1 values attribute code items0
//
// swagger:model AssetListAO1ValuesAttributeCodeItems0
type AssetListAO1ValuesAttributeCodeItems0 struct {

	// Channel code of the asset attribute value
	Channel string `json:"channel,omitempty"`

	// Asset attribute value
	Data interface{} `json:"data,omitempty"`

	// Locale code of the asset attribute value
	Locale string `json:"locale,omitempty"`
}

// Validate validates this asset list a o1 values attribute code items0
func (m *AssetListAO1ValuesAttributeCodeItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AssetListAO1ValuesAttributeCodeItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AssetListAO1ValuesAttributeCodeItems0) UnmarshalBinary(b []byte) error {
	var res AssetListAO1ValuesAttributeCodeItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}