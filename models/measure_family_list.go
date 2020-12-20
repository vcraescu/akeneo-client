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

// MeasureFamilyList measure family list
//
// swagger:model MeasureFamilyList
type MeasureFamilyList struct {

	// links
	Links *MeasureFamilyListAO0Links `json:"_links,omitempty"`

	// Measure family code
	// Required: true
	Code *string `json:"code"`

	// Measure family standard
	Standard string `json:"standard,omitempty"`

	// Family units
	Units []*MeasureFamilyListUnitsItems0 `json:"units"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *MeasureFamilyList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *MeasureFamilyListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Standard string `json:"standard,omitempty"`

		Units []*MeasureFamilyListUnitsItems0 `json:"units"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.Standard = dataAO1.Standard

	m.Units = dataAO1.Units

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m MeasureFamilyList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *MeasureFamilyListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Standard string `json:"standard,omitempty"`

		Units []*MeasureFamilyListUnitsItems0 `json:"units"`
	}

	dataAO1.Code = m.Code

	dataAO1.Standard = m.Standard

	dataAO1.Units = m.Units

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this measure family list
func (m *MeasureFamilyList) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUnits(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MeasureFamilyList) validateLinks(formats strfmt.Registry) error {

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

func (m *MeasureFamilyList) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *MeasureFamilyList) validateUnits(formats strfmt.Registry) error {

	if swag.IsZero(m.Units) { // not required
		return nil
	}

	for i := 0; i < len(m.Units); i++ {
		if swag.IsZero(m.Units[i]) { // not required
			continue
		}

		if m.Units[i] != nil {
			if err := m.Units[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("units" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *MeasureFamilyList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MeasureFamilyList) UnmarshalBinary(b []byte) error {
	var res MeasureFamilyList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MeasureFamilyListAO0Links measure family list a o0 links
//
// swagger:model MeasureFamilyListAO0Links
type MeasureFamilyListAO0Links struct {

	// self
	Self *MeasureFamilyListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this measure family list a o0 links
func (m *MeasureFamilyListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MeasureFamilyListAO0Links) validateSelf(formats strfmt.Registry) error {

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
func (m *MeasureFamilyListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MeasureFamilyListAO0Links) UnmarshalBinary(b []byte) error {
	var res MeasureFamilyListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MeasureFamilyListAO0LinksSelf measure family list a o0 links self
//
// swagger:model MeasureFamilyListAO0LinksSelf
type MeasureFamilyListAO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this measure family list a o0 links self
func (m *MeasureFamilyListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MeasureFamilyListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MeasureFamilyListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res MeasureFamilyListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MeasureFamilyListUnitsItems0 measure family list units items0
//
// swagger:model MeasureFamilyListUnitsItems0
type MeasureFamilyListUnitsItems0 struct {

	// Measure code
	Code string `json:"code,omitempty"`

	// Mathematic operation to convert the unit into the standard unit
	Convert interface{} `json:"convert,omitempty"`

	// Measure symbol
	Symbol string `json:"symbol,omitempty"`
}

// Validate validates this measure family list units items0
func (m *MeasureFamilyListUnitsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MeasureFamilyListUnitsItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MeasureFamilyListUnitsItems0) UnmarshalBinary(b []byte) error {
	var res MeasureFamilyListUnitsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}