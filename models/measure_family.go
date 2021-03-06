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

// MeasureFamily measure family
//
// swagger:model MeasureFamily
type MeasureFamily struct {

	// Measure family code
	// Required: true
	Code *string `json:"code"`

	// Measure family standard
	Standard string `json:"standard,omitempty"`

	// Family units
	Units []*MeasureFamilyUnitsItems0 `json:"units"`
}

// Validate validates this measure family
func (m *MeasureFamily) Validate(formats strfmt.Registry) error {
	var res []error

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

func (m *MeasureFamily) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *MeasureFamily) validateUnits(formats strfmt.Registry) error {

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
func (m *MeasureFamily) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MeasureFamily) UnmarshalBinary(b []byte) error {
	var res MeasureFamily
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MeasureFamilyUnitsItems0 measure family units items0
//
// swagger:model MeasureFamilyUnitsItems0
type MeasureFamilyUnitsItems0 struct {

	// Measure code
	Code string `json:"code,omitempty"`

	// Mathematic operation to convert the unit into the standard unit
	Convert interface{} `json:"convert,omitempty"`

	// Measure symbol
	Symbol string `json:"symbol,omitempty"`
}

// Validate validates this measure family units items0
func (m *MeasureFamilyUnitsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MeasureFamilyUnitsItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MeasureFamilyUnitsItems0) UnmarshalBinary(b []byte) error {
	var res MeasureFamilyUnitsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
