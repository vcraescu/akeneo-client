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

// FamilyVariantList family variant list
//
// swagger:model FamilyVariantList
type FamilyVariantList struct {

	// links
	Links *FamilyVariantListAO0Links `json:"_links,omitempty"`

	// Family variant code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *FamilyVariantListAO1Labels `json:"labels,omitempty"`

	// Attributes distribution according to the enrichment level
	// Required: true
	VariantAttributeSets []*FamilyVariantListVariantAttributeSetsItems0 `json:"variant_attribute_sets"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *FamilyVariantList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *FamilyVariantListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Labels *FamilyVariantListAO1Labels `json:"labels,omitempty"`

		VariantAttributeSets []*FamilyVariantListVariantAttributeSetsItems0 `json:"variant_attribute_sets"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.Labels = dataAO1.Labels

	m.VariantAttributeSets = dataAO1.VariantAttributeSets

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m FamilyVariantList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *FamilyVariantListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Labels *FamilyVariantListAO1Labels `json:"labels,omitempty"`

		VariantAttributeSets []*FamilyVariantListVariantAttributeSetsItems0 `json:"variant_attribute_sets"`
	}

	dataAO1.Code = m.Code

	dataAO1.Labels = m.Labels

	dataAO1.VariantAttributeSets = m.VariantAttributeSets

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this family variant list
func (m *FamilyVariantList) Validate(formats strfmt.Registry) error {
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

	if err := m.validateVariantAttributeSets(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FamilyVariantList) validateLinks(formats strfmt.Registry) error {

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

func (m *FamilyVariantList) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *FamilyVariantList) validateLabels(formats strfmt.Registry) error {

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

func (m *FamilyVariantList) validateVariantAttributeSets(formats strfmt.Registry) error {

	if err := validate.Required("variant_attribute_sets", "body", m.VariantAttributeSets); err != nil {
		return err
	}

	for i := 0; i < len(m.VariantAttributeSets); i++ {
		if swag.IsZero(m.VariantAttributeSets[i]) { // not required
			continue
		}

		if m.VariantAttributeSets[i] != nil {
			if err := m.VariantAttributeSets[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("variant_attribute_sets" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *FamilyVariantList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyVariantList) UnmarshalBinary(b []byte) error {
	var res FamilyVariantList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FamilyVariantListAO0Links family variant list a o0 links
//
// swagger:model FamilyVariantListAO0Links
type FamilyVariantListAO0Links struct {

	// self
	Self *FamilyVariantListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this family variant list a o0 links
func (m *FamilyVariantListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FamilyVariantListAO0Links) validateSelf(formats strfmt.Registry) error {

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
func (m *FamilyVariantListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyVariantListAO0Links) UnmarshalBinary(b []byte) error {
	var res FamilyVariantListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FamilyVariantListAO0LinksSelf family variant list a o0 links self
//
// swagger:model FamilyVariantListAO0LinksSelf
type FamilyVariantListAO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this family variant list a o0 links self
func (m *FamilyVariantListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FamilyVariantListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyVariantListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res FamilyVariantListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FamilyVariantListAO1Labels Family variant labels for each locale
//
// swagger:model FamilyVariantListAO1Labels
type FamilyVariantListAO1Labels struct {

	// Family variant label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this family variant list a o1 labels
func (m *FamilyVariantListAO1Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FamilyVariantListAO1Labels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyVariantListAO1Labels) UnmarshalBinary(b []byte) error {
	var res FamilyVariantListAO1Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FamilyVariantListVariantAttributeSetsItems0 Enrichment level
//
// swagger:model FamilyVariantListVariantAttributeSetsItems0
type FamilyVariantListVariantAttributeSetsItems0 struct {

	// Codes of attributes bind to this enrichment level
	Attributes []string `json:"attributes"`

	// Codes of attributes used as variant axes
	// Required: true
	Axes []string `json:"axes"`

	// Enrichment level
	// Required: true
	Level *int64 `json:"level"`
}

// Validate validates this family variant list variant attribute sets items0
func (m *FamilyVariantListVariantAttributeSetsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAxes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLevel(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FamilyVariantListVariantAttributeSetsItems0) validateAxes(formats strfmt.Registry) error {

	if err := validate.Required("axes", "body", m.Axes); err != nil {
		return err
	}

	return nil
}

func (m *FamilyVariantListVariantAttributeSetsItems0) validateLevel(formats strfmt.Registry) error {

	if err := validate.Required("level", "body", m.Level); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *FamilyVariantListVariantAttributeSetsItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FamilyVariantListVariantAttributeSetsItems0) UnmarshalBinary(b []byte) error {
	var res FamilyVariantListVariantAttributeSetsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
