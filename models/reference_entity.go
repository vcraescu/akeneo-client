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

// ReferenceEntity reference entity
//
// swagger:model ReferenceEntity
type ReferenceEntity struct {

	// links
	Links *ReferenceEntityAO0Links `json:"_links,omitempty"`

	// Reference entity code
	// Required: true
	Code *string `json:"code"`

	// Code of the reference entity image
	Image string `json:"image,omitempty"`

	// labels
	Labels *ReferenceEntityAO1Labels `json:"labels,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *ReferenceEntity) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *ReferenceEntityAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Image string `json:"image,omitempty"`

		Labels *ReferenceEntityAO1Labels `json:"labels,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.Image = dataAO1.Image

	m.Labels = dataAO1.Labels

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m ReferenceEntity) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *ReferenceEntityAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Image string `json:"image,omitempty"`

		Labels *ReferenceEntityAO1Labels `json:"labels,omitempty"`
	}

	dataAO1.Code = m.Code

	dataAO1.Image = m.Image

	dataAO1.Labels = m.Labels

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this reference entity
func (m *ReferenceEntity) Validate(formats strfmt.Registry) error {
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

func (m *ReferenceEntity) validateLinks(formats strfmt.Registry) error {

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

func (m *ReferenceEntity) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *ReferenceEntity) validateLabels(formats strfmt.Registry) error {

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
func (m *ReferenceEntity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReferenceEntity) UnmarshalBinary(b []byte) error {
	var res ReferenceEntity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ReferenceEntityAO0Links reference entity a o0 links
//
// swagger:model ReferenceEntityAO0Links
type ReferenceEntityAO0Links struct {

	// image download
	ImageDownload *ReferenceEntityAO0LinksImageDownload `json:"image_download,omitempty"`
}

// Validate validates this reference entity a o0 links
func (m *ReferenceEntityAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateImageDownload(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ReferenceEntityAO0Links) validateImageDownload(formats strfmt.Registry) error {

	if swag.IsZero(m.ImageDownload) { // not required
		return nil
	}

	if m.ImageDownload != nil {
		if err := m.ImageDownload.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "image_download")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ReferenceEntityAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReferenceEntityAO0Links) UnmarshalBinary(b []byte) error {
	var res ReferenceEntityAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ReferenceEntityAO0LinksImageDownload reference entity a o0 links image download
//
// swagger:model ReferenceEntityAO0LinksImageDownload
type ReferenceEntityAO0LinksImageDownload struct {

	// URI to download the binaries of the reference entity image file
	Href string `json:"href,omitempty"`
}

// Validate validates this reference entity a o0 links image download
func (m *ReferenceEntityAO0LinksImageDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ReferenceEntityAO0LinksImageDownload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReferenceEntityAO0LinksImageDownload) UnmarshalBinary(b []byte) error {
	var res ReferenceEntityAO0LinksImageDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ReferenceEntityAO1Labels Reference entity labels for each locale
//
// swagger:model ReferenceEntityAO1Labels
type ReferenceEntityAO1Labels struct {

	// Reference entity label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this reference entity a o1 labels
func (m *ReferenceEntityAO1Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ReferenceEntityAO1Labels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReferenceEntityAO1Labels) UnmarshalBinary(b []byte) error {
	var res ReferenceEntityAO1Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}