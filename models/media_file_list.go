// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MediaFileList media file list
//
// swagger:model MediaFileList
type MediaFileList struct {

	// links
	Links *MediaFileListAO0Links `json:"_links,omitempty"`

	// Media file code
	Code string `json:"code,omitempty"`

	// Extension of the media file
	Extension string `json:"extension,omitempty"`

	// Mime type of the media file
	MimeType string `json:"mime_type,omitempty"`

	// Original filename of the media file
	OriginalFilename string `json:"original_filename,omitempty"`

	// Size of the media file
	Size int64 `json:"size,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *MediaFileList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *MediaFileListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code string `json:"code,omitempty"`

		Extension string `json:"extension,omitempty"`

		MimeType string `json:"mime_type,omitempty"`

		OriginalFilename string `json:"original_filename,omitempty"`

		Size int64 `json:"size,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.Extension = dataAO1.Extension

	m.MimeType = dataAO1.MimeType

	m.OriginalFilename = dataAO1.OriginalFilename

	m.Size = dataAO1.Size

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m MediaFileList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *MediaFileListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code string `json:"code,omitempty"`

		Extension string `json:"extension,omitempty"`

		MimeType string `json:"mime_type,omitempty"`

		OriginalFilename string `json:"original_filename,omitempty"`

		Size int64 `json:"size,omitempty"`
	}

	dataAO1.Code = m.Code

	dataAO1.Extension = m.Extension

	dataAO1.MimeType = m.MimeType

	dataAO1.OriginalFilename = m.OriginalFilename

	dataAO1.Size = m.Size

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this media file list
func (m *MediaFileList) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MediaFileList) validateLinks(formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *MediaFileList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MediaFileList) UnmarshalBinary(b []byte) error {
	var res MediaFileList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MediaFileListAO0Links media file list a o0 links
//
// swagger:model MediaFileListAO0Links
type MediaFileListAO0Links struct {

	// download
	Download *MediaFileListAO0LinksDownload `json:"download,omitempty"`

	// self
	Self *MediaFileListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this media file list a o0 links
func (m *MediaFileListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDownload(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MediaFileListAO0Links) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(m.Download) { // not required
		return nil
	}

	if m.Download != nil {
		if err := m.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (m *MediaFileListAO0Links) validateSelf(formats strfmt.Registry) error {

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
func (m *MediaFileListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MediaFileListAO0Links) UnmarshalBinary(b []byte) error {
	var res MediaFileListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MediaFileListAO0LinksDownload media file list a o0 links download
//
// swagger:model MediaFileListAO0LinksDownload
type MediaFileListAO0LinksDownload struct {

	// URI to download the binaries of the media file
	Href string `json:"href,omitempty"`
}

// Validate validates this media file list a o0 links download
func (m *MediaFileListAO0LinksDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MediaFileListAO0LinksDownload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MediaFileListAO0LinksDownload) UnmarshalBinary(b []byte) error {
	var res MediaFileListAO0LinksDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// MediaFileListAO0LinksSelf media file list a o0 links self
//
// swagger:model MediaFileListAO0LinksSelf
type MediaFileListAO0LinksSelf struct {

	// URI to get the metadata of the media file
	Href string `json:"href,omitempty"`
}

// Validate validates this media file list a o0 links self
func (m *MediaFileListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MediaFileListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MediaFileListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res MediaFileListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
