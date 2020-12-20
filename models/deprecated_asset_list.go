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

// DeprecatedAssetList deprecated asset list
//
// swagger:model DeprecatedAssetList
type DeprecatedAssetList struct {

	// links
	Links *DeprecatedAssetListAO0Links `json:"_links,omitempty"`

	// Codes of the PAM asset categories in which the asset is classified
	Categories []string `json:"categories"`

	// PAM asset code
	// Required: true
	Code *string `json:"code"`

	// Description of the PAM asset
	Description string `json:"description,omitempty"`

	// Date on which the PAM asset expire
	EndOfUse string `json:"end_of_use,omitempty"`

	// Whether the asset is localized or not, meaning if you want to have different reference files for each of your locale
	Localizable *bool `json:"localizable,omitempty"`

	// Reference files of the PAM asset
	ReferenceFiles []*DeprecatedAssetListReferenceFilesItems0 `json:"reference_files"`

	// Tags of the PAM asset
	Tags []string `json:"tags"`

	// Variations of the PAM asset
	VariationFiles []*DeprecatedAssetListVariationFilesItems0 `json:"variation_files"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *DeprecatedAssetList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *DeprecatedAssetListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Categories []string `json:"categories"`

		Code *string `json:"code"`

		Description string `json:"description,omitempty"`

		EndOfUse string `json:"end_of_use,omitempty"`

		Localizable *bool `json:"localizable,omitempty"`

		ReferenceFiles []*DeprecatedAssetListReferenceFilesItems0 `json:"reference_files"`

		Tags []string `json:"tags"`

		VariationFiles []*DeprecatedAssetListVariationFilesItems0 `json:"variation_files"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Categories = dataAO1.Categories

	m.Code = dataAO1.Code

	m.Description = dataAO1.Description

	m.EndOfUse = dataAO1.EndOfUse

	m.Localizable = dataAO1.Localizable

	m.ReferenceFiles = dataAO1.ReferenceFiles

	m.Tags = dataAO1.Tags

	m.VariationFiles = dataAO1.VariationFiles

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m DeprecatedAssetList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *DeprecatedAssetListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Categories []string `json:"categories"`

		Code *string `json:"code"`

		Description string `json:"description,omitempty"`

		EndOfUse string `json:"end_of_use,omitempty"`

		Localizable *bool `json:"localizable,omitempty"`

		ReferenceFiles []*DeprecatedAssetListReferenceFilesItems0 `json:"reference_files"`

		Tags []string `json:"tags"`

		VariationFiles []*DeprecatedAssetListVariationFilesItems0 `json:"variation_files"`
	}

	dataAO1.Categories = m.Categories

	dataAO1.Code = m.Code

	dataAO1.Description = m.Description

	dataAO1.EndOfUse = m.EndOfUse

	dataAO1.Localizable = m.Localizable

	dataAO1.ReferenceFiles = m.ReferenceFiles

	dataAO1.Tags = m.Tags

	dataAO1.VariationFiles = m.VariationFiles

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this deprecated asset list
func (m *DeprecatedAssetList) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReferenceFiles(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVariationFiles(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeprecatedAssetList) validateLinks(formats strfmt.Registry) error {

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

func (m *DeprecatedAssetList) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *DeprecatedAssetList) validateReferenceFiles(formats strfmt.Registry) error {

	if swag.IsZero(m.ReferenceFiles) { // not required
		return nil
	}

	for i := 0; i < len(m.ReferenceFiles); i++ {
		if swag.IsZero(m.ReferenceFiles[i]) { // not required
			continue
		}

		if m.ReferenceFiles[i] != nil {
			if err := m.ReferenceFiles[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("reference_files" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DeprecatedAssetList) validateVariationFiles(formats strfmt.Registry) error {

	if swag.IsZero(m.VariationFiles) { // not required
		return nil
	}

	for i := 0; i < len(m.VariationFiles); i++ {
		if swag.IsZero(m.VariationFiles[i]) { // not required
			continue
		}

		if m.VariationFiles[i] != nil {
			if err := m.VariationFiles[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("variation_files" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetList) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListAO0Links deprecated asset list a o0 links
//
// swagger:model DeprecatedAssetListAO0Links
type DeprecatedAssetListAO0Links struct {

	// self
	Self *DeprecatedAssetListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this deprecated asset list a o0 links
func (m *DeprecatedAssetListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeprecatedAssetListAO0Links) validateSelf(formats strfmt.Registry) error {

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
func (m *DeprecatedAssetListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListAO0Links) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListAO0LinksSelf deprecated asset list a o0 links self
//
// swagger:model DeprecatedAssetListAO0LinksSelf
type DeprecatedAssetListAO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this deprecated asset list a o0 links self
func (m *DeprecatedAssetListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListReferenceFilesItems0 deprecated asset list reference files items0
//
// swagger:model DeprecatedAssetListReferenceFilesItems0
type DeprecatedAssetListReferenceFilesItems0 struct {

	// link
	Link *DeprecatedAssetListReferenceFilesItems0Link `json:"_link,omitempty"`

	// Code of the reference file
	Code string `json:"code,omitempty"`

	// Locale code of the reference file
	Locale string `json:"locale,omitempty"`
}

// Validate validates this deprecated asset list reference files items0
func (m *DeprecatedAssetListReferenceFilesItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLink(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeprecatedAssetListReferenceFilesItems0) validateLink(formats strfmt.Registry) error {

	if swag.IsZero(m.Link) { // not required
		return nil
	}

	if m.Link != nil {
		if err := m.Link.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListReferenceFilesItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListReferenceFilesItems0Link Links to get and download the reference file
//
// swagger:model DeprecatedAssetListReferenceFilesItems0Link
type DeprecatedAssetListReferenceFilesItems0Link struct {

	// download
	Download *DeprecatedAssetListReferenceFilesItems0LinkDownload `json:"download,omitempty"`

	// self
	Self *DeprecatedAssetListReferenceFilesItems0LinkSelf `json:"self,omitempty"`
}

// Validate validates this deprecated asset list reference files items0 link
func (m *DeprecatedAssetListReferenceFilesItems0Link) Validate(formats strfmt.Registry) error {
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

func (m *DeprecatedAssetListReferenceFilesItems0Link) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(m.Download) { // not required
		return nil
	}

	if m.Download != nil {
		if err := m.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (m *DeprecatedAssetListReferenceFilesItems0Link) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(m.Self) { // not required
		return nil
	}

	if m.Self != nil {
		if err := m.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0Link) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0Link) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListReferenceFilesItems0Link
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListReferenceFilesItems0LinkDownload deprecated asset list reference files items0 link download
//
// swagger:model DeprecatedAssetListReferenceFilesItems0LinkDownload
type DeprecatedAssetListReferenceFilesItems0LinkDownload struct {

	// URI to download the reference file
	Href string `json:"href,omitempty"`
}

// Validate validates this deprecated asset list reference files items0 link download
func (m *DeprecatedAssetListReferenceFilesItems0LinkDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0LinkDownload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0LinkDownload) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListReferenceFilesItems0LinkDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListReferenceFilesItems0LinkSelf deprecated asset list reference files items0 link self
//
// swagger:model DeprecatedAssetListReferenceFilesItems0LinkSelf
type DeprecatedAssetListReferenceFilesItems0LinkSelf struct {

	// URI of the reference file entity
	Href string `json:"href,omitempty"`
}

// Validate validates this deprecated asset list reference files items0 link self
func (m *DeprecatedAssetListReferenceFilesItems0LinkSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0LinkSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListReferenceFilesItems0LinkSelf) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListReferenceFilesItems0LinkSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListVariationFilesItems0 deprecated asset list variation files items0
//
// swagger:model DeprecatedAssetListVariationFilesItems0
type DeprecatedAssetListVariationFilesItems0 struct {

	// link
	Link *DeprecatedAssetListVariationFilesItems0Link `json:"_link,omitempty"`

	// Code of the variation
	Code string `json:"code,omitempty"`

	// Locale code of the variation
	Locale string `json:"locale,omitempty"`

	// Channel code of the variation
	Scope string `json:"scope,omitempty"`
}

// Validate validates this deprecated asset list variation files items0
func (m *DeprecatedAssetListVariationFilesItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLink(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeprecatedAssetListVariationFilesItems0) validateLink(formats strfmt.Registry) error {

	if swag.IsZero(m.Link) { // not required
		return nil
	}

	if m.Link != nil {
		if err := m.Link.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListVariationFilesItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListVariationFilesItems0Link Links to get and download the variation file
//
// swagger:model DeprecatedAssetListVariationFilesItems0Link
type DeprecatedAssetListVariationFilesItems0Link struct {

	// download
	Download *DeprecatedAssetListVariationFilesItems0LinkDownload `json:"download,omitempty"`

	// self
	Self *DeprecatedAssetListVariationFilesItems0LinkSelf `json:"self,omitempty"`
}

// Validate validates this deprecated asset list variation files items0 link
func (m *DeprecatedAssetListVariationFilesItems0Link) Validate(formats strfmt.Registry) error {
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

func (m *DeprecatedAssetListVariationFilesItems0Link) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(m.Download) { // not required
		return nil
	}

	if m.Download != nil {
		if err := m.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (m *DeprecatedAssetListVariationFilesItems0Link) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(m.Self) { // not required
		return nil
	}

	if m.Self != nil {
		if err := m.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0Link) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0Link) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListVariationFilesItems0Link
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListVariationFilesItems0LinkDownload deprecated asset list variation files items0 link download
//
// swagger:model DeprecatedAssetListVariationFilesItems0LinkDownload
type DeprecatedAssetListVariationFilesItems0LinkDownload struct {

	// URI to download the variation file
	Href string `json:"href,omitempty"`
}

// Validate validates this deprecated asset list variation files items0 link download
func (m *DeprecatedAssetListVariationFilesItems0LinkDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0LinkDownload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0LinkDownload) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListVariationFilesItems0LinkDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DeprecatedAssetListVariationFilesItems0LinkSelf deprecated asset list variation files items0 link self
//
// swagger:model DeprecatedAssetListVariationFilesItems0LinkSelf
type DeprecatedAssetListVariationFilesItems0LinkSelf struct {

	// URI of the variation entity
	Href string `json:"href,omitempty"`
}

// Validate validates this deprecated asset list variation files items0 link self
func (m *DeprecatedAssetListVariationFilesItems0LinkSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0LinkSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeprecatedAssetListVariationFilesItems0LinkSelf) UnmarshalBinary(b []byte) error {
	var res DeprecatedAssetListVariationFilesItems0LinkSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}