// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AttributeList attribute list
//
// swagger:model AttributeList
type AttributeList struct {

	// links
	Links *AttributeListAO0Links `json:"_links,omitempty"`

	// Extensions allowed when the attribute type is `pim_catalog_file` or `pim_catalog_image`
	AllowedExtensions []string `json:"allowed_extensions"`

	// To make the attribute locale specfic, specify here for which locales it is specific
	AvailableLocales []string `json:"available_locales"`

	// Attribute code
	// Required: true
	Code *string `json:"code"`

	// Maximum date allowed when the attribute type is `pim_catalog_date`
	// Format: date-time
	DateMax strfmt.DateTime `json:"date_max,omitempty"`

	// Minimum date allowed when the attribute type is `pim_catalog_date`
	// Format: date-time
	DateMin strfmt.DateTime `json:"date_min,omitempty"`

	// Whether decimals are allowed when the attribute type is `pim_catalog_metric`, `pim_catalog_price` or `pim_catalog_number`
	DecimalsAllowed bool `json:"decimals_allowed,omitempty"`

	// Default metric unit when the attribute type is `pim_catalog_metric`
	DefaultMetricUnit string `json:"default_metric_unit,omitempty"`

	// Attribute group
	// Required: true
	Group *string `json:"group"`

	// group labels
	GroupLabels *AttributeListAO1GroupLabels `json:"group_labels,omitempty"`

	// labels
	Labels *AttributeListAO1Labels `json:"labels,omitempty"`

	// Whether the attribute is localizable, i.e. can have one value by locale
	Localizable *bool `json:"localizable,omitempty"`

	// Number maximum of characters allowed for the value of the attribute when the attribute type is `pim_catalog_text`, `pim_catalog_textarea` or `pim_catalog_identifier`
	MaxCharacters int64 `json:"max_characters,omitempty"`

	// Max file size in MB when the attribute type is `pim_catalog_file` or `pim_catalog_image`
	MaxFileSize string `json:"max_file_size,omitempty"`

	// Metric family when the attribute type is `pim_catalog_metric`
	MetricFamily string `json:"metric_family,omitempty"`

	// Whether negative values are allowed when the attribute type is `pim_catalog_metric` or `pim_catalog_number`
	NegativeAllowed bool `json:"negative_allowed,omitempty"`

	// Maximum integer value allowed when the attribute type is `pim_catalog_metric`, `pim_catalog_price` or `pim_catalog_number`
	NumberMax string `json:"number_max,omitempty"`

	// Minimum integer value allowed when the attribute type is `pim_catalog_metric`, `pim_catalog_price` or `pim_catalog_number`
	NumberMin string `json:"number_min,omitempty"`

	// Reference entity code when the attribute type is `akeneo_reference_entity` or `akeneo_reference_entity_collection` OR Asset family code when the attribute type is `pim_catalog_asset_collection`
	ReferenceDataName string `json:"reference_data_name,omitempty"`

	// Whether the attribute is scopable, i.e. can have one value by channel
	Scopable *bool `json:"scopable,omitempty"`

	// Order of the attribute in its group
	SortOrder int64 `json:"sort_order,omitempty"`

	// Attribute type
	// Required: true
	// Enum: [pim_catalog_identifier pim_catalog_metric pim_catalog_number pim_catalog_reference_data_multi_select pim_catalog_reference_data_simple_select pim_catalog_simpleselect pim_catalog_multiselect pim_catalog_date pim_catalog_textarea pim_catalog_text pim_catalog_file pim_catalog_image pim_catalog_price_collection pim_catalog_boolean akeneo_reference_entity akeneo_reference_entity_collection pim_catalog_asset_collection]
	Type *string `json:"type"`

	// Whether two values for the attribute cannot be the same
	Unique bool `json:"unique,omitempty"`

	// Whether the attribute can be used as a filter for the product grid in the PIM user interface
	UseableAsGridFilter bool `json:"useable_as_grid_filter,omitempty"`

	// Regexp expression used to validate any attribute value when the attribute type is `pim_catalog_text` or `pim_catalog_identifier`
	ValidationRegexp string `json:"validation_regexp,omitempty"`

	// Validation rule type used to validate any attribute value when the attribute type is `pim_catalog_text` or `pim_catalog_identifier`
	ValidationRule string `json:"validation_rule,omitempty"`

	// Whether the WYSIWYG interface is shown when the attribute type is `pim_catalog_textarea`
	WysiwygEnabled bool `json:"wysiwyg_enabled,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *AttributeList) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *AttributeListAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	m.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		AllowedExtensions []string `json:"allowed_extensions"`

		AvailableLocales []string `json:"available_locales"`

		Code *string `json:"code"`

		DateMax strfmt.DateTime `json:"date_max,omitempty"`

		DateMin strfmt.DateTime `json:"date_min,omitempty"`

		DecimalsAllowed bool `json:"decimals_allowed,omitempty"`

		DefaultMetricUnit string `json:"default_metric_unit,omitempty"`

		Group *string `json:"group"`

		GroupLabels *AttributeListAO1GroupLabels `json:"group_labels,omitempty"`

		Labels *AttributeListAO1Labels `json:"labels,omitempty"`

		Localizable *bool `json:"localizable,omitempty"`

		MaxCharacters int64 `json:"max_characters,omitempty"`

		MaxFileSize string `json:"max_file_size,omitempty"`

		MetricFamily string `json:"metric_family,omitempty"`

		NegativeAllowed bool `json:"negative_allowed,omitempty"`

		NumberMax string `json:"number_max,omitempty"`

		NumberMin string `json:"number_min,omitempty"`

		ReferenceDataName string `json:"reference_data_name,omitempty"`

		Scopable *bool `json:"scopable,omitempty"`

		SortOrder int64 `json:"sort_order,omitempty"`

		Type *string `json:"type"`

		Unique bool `json:"unique,omitempty"`

		UseableAsGridFilter bool `json:"useable_as_grid_filter,omitempty"`

		ValidationRegexp string `json:"validation_regexp,omitempty"`

		ValidationRule string `json:"validation_rule,omitempty"`

		WysiwygEnabled bool `json:"wysiwyg_enabled,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.AllowedExtensions = dataAO1.AllowedExtensions

	m.AvailableLocales = dataAO1.AvailableLocales

	m.Code = dataAO1.Code

	m.DateMax = dataAO1.DateMax

	m.DateMin = dataAO1.DateMin

	m.DecimalsAllowed = dataAO1.DecimalsAllowed

	m.DefaultMetricUnit = dataAO1.DefaultMetricUnit

	m.Group = dataAO1.Group

	m.GroupLabels = dataAO1.GroupLabels

	m.Labels = dataAO1.Labels

	m.Localizable = dataAO1.Localizable

	m.MaxCharacters = dataAO1.MaxCharacters

	m.MaxFileSize = dataAO1.MaxFileSize

	m.MetricFamily = dataAO1.MetricFamily

	m.NegativeAllowed = dataAO1.NegativeAllowed

	m.NumberMax = dataAO1.NumberMax

	m.NumberMin = dataAO1.NumberMin

	m.ReferenceDataName = dataAO1.ReferenceDataName

	m.Scopable = dataAO1.Scopable

	m.SortOrder = dataAO1.SortOrder

	m.Type = dataAO1.Type

	m.Unique = dataAO1.Unique

	m.UseableAsGridFilter = dataAO1.UseableAsGridFilter

	m.ValidationRegexp = dataAO1.ValidationRegexp

	m.ValidationRule = dataAO1.ValidationRule

	m.WysiwygEnabled = dataAO1.WysiwygEnabled

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m AttributeList) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *AttributeListAO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = m.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		AllowedExtensions []string `json:"allowed_extensions"`

		AvailableLocales []string `json:"available_locales"`

		Code *string `json:"code"`

		DateMax strfmt.DateTime `json:"date_max,omitempty"`

		DateMin strfmt.DateTime `json:"date_min,omitempty"`

		DecimalsAllowed bool `json:"decimals_allowed,omitempty"`

		DefaultMetricUnit string `json:"default_metric_unit,omitempty"`

		Group *string `json:"group"`

		GroupLabels *AttributeListAO1GroupLabels `json:"group_labels,omitempty"`

		Labels *AttributeListAO1Labels `json:"labels,omitempty"`

		Localizable *bool `json:"localizable,omitempty"`

		MaxCharacters int64 `json:"max_characters,omitempty"`

		MaxFileSize string `json:"max_file_size,omitempty"`

		MetricFamily string `json:"metric_family,omitempty"`

		NegativeAllowed bool `json:"negative_allowed,omitempty"`

		NumberMax string `json:"number_max,omitempty"`

		NumberMin string `json:"number_min,omitempty"`

		ReferenceDataName string `json:"reference_data_name,omitempty"`

		Scopable *bool `json:"scopable,omitempty"`

		SortOrder int64 `json:"sort_order,omitempty"`

		Type *string `json:"type"`

		Unique bool `json:"unique,omitempty"`

		UseableAsGridFilter bool `json:"useable_as_grid_filter,omitempty"`

		ValidationRegexp string `json:"validation_regexp,omitempty"`

		ValidationRule string `json:"validation_rule,omitempty"`

		WysiwygEnabled bool `json:"wysiwyg_enabled,omitempty"`
	}

	dataAO1.AllowedExtensions = m.AllowedExtensions

	dataAO1.AvailableLocales = m.AvailableLocales

	dataAO1.Code = m.Code

	dataAO1.DateMax = m.DateMax

	dataAO1.DateMin = m.DateMin

	dataAO1.DecimalsAllowed = m.DecimalsAllowed

	dataAO1.DefaultMetricUnit = m.DefaultMetricUnit

	dataAO1.Group = m.Group

	dataAO1.GroupLabels = m.GroupLabels

	dataAO1.Labels = m.Labels

	dataAO1.Localizable = m.Localizable

	dataAO1.MaxCharacters = m.MaxCharacters

	dataAO1.MaxFileSize = m.MaxFileSize

	dataAO1.MetricFamily = m.MetricFamily

	dataAO1.NegativeAllowed = m.NegativeAllowed

	dataAO1.NumberMax = m.NumberMax

	dataAO1.NumberMin = m.NumberMin

	dataAO1.ReferenceDataName = m.ReferenceDataName

	dataAO1.Scopable = m.Scopable

	dataAO1.SortOrder = m.SortOrder

	dataAO1.Type = m.Type

	dataAO1.Unique = m.Unique

	dataAO1.UseableAsGridFilter = m.UseableAsGridFilter

	dataAO1.ValidationRegexp = m.ValidationRegexp

	dataAO1.ValidationRule = m.ValidationRule

	dataAO1.WysiwygEnabled = m.WysiwygEnabled

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this attribute list
func (m *AttributeList) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDateMax(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDateMin(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGroupLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AttributeList) validateLinks(formats strfmt.Registry) error {

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

func (m *AttributeList) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *AttributeList) validateDateMax(formats strfmt.Registry) error {

	if swag.IsZero(m.DateMax) { // not required
		return nil
	}

	if err := validate.FormatOf("date_max", "body", "date-time", m.DateMax.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AttributeList) validateDateMin(formats strfmt.Registry) error {

	if swag.IsZero(m.DateMin) { // not required
		return nil
	}

	if err := validate.FormatOf("date_min", "body", "date-time", m.DateMin.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AttributeList) validateGroup(formats strfmt.Registry) error {

	if err := validate.Required("group", "body", m.Group); err != nil {
		return err
	}

	return nil
}

func (m *AttributeList) validateGroupLabels(formats strfmt.Registry) error {

	if swag.IsZero(m.GroupLabels) { // not required
		return nil
	}

	if m.GroupLabels != nil {
		if err := m.GroupLabels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("group_labels")
			}
			return err
		}
	}

	return nil
}

func (m *AttributeList) validateLabels(formats strfmt.Registry) error {

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

var attributeListTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["pim_catalog_identifier","pim_catalog_metric","pim_catalog_number","pim_catalog_reference_data_multi_select","pim_catalog_reference_data_simple_select","pim_catalog_simpleselect","pim_catalog_multiselect","pim_catalog_date","pim_catalog_textarea","pim_catalog_text","pim_catalog_file","pim_catalog_image","pim_catalog_price_collection","pim_catalog_boolean","akeneo_reference_entity","akeneo_reference_entity_collection","pim_catalog_asset_collection"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		attributeListTypeTypePropEnum = append(attributeListTypeTypePropEnum, v)
	}
}

// property enum
func (m *AttributeList) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, attributeListTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AttributeList) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", *m.Type); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AttributeList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeList) UnmarshalBinary(b []byte) error {
	var res AttributeList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AttributeListAO0Links attribute list a o0 links
//
// swagger:model AttributeListAO0Links
type AttributeListAO0Links struct {

	// self
	Self *AttributeListAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this attribute list a o0 links
func (m *AttributeListAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AttributeListAO0Links) validateSelf(formats strfmt.Registry) error {

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
func (m *AttributeListAO0Links) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeListAO0Links) UnmarshalBinary(b []byte) error {
	var res AttributeListAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AttributeListAO0LinksSelf attribute list a o0 links self
//
// swagger:model AttributeListAO0LinksSelf
type AttributeListAO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this attribute list a o0 links self
func (m *AttributeListAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AttributeListAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeListAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res AttributeListAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AttributeListAO1GroupLabels Group labels for each locale
//
// swagger:model AttributeListAO1GroupLabels
type AttributeListAO1GroupLabels struct {

	// Group label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this attribute list a o1 group labels
func (m *AttributeListAO1GroupLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AttributeListAO1GroupLabels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeListAO1GroupLabels) UnmarshalBinary(b []byte) error {
	var res AttributeListAO1GroupLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// AttributeListAO1Labels Attribute labels for each locale
//
// swagger:model AttributeListAO1Labels
type AttributeListAO1Labels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this attribute list a o1 labels
func (m *AttributeListAO1Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AttributeListAO1Labels) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeListAO1Labels) UnmarshalBinary(b []byte) error {
	var res AttributeListAO1Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
