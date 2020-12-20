// Code generated by go-swagger; DO NOT EDIT.

package attribute

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PostAttributesReader is a Reader for the PostAttributes structure.
type PostAttributesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAttributesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAttributesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAttributesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAttributesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostAttributesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPostAttributesUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPostAttributesUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostAttributesCreated creates a PostAttributesCreated with default headers values
func NewPostAttributesCreated() *PostAttributesCreated {
	return &PostAttributesCreated{}
}

/*PostAttributesCreated handles this case with default header values.

Created
*/
type PostAttributesCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PostAttributesCreated) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/attributes][%d] postAttributesCreated ", 201)
}

func (o *PostAttributesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPostAttributesBadRequest creates a PostAttributesBadRequest with default headers values
func NewPostAttributesBadRequest() *PostAttributesBadRequest {
	return &PostAttributesBadRequest{}
}

/*PostAttributesBadRequest handles this case with default header values.

Bad request
*/
type PostAttributesBadRequest struct {
	Payload *PostAttributesBadRequestBody
}

func (o *PostAttributesBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/attributes][%d] postAttributesBadRequest  %+v", 400, o.Payload)
}

func (o *PostAttributesBadRequest) GetPayload() *PostAttributesBadRequestBody {
	return o.Payload
}

func (o *PostAttributesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAttributesBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAttributesUnauthorized creates a PostAttributesUnauthorized with default headers values
func NewPostAttributesUnauthorized() *PostAttributesUnauthorized {
	return &PostAttributesUnauthorized{}
}

/*PostAttributesUnauthorized handles this case with default header values.

Authentication required
*/
type PostAttributesUnauthorized struct {
	Payload *PostAttributesUnauthorizedBody
}

func (o *PostAttributesUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/attributes][%d] postAttributesUnauthorized  %+v", 401, o.Payload)
}

func (o *PostAttributesUnauthorized) GetPayload() *PostAttributesUnauthorizedBody {
	return o.Payload
}

func (o *PostAttributesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAttributesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAttributesForbidden creates a PostAttributesForbidden with default headers values
func NewPostAttributesForbidden() *PostAttributesForbidden {
	return &PostAttributesForbidden{}
}

/*PostAttributesForbidden handles this case with default header values.

Access forbidden
*/
type PostAttributesForbidden struct {
	Payload *PostAttributesForbiddenBody
}

func (o *PostAttributesForbidden) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/attributes][%d] postAttributesForbidden  %+v", 403, o.Payload)
}

func (o *PostAttributesForbidden) GetPayload() *PostAttributesForbiddenBody {
	return o.Payload
}

func (o *PostAttributesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAttributesForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAttributesUnsupportedMediaType creates a PostAttributesUnsupportedMediaType with default headers values
func NewPostAttributesUnsupportedMediaType() *PostAttributesUnsupportedMediaType {
	return &PostAttributesUnsupportedMediaType{}
}

/*PostAttributesUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PostAttributesUnsupportedMediaType struct {
	Payload *PostAttributesUnsupportedMediaTypeBody
}

func (o *PostAttributesUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/attributes][%d] postAttributesUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PostAttributesUnsupportedMediaType) GetPayload() *PostAttributesUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PostAttributesUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAttributesUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAttributesUnprocessableEntity creates a PostAttributesUnprocessableEntity with default headers values
func NewPostAttributesUnprocessableEntity() *PostAttributesUnprocessableEntity {
	return &PostAttributesUnprocessableEntity{}
}

/*PostAttributesUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PostAttributesUnprocessableEntity struct {
	Payload *PostAttributesUnprocessableEntityBody
}

func (o *PostAttributesUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/attributes][%d] postAttributesUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PostAttributesUnprocessableEntity) GetPayload() *PostAttributesUnprocessableEntityBody {
	return o.Payload
}

func (o *PostAttributesUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAttributesUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PostAttributesBadRequestBody post attributes bad request body
swagger:model PostAttributesBadRequestBody
*/
type PostAttributesBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post attributes bad request body
func (o *PostAttributesBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PostAttributesBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesBody post attributes body
swagger:model PostAttributesBody
*/
type PostAttributesBody struct {

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
	GroupLabels *PostAttributesParamsBodyGroupLabels `json:"group_labels,omitempty"`

	// labels
	Labels *PostAttributesParamsBodyLabels `json:"labels,omitempty"`

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

// Validate validates this post attributes body
func (o *PostAttributesBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateDateMax(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateDateMin(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateGroupLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostAttributesBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PostAttributesBody) validateDateMax(formats strfmt.Registry) error {

	if swag.IsZero(o.DateMax) { // not required
		return nil
	}

	if err := validate.FormatOf("body"+"."+"date_max", "body", "date-time", o.DateMax.String(), formats); err != nil {
		return err
	}

	return nil
}

func (o *PostAttributesBody) validateDateMin(formats strfmt.Registry) error {

	if swag.IsZero(o.DateMin) { // not required
		return nil
	}

	if err := validate.FormatOf("body"+"."+"date_min", "body", "date-time", o.DateMin.String(), formats); err != nil {
		return err
	}

	return nil
}

func (o *PostAttributesBody) validateGroup(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"group", "body", o.Group); err != nil {
		return err
	}

	return nil
}

func (o *PostAttributesBody) validateGroupLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.GroupLabels) { // not required
		return nil
	}

	if o.GroupLabels != nil {
		if err := o.GroupLabels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "group_labels")
			}
			return err
		}
	}

	return nil
}

func (o *PostAttributesBody) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "labels")
			}
			return err
		}
	}

	return nil
}

var postAttributesBodyTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["pim_catalog_identifier","pim_catalog_metric","pim_catalog_number","pim_catalog_reference_data_multi_select","pim_catalog_reference_data_simple_select","pim_catalog_simpleselect","pim_catalog_multiselect","pim_catalog_date","pim_catalog_textarea","pim_catalog_text","pim_catalog_file","pim_catalog_image","pim_catalog_price_collection","pim_catalog_boolean","akeneo_reference_entity","akeneo_reference_entity_collection","pim_catalog_asset_collection"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		postAttributesBodyTypeTypePropEnum = append(postAttributesBodyTypeTypePropEnum, v)
	}
}

const (

	// PostAttributesBodyTypePimCatalogIdentifier captures enum value "pim_catalog_identifier"
	PostAttributesBodyTypePimCatalogIdentifier string = "pim_catalog_identifier"

	// PostAttributesBodyTypePimCatalogMetric captures enum value "pim_catalog_metric"
	PostAttributesBodyTypePimCatalogMetric string = "pim_catalog_metric"

	// PostAttributesBodyTypePimCatalogNumber captures enum value "pim_catalog_number"
	PostAttributesBodyTypePimCatalogNumber string = "pim_catalog_number"

	// PostAttributesBodyTypePimCatalogReferenceDataMultiSelect captures enum value "pim_catalog_reference_data_multi_select"
	PostAttributesBodyTypePimCatalogReferenceDataMultiSelect string = "pim_catalog_reference_data_multi_select"

	// PostAttributesBodyTypePimCatalogReferenceDataSimpleSelect captures enum value "pim_catalog_reference_data_simple_select"
	PostAttributesBodyTypePimCatalogReferenceDataSimpleSelect string = "pim_catalog_reference_data_simple_select"

	// PostAttributesBodyTypePimCatalogSimpleselect captures enum value "pim_catalog_simpleselect"
	PostAttributesBodyTypePimCatalogSimpleselect string = "pim_catalog_simpleselect"

	// PostAttributesBodyTypePimCatalogMultiselect captures enum value "pim_catalog_multiselect"
	PostAttributesBodyTypePimCatalogMultiselect string = "pim_catalog_multiselect"

	// PostAttributesBodyTypePimCatalogDate captures enum value "pim_catalog_date"
	PostAttributesBodyTypePimCatalogDate string = "pim_catalog_date"

	// PostAttributesBodyTypePimCatalogTextarea captures enum value "pim_catalog_textarea"
	PostAttributesBodyTypePimCatalogTextarea string = "pim_catalog_textarea"

	// PostAttributesBodyTypePimCatalogText captures enum value "pim_catalog_text"
	PostAttributesBodyTypePimCatalogText string = "pim_catalog_text"

	// PostAttributesBodyTypePimCatalogFile captures enum value "pim_catalog_file"
	PostAttributesBodyTypePimCatalogFile string = "pim_catalog_file"

	// PostAttributesBodyTypePimCatalogImage captures enum value "pim_catalog_image"
	PostAttributesBodyTypePimCatalogImage string = "pim_catalog_image"

	// PostAttributesBodyTypePimCatalogPriceCollection captures enum value "pim_catalog_price_collection"
	PostAttributesBodyTypePimCatalogPriceCollection string = "pim_catalog_price_collection"

	// PostAttributesBodyTypePimCatalogBoolean captures enum value "pim_catalog_boolean"
	PostAttributesBodyTypePimCatalogBoolean string = "pim_catalog_boolean"

	// PostAttributesBodyTypeAkeneoReferenceEntity captures enum value "akeneo_reference_entity"
	PostAttributesBodyTypeAkeneoReferenceEntity string = "akeneo_reference_entity"

	// PostAttributesBodyTypeAkeneoReferenceEntityCollection captures enum value "akeneo_reference_entity_collection"
	PostAttributesBodyTypeAkeneoReferenceEntityCollection string = "akeneo_reference_entity_collection"

	// PostAttributesBodyTypePimCatalogAssetCollection captures enum value "pim_catalog_asset_collection"
	PostAttributesBodyTypePimCatalogAssetCollection string = "pim_catalog_asset_collection"
)

// prop value enum
func (o *PostAttributesBody) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, postAttributesBodyTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PostAttributesBody) validateType(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"type", "body", o.Type); err != nil {
		return err
	}

	// value enum
	if err := o.validateTypeEnum("body"+"."+"type", "body", *o.Type); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesBody) UnmarshalBinary(b []byte) error {
	var res PostAttributesBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesForbiddenBody post attributes forbidden body
swagger:model PostAttributesForbiddenBody
*/
type PostAttributesForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post attributes forbidden body
func (o *PostAttributesForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PostAttributesForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesParamsBodyGroupLabels Group labels for each locale
swagger:model PostAttributesParamsBodyGroupLabels
*/
type PostAttributesParamsBodyGroupLabels struct {

	// Group label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this post attributes params body group labels
func (o *PostAttributesParamsBodyGroupLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesParamsBodyGroupLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesParamsBodyGroupLabels) UnmarshalBinary(b []byte) error {
	var res PostAttributesParamsBodyGroupLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesParamsBodyLabels Attribute labels for each locale
swagger:model PostAttributesParamsBodyLabels
*/
type PostAttributesParamsBodyLabels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this post attributes params body labels
func (o *PostAttributesParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PostAttributesParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesUnauthorizedBody post attributes unauthorized body
swagger:model PostAttributesUnauthorizedBody
*/
type PostAttributesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post attributes unauthorized body
func (o *PostAttributesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PostAttributesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesUnprocessableEntityBody post attributes unprocessable entity body
swagger:model PostAttributesUnprocessableEntityBody
*/
type PostAttributesUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post attributes unprocessable entity body
func (o *PostAttributesUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PostAttributesUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAttributesUnsupportedMediaTypeBody post attributes unsupported media type body
swagger:model PostAttributesUnsupportedMediaTypeBody
*/
type PostAttributesUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post attributes unsupported media type body
func (o *PostAttributesUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAttributesUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAttributesUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PostAttributesUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
