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

// PatchAttributesCodeReader is a Reader for the PatchAttributesCode structure.
type PatchAttributesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchAttributesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchAttributesCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewPatchAttributesCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchAttributesCodeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchAttributesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchAttributesCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchAttributesCodeUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchAttributesCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchAttributesCodeCreated creates a PatchAttributesCodeCreated with default headers values
func NewPatchAttributesCodeCreated() *PatchAttributesCodeCreated {
	return &PatchAttributesCodeCreated{}
}

/*PatchAttributesCodeCreated handles this case with default header values.

Created
*/
type PatchAttributesCodeCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PatchAttributesCodeCreated) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeCreated ", 201)
}

func (o *PatchAttributesCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchAttributesCodeNoContent creates a PatchAttributesCodeNoContent with default headers values
func NewPatchAttributesCodeNoContent() *PatchAttributesCodeNoContent {
	return &PatchAttributesCodeNoContent{}
}

/*PatchAttributesCodeNoContent handles this case with default header values.

No content to return
*/
type PatchAttributesCodeNoContent struct {
	/*URI of the updated resource
	 */
	Location string
}

func (o *PatchAttributesCodeNoContent) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeNoContent ", 204)
}

func (o *PatchAttributesCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchAttributesCodeBadRequest creates a PatchAttributesCodeBadRequest with default headers values
func NewPatchAttributesCodeBadRequest() *PatchAttributesCodeBadRequest {
	return &PatchAttributesCodeBadRequest{}
}

/*PatchAttributesCodeBadRequest handles this case with default header values.

Bad request
*/
type PatchAttributesCodeBadRequest struct {
	Payload *PatchAttributesCodeBadRequestBody
}

func (o *PatchAttributesCodeBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeBadRequest  %+v", 400, o.Payload)
}

func (o *PatchAttributesCodeBadRequest) GetPayload() *PatchAttributesCodeBadRequestBody {
	return o.Payload
}

func (o *PatchAttributesCodeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchAttributesCodeBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAttributesCodeUnauthorized creates a PatchAttributesCodeUnauthorized with default headers values
func NewPatchAttributesCodeUnauthorized() *PatchAttributesCodeUnauthorized {
	return &PatchAttributesCodeUnauthorized{}
}

/*PatchAttributesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type PatchAttributesCodeUnauthorized struct {
	Payload *PatchAttributesCodeUnauthorizedBody
}

func (o *PatchAttributesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchAttributesCodeUnauthorized) GetPayload() *PatchAttributesCodeUnauthorizedBody {
	return o.Payload
}

func (o *PatchAttributesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchAttributesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAttributesCodeForbidden creates a PatchAttributesCodeForbidden with default headers values
func NewPatchAttributesCodeForbidden() *PatchAttributesCodeForbidden {
	return &PatchAttributesCodeForbidden{}
}

/*PatchAttributesCodeForbidden handles this case with default header values.

Access forbidden
*/
type PatchAttributesCodeForbidden struct {
	Payload *PatchAttributesCodeForbiddenBody
}

func (o *PatchAttributesCodeForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeForbidden  %+v", 403, o.Payload)
}

func (o *PatchAttributesCodeForbidden) GetPayload() *PatchAttributesCodeForbiddenBody {
	return o.Payload
}

func (o *PatchAttributesCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchAttributesCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAttributesCodeUnsupportedMediaType creates a PatchAttributesCodeUnsupportedMediaType with default headers values
func NewPatchAttributesCodeUnsupportedMediaType() *PatchAttributesCodeUnsupportedMediaType {
	return &PatchAttributesCodeUnsupportedMediaType{}
}

/*PatchAttributesCodeUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchAttributesCodeUnsupportedMediaType struct {
	Payload *PatchAttributesCodeUnsupportedMediaTypeBody
}

func (o *PatchAttributesCodeUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchAttributesCodeUnsupportedMediaType) GetPayload() *PatchAttributesCodeUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchAttributesCodeUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchAttributesCodeUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAttributesCodeUnprocessableEntity creates a PatchAttributesCodeUnprocessableEntity with default headers values
func NewPatchAttributesCodeUnprocessableEntity() *PatchAttributesCodeUnprocessableEntity {
	return &PatchAttributesCodeUnprocessableEntity{}
}

/*PatchAttributesCodeUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PatchAttributesCodeUnprocessableEntity struct {
	Payload *PatchAttributesCodeUnprocessableEntityBody
}

func (o *PatchAttributesCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/attributes/{code}][%d] patchAttributesCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchAttributesCodeUnprocessableEntity) GetPayload() *PatchAttributesCodeUnprocessableEntityBody {
	return o.Payload
}

func (o *PatchAttributesCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchAttributesCodeUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchAttributesCodeBadRequestBody patch attributes code bad request body
swagger:model PatchAttributesCodeBadRequestBody
*/
type PatchAttributesCodeBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch attributes code bad request body
func (o *PatchAttributesCodeBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeBody patch attributes code body
swagger:model PatchAttributesCodeBody
*/
type PatchAttributesCodeBody struct {

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
	GroupLabels *PatchAttributesCodeParamsBodyGroupLabels `json:"group_labels,omitempty"`

	// labels
	Labels *PatchAttributesCodeParamsBodyLabels `json:"labels,omitempty"`

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

// Validate validates this patch attributes code body
func (o *PatchAttributesCodeBody) Validate(formats strfmt.Registry) error {
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

func (o *PatchAttributesCodeBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PatchAttributesCodeBody) validateDateMax(formats strfmt.Registry) error {

	if swag.IsZero(o.DateMax) { // not required
		return nil
	}

	if err := validate.FormatOf("body"+"."+"date_max", "body", "date-time", o.DateMax.String(), formats); err != nil {
		return err
	}

	return nil
}

func (o *PatchAttributesCodeBody) validateDateMin(formats strfmt.Registry) error {

	if swag.IsZero(o.DateMin) { // not required
		return nil
	}

	if err := validate.FormatOf("body"+"."+"date_min", "body", "date-time", o.DateMin.String(), formats); err != nil {
		return err
	}

	return nil
}

func (o *PatchAttributesCodeBody) validateGroup(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"group", "body", o.Group); err != nil {
		return err
	}

	return nil
}

func (o *PatchAttributesCodeBody) validateGroupLabels(formats strfmt.Registry) error {

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

func (o *PatchAttributesCodeBody) validateLabels(formats strfmt.Registry) error {

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

var patchAttributesCodeBodyTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["pim_catalog_identifier","pim_catalog_metric","pim_catalog_number","pim_catalog_reference_data_multi_select","pim_catalog_reference_data_simple_select","pim_catalog_simpleselect","pim_catalog_multiselect","pim_catalog_date","pim_catalog_textarea","pim_catalog_text","pim_catalog_file","pim_catalog_image","pim_catalog_price_collection","pim_catalog_boolean","akeneo_reference_entity","akeneo_reference_entity_collection","pim_catalog_asset_collection"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		patchAttributesCodeBodyTypeTypePropEnum = append(patchAttributesCodeBodyTypeTypePropEnum, v)
	}
}

const (

	// PatchAttributesCodeBodyTypePimCatalogIdentifier captures enum value "pim_catalog_identifier"
	PatchAttributesCodeBodyTypePimCatalogIdentifier string = "pim_catalog_identifier"

	// PatchAttributesCodeBodyTypePimCatalogMetric captures enum value "pim_catalog_metric"
	PatchAttributesCodeBodyTypePimCatalogMetric string = "pim_catalog_metric"

	// PatchAttributesCodeBodyTypePimCatalogNumber captures enum value "pim_catalog_number"
	PatchAttributesCodeBodyTypePimCatalogNumber string = "pim_catalog_number"

	// PatchAttributesCodeBodyTypePimCatalogReferenceDataMultiSelect captures enum value "pim_catalog_reference_data_multi_select"
	PatchAttributesCodeBodyTypePimCatalogReferenceDataMultiSelect string = "pim_catalog_reference_data_multi_select"

	// PatchAttributesCodeBodyTypePimCatalogReferenceDataSimpleSelect captures enum value "pim_catalog_reference_data_simple_select"
	PatchAttributesCodeBodyTypePimCatalogReferenceDataSimpleSelect string = "pim_catalog_reference_data_simple_select"

	// PatchAttributesCodeBodyTypePimCatalogSimpleselect captures enum value "pim_catalog_simpleselect"
	PatchAttributesCodeBodyTypePimCatalogSimpleselect string = "pim_catalog_simpleselect"

	// PatchAttributesCodeBodyTypePimCatalogMultiselect captures enum value "pim_catalog_multiselect"
	PatchAttributesCodeBodyTypePimCatalogMultiselect string = "pim_catalog_multiselect"

	// PatchAttributesCodeBodyTypePimCatalogDate captures enum value "pim_catalog_date"
	PatchAttributesCodeBodyTypePimCatalogDate string = "pim_catalog_date"

	// PatchAttributesCodeBodyTypePimCatalogTextarea captures enum value "pim_catalog_textarea"
	PatchAttributesCodeBodyTypePimCatalogTextarea string = "pim_catalog_textarea"

	// PatchAttributesCodeBodyTypePimCatalogText captures enum value "pim_catalog_text"
	PatchAttributesCodeBodyTypePimCatalogText string = "pim_catalog_text"

	// PatchAttributesCodeBodyTypePimCatalogFile captures enum value "pim_catalog_file"
	PatchAttributesCodeBodyTypePimCatalogFile string = "pim_catalog_file"

	// PatchAttributesCodeBodyTypePimCatalogImage captures enum value "pim_catalog_image"
	PatchAttributesCodeBodyTypePimCatalogImage string = "pim_catalog_image"

	// PatchAttributesCodeBodyTypePimCatalogPriceCollection captures enum value "pim_catalog_price_collection"
	PatchAttributesCodeBodyTypePimCatalogPriceCollection string = "pim_catalog_price_collection"

	// PatchAttributesCodeBodyTypePimCatalogBoolean captures enum value "pim_catalog_boolean"
	PatchAttributesCodeBodyTypePimCatalogBoolean string = "pim_catalog_boolean"

	// PatchAttributesCodeBodyTypeAkeneoReferenceEntity captures enum value "akeneo_reference_entity"
	PatchAttributesCodeBodyTypeAkeneoReferenceEntity string = "akeneo_reference_entity"

	// PatchAttributesCodeBodyTypeAkeneoReferenceEntityCollection captures enum value "akeneo_reference_entity_collection"
	PatchAttributesCodeBodyTypeAkeneoReferenceEntityCollection string = "akeneo_reference_entity_collection"

	// PatchAttributesCodeBodyTypePimCatalogAssetCollection captures enum value "pim_catalog_asset_collection"
	PatchAttributesCodeBodyTypePimCatalogAssetCollection string = "pim_catalog_asset_collection"
)

// prop value enum
func (o *PatchAttributesCodeBody) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, patchAttributesCodeBodyTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PatchAttributesCodeBody) validateType(formats strfmt.Registry) error {

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
func (o *PatchAttributesCodeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeBody) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeForbiddenBody patch attributes code forbidden body
swagger:model PatchAttributesCodeForbiddenBody
*/
type PatchAttributesCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch attributes code forbidden body
func (o *PatchAttributesCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeParamsBodyGroupLabels Group labels for each locale
swagger:model PatchAttributesCodeParamsBodyGroupLabels
*/
type PatchAttributesCodeParamsBodyGroupLabels struct {

	// Group label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch attributes code params body group labels
func (o *PatchAttributesCodeParamsBodyGroupLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeParamsBodyGroupLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeParamsBodyGroupLabels) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeParamsBodyGroupLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeParamsBodyLabels Attribute labels for each locale
swagger:model PatchAttributesCodeParamsBodyLabels
*/
type PatchAttributesCodeParamsBodyLabels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch attributes code params body labels
func (o *PatchAttributesCodeParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeUnauthorizedBody patch attributes code unauthorized body
swagger:model PatchAttributesCodeUnauthorizedBody
*/
type PatchAttributesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch attributes code unauthorized body
func (o *PatchAttributesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeUnprocessableEntityBody patch attributes code unprocessable entity body
swagger:model PatchAttributesCodeUnprocessableEntityBody
*/
type PatchAttributesCodeUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch attributes code unprocessable entity body
func (o *PatchAttributesCodeUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchAttributesCodeUnsupportedMediaTypeBody patch attributes code unsupported media type body
swagger:model PatchAttributesCodeUnsupportedMediaTypeBody
*/
type PatchAttributesCodeUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch attributes code unsupported media type body
func (o *PatchAttributesCodeUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchAttributesCodeUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchAttributesCodeUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchAttributesCodeUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
