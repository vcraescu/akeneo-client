// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_attribute

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

// PatchReferenceEntityAttributesCodeReader is a Reader for the PatchReferenceEntityAttributesCode structure.
type PatchReferenceEntityAttributesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchReferenceEntityAttributesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchReferenceEntityAttributesCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewPatchReferenceEntityAttributesCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPatchReferenceEntityAttributesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchReferenceEntityAttributesCodeUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchReferenceEntityAttributesCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchReferenceEntityAttributesCodeCreated creates a PatchReferenceEntityAttributesCodeCreated with default headers values
func NewPatchReferenceEntityAttributesCodeCreated() *PatchReferenceEntityAttributesCodeCreated {
	return &PatchReferenceEntityAttributesCodeCreated{}
}

/*PatchReferenceEntityAttributesCodeCreated handles this case with default header values.

Created
*/
type PatchReferenceEntityAttributesCodeCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PatchReferenceEntityAttributesCodeCreated) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] patchReferenceEntityAttributesCodeCreated ", 201)
}

func (o *PatchReferenceEntityAttributesCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchReferenceEntityAttributesCodeNoContent creates a PatchReferenceEntityAttributesCodeNoContent with default headers values
func NewPatchReferenceEntityAttributesCodeNoContent() *PatchReferenceEntityAttributesCodeNoContent {
	return &PatchReferenceEntityAttributesCodeNoContent{}
}

/*PatchReferenceEntityAttributesCodeNoContent handles this case with default header values.

No content to return
*/
type PatchReferenceEntityAttributesCodeNoContent struct {
	/*URI of the updated resource
	 */
	Location string
}

func (o *PatchReferenceEntityAttributesCodeNoContent) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] patchReferenceEntityAttributesCodeNoContent ", 204)
}

func (o *PatchReferenceEntityAttributesCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchReferenceEntityAttributesCodeUnauthorized creates a PatchReferenceEntityAttributesCodeUnauthorized with default headers values
func NewPatchReferenceEntityAttributesCodeUnauthorized() *PatchReferenceEntityAttributesCodeUnauthorized {
	return &PatchReferenceEntityAttributesCodeUnauthorized{}
}

/*PatchReferenceEntityAttributesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type PatchReferenceEntityAttributesCodeUnauthorized struct {
	Payload *PatchReferenceEntityAttributesCodeUnauthorizedBody
}

func (o *PatchReferenceEntityAttributesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] patchReferenceEntityAttributesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchReferenceEntityAttributesCodeUnauthorized) GetPayload() *PatchReferenceEntityAttributesCodeUnauthorizedBody {
	return o.Payload
}

func (o *PatchReferenceEntityAttributesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchReferenceEntityAttributesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchReferenceEntityAttributesCodeUnsupportedMediaType creates a PatchReferenceEntityAttributesCodeUnsupportedMediaType with default headers values
func NewPatchReferenceEntityAttributesCodeUnsupportedMediaType() *PatchReferenceEntityAttributesCodeUnsupportedMediaType {
	return &PatchReferenceEntityAttributesCodeUnsupportedMediaType{}
}

/*PatchReferenceEntityAttributesCodeUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchReferenceEntityAttributesCodeUnsupportedMediaType struct {
	Payload *PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody
}

func (o *PatchReferenceEntityAttributesCodeUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] patchReferenceEntityAttributesCodeUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchReferenceEntityAttributesCodeUnsupportedMediaType) GetPayload() *PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchReferenceEntityAttributesCodeUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchReferenceEntityAttributesCodeUnprocessableEntity creates a PatchReferenceEntityAttributesCodeUnprocessableEntity with default headers values
func NewPatchReferenceEntityAttributesCodeUnprocessableEntity() *PatchReferenceEntityAttributesCodeUnprocessableEntity {
	return &PatchReferenceEntityAttributesCodeUnprocessableEntity{}
}

/*PatchReferenceEntityAttributesCodeUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PatchReferenceEntityAttributesCodeUnprocessableEntity struct {
	Payload *PatchReferenceEntityAttributesCodeUnprocessableEntityBody
}

func (o *PatchReferenceEntityAttributesCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] patchReferenceEntityAttributesCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchReferenceEntityAttributesCodeUnprocessableEntity) GetPayload() *PatchReferenceEntityAttributesCodeUnprocessableEntityBody {
	return o.Payload
}

func (o *PatchReferenceEntityAttributesCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchReferenceEntityAttributesCodeUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchReferenceEntityAttributesCodeBody patch reference entity attributes code body
swagger:model PatchReferenceEntityAttributesCodeBody
*/
type PatchReferenceEntityAttributesCodeBody struct {

	// Extensions allowed when the attribute type is `image`
	AllowedExtensions []string `json:"allowed_extensions"`

	// Attribute code
	// Required: true
	Code *string `json:"code"`

	// Whether decimals are allowed when the attribute type is `number`
	DecimalsAllowed *bool `json:"decimals_allowed,omitempty"`

	// Whether the attribute should be part of the record's completeness calculation
	IsRequiredForCompleteness *bool `json:"is_required_for_completeness,omitempty"`

	// Whether the UI should display a rich text editor instead of a simple text area when the attribute type is `text`
	IsRichTextEditor bool `json:"is_rich_text_editor,omitempty"`

	// Whether the UI should display a text area instead of a simple field when the attribute type is `text`
	IsTextarea *bool `json:"is_textarea,omitempty"`

	// labels
	Labels *PatchReferenceEntityAttributesCodeParamsBodyLabels `json:"labels,omitempty"`

	// Maximum number of characters allowed for the value of the attribute when the attribute type is `text`
	MaxCharacters int64 `json:"max_characters,omitempty"`

	// Max file size in MB when the attribute type is `image`
	MaxFileSize string `json:"max_file_size,omitempty"`

	// Maximum value allowed when the attribute type is `number`
	MaxValue string `json:"max_value,omitempty"`

	// Minimum value allowed when the attribute type is `number`
	MinValue string `json:"min_value,omitempty"`

	// Code of the linked reference entity when the attribute type is `reference_entity_single_link` or `reference_entity_multiple_links`
	ReferenceEntityCode string `json:"reference_entity_code,omitempty"`

	// Attribute type
	// Required: true
	// Enum: [text image number single_option multiple_options reference_entity_single_link reference_entity_multiple_links]
	Type *string `json:"type"`

	// Regexp expression used to validate the attribute value when the attribute type is `text`
	ValidationRegexp string `json:"validation_regexp,omitempty"`

	// Validation rule type used to validate the attribute value when the attribute type is `text`
	// Enum: [email url regexp none]
	ValidationRule *string `json:"validation_rule,omitempty"`

	// Whether the attribute is scopable, i.e. can have one value by channel
	ValuePerChannel *bool `json:"value_per_channel,omitempty"`

	// Whether the attribute is localizable, i.e. can have one value by locale
	ValuePerLocale *bool `json:"value_per_locale,omitempty"`
}

// Validate validates this patch reference entity attributes code body
func (o *PatchReferenceEntityAttributesCodeBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateValidationRule(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchReferenceEntityAttributesCodeBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PatchReferenceEntityAttributesCodeBody) validateLabels(formats strfmt.Registry) error {

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

var patchReferenceEntityAttributesCodeBodyTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["text","image","number","single_option","multiple_options","reference_entity_single_link","reference_entity_multiple_links"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		patchReferenceEntityAttributesCodeBodyTypeTypePropEnum = append(patchReferenceEntityAttributesCodeBodyTypeTypePropEnum, v)
	}
}

const (

	// PatchReferenceEntityAttributesCodeBodyTypeText captures enum value "text"
	PatchReferenceEntityAttributesCodeBodyTypeText string = "text"

	// PatchReferenceEntityAttributesCodeBodyTypeImage captures enum value "image"
	PatchReferenceEntityAttributesCodeBodyTypeImage string = "image"

	// PatchReferenceEntityAttributesCodeBodyTypeNumber captures enum value "number"
	PatchReferenceEntityAttributesCodeBodyTypeNumber string = "number"

	// PatchReferenceEntityAttributesCodeBodyTypeSingleOption captures enum value "single_option"
	PatchReferenceEntityAttributesCodeBodyTypeSingleOption string = "single_option"

	// PatchReferenceEntityAttributesCodeBodyTypeMultipleOptions captures enum value "multiple_options"
	PatchReferenceEntityAttributesCodeBodyTypeMultipleOptions string = "multiple_options"

	// PatchReferenceEntityAttributesCodeBodyTypeReferenceEntitySingleLink captures enum value "reference_entity_single_link"
	PatchReferenceEntityAttributesCodeBodyTypeReferenceEntitySingleLink string = "reference_entity_single_link"

	// PatchReferenceEntityAttributesCodeBodyTypeReferenceEntityMultipleLinks captures enum value "reference_entity_multiple_links"
	PatchReferenceEntityAttributesCodeBodyTypeReferenceEntityMultipleLinks string = "reference_entity_multiple_links"
)

// prop value enum
func (o *PatchReferenceEntityAttributesCodeBody) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, patchReferenceEntityAttributesCodeBodyTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PatchReferenceEntityAttributesCodeBody) validateType(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"type", "body", o.Type); err != nil {
		return err
	}

	// value enum
	if err := o.validateTypeEnum("body"+"."+"type", "body", *o.Type); err != nil {
		return err
	}

	return nil
}

var patchReferenceEntityAttributesCodeBodyTypeValidationRulePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["email","url","regexp","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		patchReferenceEntityAttributesCodeBodyTypeValidationRulePropEnum = append(patchReferenceEntityAttributesCodeBodyTypeValidationRulePropEnum, v)
	}
}

const (

	// PatchReferenceEntityAttributesCodeBodyValidationRuleEmail captures enum value "email"
	PatchReferenceEntityAttributesCodeBodyValidationRuleEmail string = "email"

	// PatchReferenceEntityAttributesCodeBodyValidationRuleURL captures enum value "url"
	PatchReferenceEntityAttributesCodeBodyValidationRuleURL string = "url"

	// PatchReferenceEntityAttributesCodeBodyValidationRuleRegexp captures enum value "regexp"
	PatchReferenceEntityAttributesCodeBodyValidationRuleRegexp string = "regexp"

	// PatchReferenceEntityAttributesCodeBodyValidationRuleNone captures enum value "none"
	PatchReferenceEntityAttributesCodeBodyValidationRuleNone string = "none"
)

// prop value enum
func (o *PatchReferenceEntityAttributesCodeBody) validateValidationRuleEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, patchReferenceEntityAttributesCodeBodyTypeValidationRulePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PatchReferenceEntityAttributesCodeBody) validateValidationRule(formats strfmt.Registry) error {

	if swag.IsZero(o.ValidationRule) { // not required
		return nil
	}

	// value enum
	if err := o.validateValidationRuleEnum("body"+"."+"validation_rule", "body", *o.ValidationRule); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesCodeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesCodeParamsBodyLabels Attribute labels for each locale
swagger:model PatchReferenceEntityAttributesCodeParamsBodyLabels
*/
type PatchReferenceEntityAttributesCodeParamsBodyLabels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch reference entity attributes code params body labels
func (o *PatchReferenceEntityAttributesCodeParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesCodeParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesCodeUnauthorizedBody patch reference entity attributes code unauthorized body
swagger:model PatchReferenceEntityAttributesCodeUnauthorizedBody
*/
type PatchReferenceEntityAttributesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch reference entity attributes code unauthorized body
func (o *PatchReferenceEntityAttributesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesCodeUnprocessableEntityBody patch reference entity attributes code unprocessable entity body
swagger:model PatchReferenceEntityAttributesCodeUnprocessableEntityBody
*/
type PatchReferenceEntityAttributesCodeUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch reference entity attributes code unprocessable entity body
func (o *PatchReferenceEntityAttributesCodeUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesCodeUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody patch reference entity attributes code unsupported media type body
swagger:model PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody
*/
type PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch reference entity attributes code unsupported media type body
func (o *PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesCodeUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}