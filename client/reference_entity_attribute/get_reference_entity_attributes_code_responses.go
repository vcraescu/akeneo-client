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

// GetReferenceEntityAttributesCodeReader is a Reader for the GetReferenceEntityAttributesCode structure.
type GetReferenceEntityAttributesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetReferenceEntityAttributesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetReferenceEntityAttributesCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetReferenceEntityAttributesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetReferenceEntityAttributesCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetReferenceEntityAttributesCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetReferenceEntityAttributesCodeOK creates a GetReferenceEntityAttributesCodeOK with default headers values
func NewGetReferenceEntityAttributesCodeOK() *GetReferenceEntityAttributesCodeOK {
	return &GetReferenceEntityAttributesCodeOK{}
}

/*GetReferenceEntityAttributesCodeOK handles this case with default header values.

OK
*/
type GetReferenceEntityAttributesCodeOK struct {
	Payload *GetReferenceEntityAttributesCodeOKBody
}

func (o *GetReferenceEntityAttributesCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] getReferenceEntityAttributesCodeOK  %+v", 200, o.Payload)
}

func (o *GetReferenceEntityAttributesCodeOK) GetPayload() *GetReferenceEntityAttributesCodeOKBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityAttributesCodeUnauthorized creates a GetReferenceEntityAttributesCodeUnauthorized with default headers values
func NewGetReferenceEntityAttributesCodeUnauthorized() *GetReferenceEntityAttributesCodeUnauthorized {
	return &GetReferenceEntityAttributesCodeUnauthorized{}
}

/*GetReferenceEntityAttributesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetReferenceEntityAttributesCodeUnauthorized struct {
	Payload *GetReferenceEntityAttributesCodeUnauthorizedBody
}

func (o *GetReferenceEntityAttributesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] getReferenceEntityAttributesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetReferenceEntityAttributesCodeUnauthorized) GetPayload() *GetReferenceEntityAttributesCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityAttributesCodeNotFound creates a GetReferenceEntityAttributesCodeNotFound with default headers values
func NewGetReferenceEntityAttributesCodeNotFound() *GetReferenceEntityAttributesCodeNotFound {
	return &GetReferenceEntityAttributesCodeNotFound{}
}

/*GetReferenceEntityAttributesCodeNotFound handles this case with default header values.

Resource not found
*/
type GetReferenceEntityAttributesCodeNotFound struct {
	Payload *GetReferenceEntityAttributesCodeNotFoundBody
}

func (o *GetReferenceEntityAttributesCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] getReferenceEntityAttributesCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetReferenceEntityAttributesCodeNotFound) GetPayload() *GetReferenceEntityAttributesCodeNotFoundBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityAttributesCodeNotAcceptable creates a GetReferenceEntityAttributesCodeNotAcceptable with default headers values
func NewGetReferenceEntityAttributesCodeNotAcceptable() *GetReferenceEntityAttributesCodeNotAcceptable {
	return &GetReferenceEntityAttributesCodeNotAcceptable{}
}

/*GetReferenceEntityAttributesCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetReferenceEntityAttributesCodeNotAcceptable struct {
	Payload *GetReferenceEntityAttributesCodeNotAcceptableBody
}

func (o *GetReferenceEntityAttributesCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{code}][%d] getReferenceEntityAttributesCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetReferenceEntityAttributesCodeNotAcceptable) GetPayload() *GetReferenceEntityAttributesCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetReferenceEntityAttributesCodeNotAcceptableBody get reference entity attributes code not acceptable body
swagger:model GetReferenceEntityAttributesCodeNotAcceptableBody
*/
type GetReferenceEntityAttributesCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity attributes code not acceptable body
func (o *GetReferenceEntityAttributesCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesCodeNotFoundBody get reference entity attributes code not found body
swagger:model GetReferenceEntityAttributesCodeNotFoundBody
*/
type GetReferenceEntityAttributesCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity attributes code not found body
func (o *GetReferenceEntityAttributesCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesCodeOKBody get reference entity attributes code o k body
swagger:model GetReferenceEntityAttributesCodeOKBody
*/
type GetReferenceEntityAttributesCodeOKBody struct {

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
	Labels *GetReferenceEntityAttributesCodeOKBodyLabels `json:"labels,omitempty"`

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

// Validate validates this get reference entity attributes code o k body
func (o *GetReferenceEntityAttributesCodeOKBody) Validate(formats strfmt.Registry) error {
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

func (o *GetReferenceEntityAttributesCodeOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("getReferenceEntityAttributesCodeOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetReferenceEntityAttributesCodeOKBody) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityAttributesCodeOK" + "." + "labels")
			}
			return err
		}
	}

	return nil
}

var getReferenceEntityAttributesCodeOKBodyTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["text","image","number","single_option","multiple_options","reference_entity_single_link","reference_entity_multiple_links"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getReferenceEntityAttributesCodeOKBodyTypeTypePropEnum = append(getReferenceEntityAttributesCodeOKBodyTypeTypePropEnum, v)
	}
}

const (

	// GetReferenceEntityAttributesCodeOKBodyTypeText captures enum value "text"
	GetReferenceEntityAttributesCodeOKBodyTypeText string = "text"

	// GetReferenceEntityAttributesCodeOKBodyTypeImage captures enum value "image"
	GetReferenceEntityAttributesCodeOKBodyTypeImage string = "image"

	// GetReferenceEntityAttributesCodeOKBodyTypeNumber captures enum value "number"
	GetReferenceEntityAttributesCodeOKBodyTypeNumber string = "number"

	// GetReferenceEntityAttributesCodeOKBodyTypeSingleOption captures enum value "single_option"
	GetReferenceEntityAttributesCodeOKBodyTypeSingleOption string = "single_option"

	// GetReferenceEntityAttributesCodeOKBodyTypeMultipleOptions captures enum value "multiple_options"
	GetReferenceEntityAttributesCodeOKBodyTypeMultipleOptions string = "multiple_options"

	// GetReferenceEntityAttributesCodeOKBodyTypeReferenceEntitySingleLink captures enum value "reference_entity_single_link"
	GetReferenceEntityAttributesCodeOKBodyTypeReferenceEntitySingleLink string = "reference_entity_single_link"

	// GetReferenceEntityAttributesCodeOKBodyTypeReferenceEntityMultipleLinks captures enum value "reference_entity_multiple_links"
	GetReferenceEntityAttributesCodeOKBodyTypeReferenceEntityMultipleLinks string = "reference_entity_multiple_links"
)

// prop value enum
func (o *GetReferenceEntityAttributesCodeOKBody) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getReferenceEntityAttributesCodeOKBodyTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *GetReferenceEntityAttributesCodeOKBody) validateType(formats strfmt.Registry) error {

	if err := validate.Required("getReferenceEntityAttributesCodeOK"+"."+"type", "body", o.Type); err != nil {
		return err
	}

	// value enum
	if err := o.validateTypeEnum("getReferenceEntityAttributesCodeOK"+"."+"type", "body", *o.Type); err != nil {
		return err
	}

	return nil
}

var getReferenceEntityAttributesCodeOKBodyTypeValidationRulePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["email","url","regexp","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getReferenceEntityAttributesCodeOKBodyTypeValidationRulePropEnum = append(getReferenceEntityAttributesCodeOKBodyTypeValidationRulePropEnum, v)
	}
}

const (

	// GetReferenceEntityAttributesCodeOKBodyValidationRuleEmail captures enum value "email"
	GetReferenceEntityAttributesCodeOKBodyValidationRuleEmail string = "email"

	// GetReferenceEntityAttributesCodeOKBodyValidationRuleURL captures enum value "url"
	GetReferenceEntityAttributesCodeOKBodyValidationRuleURL string = "url"

	// GetReferenceEntityAttributesCodeOKBodyValidationRuleRegexp captures enum value "regexp"
	GetReferenceEntityAttributesCodeOKBodyValidationRuleRegexp string = "regexp"

	// GetReferenceEntityAttributesCodeOKBodyValidationRuleNone captures enum value "none"
	GetReferenceEntityAttributesCodeOKBodyValidationRuleNone string = "none"
)

// prop value enum
func (o *GetReferenceEntityAttributesCodeOKBody) validateValidationRuleEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getReferenceEntityAttributesCodeOKBodyTypeValidationRulePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *GetReferenceEntityAttributesCodeOKBody) validateValidationRule(formats strfmt.Registry) error {

	if swag.IsZero(o.ValidationRule) { // not required
		return nil
	}

	// value enum
	if err := o.validateValidationRuleEnum("getReferenceEntityAttributesCodeOK"+"."+"validation_rule", "body", *o.ValidationRule); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesCodeOKBodyLabels Attribute labels for each locale
swagger:model GetReferenceEntityAttributesCodeOKBodyLabels
*/
type GetReferenceEntityAttributesCodeOKBodyLabels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this get reference entity attributes code o k body labels
func (o *GetReferenceEntityAttributesCodeOKBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeOKBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeOKBodyLabels) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesCodeOKBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesCodeUnauthorizedBody get reference entity attributes code unauthorized body
swagger:model GetReferenceEntityAttributesCodeUnauthorizedBody
*/
type GetReferenceEntityAttributesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity attributes code unauthorized body
func (o *GetReferenceEntityAttributesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}