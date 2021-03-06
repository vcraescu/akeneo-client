// Code generated by go-swagger; DO NOT EDIT.

package asset_attribute

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

// GetAssetFamiliesCodeAttributesReader is a Reader for the GetAssetFamiliesCodeAttributes structure.
type GetAssetFamiliesCodeAttributesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAssetFamiliesCodeAttributesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAssetFamiliesCodeAttributesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAssetFamiliesCodeAttributesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetAssetFamiliesCodeAttributesNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAssetFamiliesCodeAttributesOK creates a GetAssetFamiliesCodeAttributesOK with default headers values
func NewGetAssetFamiliesCodeAttributesOK() *GetAssetFamiliesCodeAttributesOK {
	return &GetAssetFamiliesCodeAttributesOK{}
}

/*GetAssetFamiliesCodeAttributesOK handles this case with default header values.

Return the attributes of the given asset family
*/
type GetAssetFamiliesCodeAttributesOK struct {
	Payload []*GetAssetFamiliesCodeAttributesOKBodyItems0
}

func (o *GetAssetFamiliesCodeAttributesOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-families/{asset_family_code}/attributes][%d] getAssetFamiliesCodeAttributesOK  %+v", 200, o.Payload)
}

func (o *GetAssetFamiliesCodeAttributesOK) GetPayload() []*GetAssetFamiliesCodeAttributesOKBodyItems0 {
	return o.Payload
}

func (o *GetAssetFamiliesCodeAttributesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetFamiliesCodeAttributesUnauthorized creates a GetAssetFamiliesCodeAttributesUnauthorized with default headers values
func NewGetAssetFamiliesCodeAttributesUnauthorized() *GetAssetFamiliesCodeAttributesUnauthorized {
	return &GetAssetFamiliesCodeAttributesUnauthorized{}
}

/*GetAssetFamiliesCodeAttributesUnauthorized handles this case with default header values.

Authentication required
*/
type GetAssetFamiliesCodeAttributesUnauthorized struct {
	Payload *GetAssetFamiliesCodeAttributesUnauthorizedBody
}

func (o *GetAssetFamiliesCodeAttributesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-families/{asset_family_code}/attributes][%d] getAssetFamiliesCodeAttributesUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAssetFamiliesCodeAttributesUnauthorized) GetPayload() *GetAssetFamiliesCodeAttributesUnauthorizedBody {
	return o.Payload
}

func (o *GetAssetFamiliesCodeAttributesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetFamiliesCodeAttributesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetFamiliesCodeAttributesNotAcceptable creates a GetAssetFamiliesCodeAttributesNotAcceptable with default headers values
func NewGetAssetFamiliesCodeAttributesNotAcceptable() *GetAssetFamiliesCodeAttributesNotAcceptable {
	return &GetAssetFamiliesCodeAttributesNotAcceptable{}
}

/*GetAssetFamiliesCodeAttributesNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetAssetFamiliesCodeAttributesNotAcceptable struct {
	Payload *GetAssetFamiliesCodeAttributesNotAcceptableBody
}

func (o *GetAssetFamiliesCodeAttributesNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-families/{asset_family_code}/attributes][%d] getAssetFamiliesCodeAttributesNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetAssetFamiliesCodeAttributesNotAcceptable) GetPayload() *GetAssetFamiliesCodeAttributesNotAcceptableBody {
	return o.Payload
}

func (o *GetAssetFamiliesCodeAttributesNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetFamiliesCodeAttributesNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetAssetFamiliesCodeAttributesNotAcceptableBody get asset families code attributes not acceptable body
swagger:model GetAssetFamiliesCodeAttributesNotAcceptableBody
*/
type GetAssetFamiliesCodeAttributesNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get asset families code attributes not acceptable body
func (o *GetAssetFamiliesCodeAttributesNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetAssetFamiliesCodeAttributesNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetFamiliesCodeAttributesOKBodyItems0 get asset families code attributes o k body items0
swagger:model GetAssetFamiliesCodeAttributesOKBodyItems0
*/
type GetAssetFamiliesCodeAttributesOKBodyItems0 struct {

	// Extensions allowed when the attribute type is `media_file`
	AllowedExtensions []string `json:"allowed_extensions"`

	// Attribute code
	// Required: true
	Code *string `json:"code"`

	// Whether decimals are allowed when the attribute type is `number`
	DecimalsAllowed *bool `json:"decimals_allowed,omitempty"`

	// Whether the attribute should be in read only mode only in the UI, but you can still update it with the API
	IsReadOnly *bool `json:"is_read_only,omitempty"`

	// Whether the attribute should be part of the record's completeness calculation
	IsRequiredForCompleteness *bool `json:"is_required_for_completeness,omitempty"`

	// Whether the UI should display a rich text editor instead of a simple text area when the attribute type is `text`
	IsRichTextEditor bool `json:"is_rich_text_editor,omitempty"`

	// Whether the UI should display a text area instead of a simple field when the attribute type is `text`
	IsTextarea *bool `json:"is_textarea,omitempty"`

	// labels
	Labels *GetAssetFamiliesCodeAttributesOKBodyItems0Labels `json:"labels,omitempty"`

	// Maximum number of characters allowed for the value of the attribute when the attribute type is `text`
	MaxCharacters int64 `json:"max_characters,omitempty"`

	// Max file size in MB when the attribute type is `media_file`
	MaxFileSize string `json:"max_file_size,omitempty"`

	// Maximum value allowed when the attribute type is `number`
	MaxValue string `json:"max_value,omitempty"`

	// For the `media_link` attribute type, it is the type of the media behind the url, to allow its preview in the PIM. For the `media_file` attribute type, it is the type of the file.
	// Required: true
	// Enum: [image pdf youtube vimeo other]
	MediaType *string `json:"media_type"`

	// Minimum value allowed when the attribute type is `number`
	MinValue string `json:"min_value,omitempty"`

	// Prefix of the `media_link` attribute type. The common url root that prefixes the link to the media
	Prefix string `json:"prefix,omitempty"`

	// Suffix of the `media_link` attribute type. The common url suffix for the media
	Suffix string `json:"suffix,omitempty"`

	// Attribute type
	// Required: true
	// Enum: [text media_link number media_file single_option multiple_options reference_entity_single_link reference_entity_multiple_links]
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

// Validate validates this get asset families code attributes o k body items0
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateMediaType(formats); err != nil {
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

func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("labels")
			}
			return err
		}
	}

	return nil
}

var getAssetFamiliesCodeAttributesOKBodyItems0TypeMediaTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["image","pdf","youtube","vimeo","other"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getAssetFamiliesCodeAttributesOKBodyItems0TypeMediaTypePropEnum = append(getAssetFamiliesCodeAttributesOKBodyItems0TypeMediaTypePropEnum, v)
	}
}

const (

	// GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeImage captures enum value "image"
	GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeImage string = "image"

	// GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypePdf captures enum value "pdf"
	GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypePdf string = "pdf"

	// GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeYoutube captures enum value "youtube"
	GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeYoutube string = "youtube"

	// GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeVimeo captures enum value "vimeo"
	GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeVimeo string = "vimeo"

	// GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeOther captures enum value "other"
	GetAssetFamiliesCodeAttributesOKBodyItems0MediaTypeOther string = "other"
)

// prop value enum
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateMediaTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getAssetFamiliesCodeAttributesOKBodyItems0TypeMediaTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateMediaType(formats strfmt.Registry) error {

	if err := validate.Required("media_type", "body", o.MediaType); err != nil {
		return err
	}

	// value enum
	if err := o.validateMediaTypeEnum("media_type", "body", *o.MediaType); err != nil {
		return err
	}

	return nil
}

var getAssetFamiliesCodeAttributesOKBodyItems0TypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["text","media_link","number","media_file","single_option","multiple_options","reference_entity_single_link","reference_entity_multiple_links"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getAssetFamiliesCodeAttributesOKBodyItems0TypeTypePropEnum = append(getAssetFamiliesCodeAttributesOKBodyItems0TypeTypePropEnum, v)
	}
}

const (

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeText captures enum value "text"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeText string = "text"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeMediaLink captures enum value "media_link"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeMediaLink string = "media_link"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeNumber captures enum value "number"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeNumber string = "number"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeMediaFile captures enum value "media_file"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeMediaFile string = "media_file"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeSingleOption captures enum value "single_option"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeSingleOption string = "single_option"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeMultipleOptions captures enum value "multiple_options"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeMultipleOptions string = "multiple_options"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeReferenceEntitySingleLink captures enum value "reference_entity_single_link"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeReferenceEntitySingleLink string = "reference_entity_single_link"

	// GetAssetFamiliesCodeAttributesOKBodyItems0TypeReferenceEntityMultipleLinks captures enum value "reference_entity_multiple_links"
	GetAssetFamiliesCodeAttributesOKBodyItems0TypeReferenceEntityMultipleLinks string = "reference_entity_multiple_links"
)

// prop value enum
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getAssetFamiliesCodeAttributesOKBodyItems0TypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", o.Type); err != nil {
		return err
	}

	// value enum
	if err := o.validateTypeEnum("type", "body", *o.Type); err != nil {
		return err
	}

	return nil
}

var getAssetFamiliesCodeAttributesOKBodyItems0TypeValidationRulePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["email","url","regexp","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getAssetFamiliesCodeAttributesOKBodyItems0TypeValidationRulePropEnum = append(getAssetFamiliesCodeAttributesOKBodyItems0TypeValidationRulePropEnum, v)
	}
}

const (

	// GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleEmail captures enum value "email"
	GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleEmail string = "email"

	// GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleURL captures enum value "url"
	GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleURL string = "url"

	// GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleRegexp captures enum value "regexp"
	GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleRegexp string = "regexp"

	// GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleNone captures enum value "none"
	GetAssetFamiliesCodeAttributesOKBodyItems0ValidationRuleNone string = "none"
)

// prop value enum
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateValidationRuleEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getAssetFamiliesCodeAttributesOKBodyItems0TypeValidationRulePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) validateValidationRule(formats strfmt.Registry) error {

	if swag.IsZero(o.ValidationRule) { // not required
		return nil
	}

	// value enum
	if err := o.validateValidationRuleEnum("validation_rule", "body", *o.ValidationRule); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0) UnmarshalBinary(b []byte) error {
	var res GetAssetFamiliesCodeAttributesOKBodyItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetFamiliesCodeAttributesOKBodyItems0Labels Attribute labels for each locale
swagger:model GetAssetFamiliesCodeAttributesOKBodyItems0Labels
*/
type GetAssetFamiliesCodeAttributesOKBodyItems0Labels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this get asset families code attributes o k body items0 labels
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0Labels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesOKBodyItems0Labels) UnmarshalBinary(b []byte) error {
	var res GetAssetFamiliesCodeAttributesOKBodyItems0Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetFamiliesCodeAttributesUnauthorizedBody get asset families code attributes unauthorized body
swagger:model GetAssetFamiliesCodeAttributesUnauthorizedBody
*/
type GetAssetFamiliesCodeAttributesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get asset families code attributes unauthorized body
func (o *GetAssetFamiliesCodeAttributesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetFamiliesCodeAttributesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetAssetFamiliesCodeAttributesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
