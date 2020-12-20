// Code generated by go-swagger; DO NOT EDIT.

package channel

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// SeveralChannelsPatchReader is a Reader for the SeveralChannelsPatch structure.
type SeveralChannelsPatchReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SeveralChannelsPatchReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSeveralChannelsPatchOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSeveralChannelsPatchUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSeveralChannelsPatchForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 413:
		result := NewSeveralChannelsPatchRequestEntityTooLarge()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewSeveralChannelsPatchUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSeveralChannelsPatchOK creates a SeveralChannelsPatchOK with default headers values
func NewSeveralChannelsPatchOK() *SeveralChannelsPatchOK {
	return &SeveralChannelsPatchOK{}
}

/*SeveralChannelsPatchOK handles this case with default header values.

OK
*/
type SeveralChannelsPatchOK struct {
	Payload *SeveralChannelsPatchOKBody
}

func (o *SeveralChannelsPatchOK) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/channels][%d] severalChannelsPatchOK  %+v", 200, o.Payload)
}

func (o *SeveralChannelsPatchOK) GetPayload() *SeveralChannelsPatchOKBody {
	return o.Payload
}

func (o *SeveralChannelsPatchOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralChannelsPatchOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralChannelsPatchUnauthorized creates a SeveralChannelsPatchUnauthorized with default headers values
func NewSeveralChannelsPatchUnauthorized() *SeveralChannelsPatchUnauthorized {
	return &SeveralChannelsPatchUnauthorized{}
}

/*SeveralChannelsPatchUnauthorized handles this case with default header values.

Authentication required
*/
type SeveralChannelsPatchUnauthorized struct {
	Payload *SeveralChannelsPatchUnauthorizedBody
}

func (o *SeveralChannelsPatchUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/channels][%d] severalChannelsPatchUnauthorized  %+v", 401, o.Payload)
}

func (o *SeveralChannelsPatchUnauthorized) GetPayload() *SeveralChannelsPatchUnauthorizedBody {
	return o.Payload
}

func (o *SeveralChannelsPatchUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralChannelsPatchUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralChannelsPatchForbidden creates a SeveralChannelsPatchForbidden with default headers values
func NewSeveralChannelsPatchForbidden() *SeveralChannelsPatchForbidden {
	return &SeveralChannelsPatchForbidden{}
}

/*SeveralChannelsPatchForbidden handles this case with default header values.

Access forbidden
*/
type SeveralChannelsPatchForbidden struct {
	Payload *SeveralChannelsPatchForbiddenBody
}

func (o *SeveralChannelsPatchForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/channels][%d] severalChannelsPatchForbidden  %+v", 403, o.Payload)
}

func (o *SeveralChannelsPatchForbidden) GetPayload() *SeveralChannelsPatchForbiddenBody {
	return o.Payload
}

func (o *SeveralChannelsPatchForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralChannelsPatchForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralChannelsPatchRequestEntityTooLarge creates a SeveralChannelsPatchRequestEntityTooLarge with default headers values
func NewSeveralChannelsPatchRequestEntityTooLarge() *SeveralChannelsPatchRequestEntityTooLarge {
	return &SeveralChannelsPatchRequestEntityTooLarge{}
}

/*SeveralChannelsPatchRequestEntityTooLarge handles this case with default header values.

Request Entity Too Large
*/
type SeveralChannelsPatchRequestEntityTooLarge struct {
	Payload *SeveralChannelsPatchRequestEntityTooLargeBody
}

func (o *SeveralChannelsPatchRequestEntityTooLarge) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/channels][%d] severalChannelsPatchRequestEntityTooLarge  %+v", 413, o.Payload)
}

func (o *SeveralChannelsPatchRequestEntityTooLarge) GetPayload() *SeveralChannelsPatchRequestEntityTooLargeBody {
	return o.Payload
}

func (o *SeveralChannelsPatchRequestEntityTooLarge) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralChannelsPatchRequestEntityTooLargeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralChannelsPatchUnsupportedMediaType creates a SeveralChannelsPatchUnsupportedMediaType with default headers values
func NewSeveralChannelsPatchUnsupportedMediaType() *SeveralChannelsPatchUnsupportedMediaType {
	return &SeveralChannelsPatchUnsupportedMediaType{}
}

/*SeveralChannelsPatchUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type SeveralChannelsPatchUnsupportedMediaType struct {
	Payload *SeveralChannelsPatchUnsupportedMediaTypeBody
}

func (o *SeveralChannelsPatchUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/channels][%d] severalChannelsPatchUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *SeveralChannelsPatchUnsupportedMediaType) GetPayload() *SeveralChannelsPatchUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *SeveralChannelsPatchUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralChannelsPatchUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*SeveralChannelsPatchBody several channels patch body
swagger:model SeveralChannelsPatchBody
*/
type SeveralChannelsPatchBody struct {

	// Code of the category tree linked to the channel
	// Required: true
	CategoryTree *string `json:"category_tree"`

	// Channel code
	// Required: true
	Code *string `json:"code"`

	// conversion units
	ConversionUnits *SeveralChannelsPatchParamsBodyConversionUnits `json:"conversion_units,omitempty"`

	// Codes of activated currencies for the channel
	// Required: true
	Currencies []string `json:"currencies"`

	// labels
	Labels *SeveralChannelsPatchParamsBodyLabels `json:"labels,omitempty"`

	// Codes of activated locales for the channel
	// Required: true
	Locales []string `json:"locales"`
}

// Validate validates this several channels patch body
func (o *SeveralChannelsPatchBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCategoryTree(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateConversionUnits(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCurrencies(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLocales(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SeveralChannelsPatchBody) validateCategoryTree(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"category_tree", "body", o.CategoryTree); err != nil {
		return err
	}

	return nil
}

func (o *SeveralChannelsPatchBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *SeveralChannelsPatchBody) validateConversionUnits(formats strfmt.Registry) error {

	if swag.IsZero(o.ConversionUnits) { // not required
		return nil
	}

	if o.ConversionUnits != nil {
		if err := o.ConversionUnits.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "conversion_units")
			}
			return err
		}
	}

	return nil
}

func (o *SeveralChannelsPatchBody) validateCurrencies(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"currencies", "body", o.Currencies); err != nil {
		return err
	}

	return nil
}

func (o *SeveralChannelsPatchBody) validateLabels(formats strfmt.Registry) error {

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

func (o *SeveralChannelsPatchBody) validateLocales(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"locales", "body", o.Locales); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchBody) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchForbiddenBody several channels patch forbidden body
swagger:model SeveralChannelsPatchForbiddenBody
*/
type SeveralChannelsPatchForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several channels patch forbidden body
func (o *SeveralChannelsPatchForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchForbiddenBody) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchOKBody several channels patch o k body
swagger:model SeveralChannelsPatchOKBody
*/
type SeveralChannelsPatchOKBody struct {

	// Resource code, only filled when the resource is not a product
	Code string `json:"code,omitempty"`

	// Resource identifier, only filled when the resource is a product
	Identifier string `json:"identifier,omitempty"`

	// Line number
	Line int64 `json:"line,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`

	// HTTP status code, see <a href="/documentation/responses.html#client-errors">Client errors</a> to understand the meaning of each code
	StatusCode int64 `json:"status_code,omitempty"`
}

// Validate validates this several channels patch o k body
func (o *SeveralChannelsPatchOKBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchOKBody) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchParamsBodyConversionUnits Units to which the given metric attributes should be converted when exporting products
swagger:model SeveralChannelsPatchParamsBodyConversionUnits
*/
type SeveralChannelsPatchParamsBodyConversionUnits struct {

	// Conversion unit code used to convert the values of the attribute `attributeCode` when exporting via the channel
	AttributeCode string `json:"attributeCode,omitempty"`
}

// Validate validates this several channels patch params body conversion units
func (o *SeveralChannelsPatchParamsBodyConversionUnits) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchParamsBodyConversionUnits) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchParamsBodyConversionUnits) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchParamsBodyConversionUnits
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchParamsBodyLabels Channel labels for each locale
swagger:model SeveralChannelsPatchParamsBodyLabels
*/
type SeveralChannelsPatchParamsBodyLabels struct {

	// Channel label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this several channels patch params body labels
func (o *SeveralChannelsPatchParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchRequestEntityTooLargeBody several channels patch request entity too large body
swagger:model SeveralChannelsPatchRequestEntityTooLargeBody
*/
type SeveralChannelsPatchRequestEntityTooLargeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several channels patch request entity too large body
func (o *SeveralChannelsPatchRequestEntityTooLargeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchRequestEntityTooLargeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchRequestEntityTooLargeBody) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchRequestEntityTooLargeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchUnauthorizedBody several channels patch unauthorized body
swagger:model SeveralChannelsPatchUnauthorizedBody
*/
type SeveralChannelsPatchUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several channels patch unauthorized body
func (o *SeveralChannelsPatchUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralChannelsPatchUnsupportedMediaTypeBody several channels patch unsupported media type body
swagger:model SeveralChannelsPatchUnsupportedMediaTypeBody
*/
type SeveralChannelsPatchUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several channels patch unsupported media type body
func (o *SeveralChannelsPatchUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralChannelsPatchUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralChannelsPatchUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res SeveralChannelsPatchUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}