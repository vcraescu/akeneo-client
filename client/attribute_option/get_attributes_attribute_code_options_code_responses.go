// Code generated by go-swagger; DO NOT EDIT.

package attribute_option

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

// GetAttributesAttributeCodeOptionsCodeReader is a Reader for the GetAttributesAttributeCodeOptionsCode structure.
type GetAttributesAttributeCodeOptionsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAttributesAttributeCodeOptionsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAttributesAttributeCodeOptionsCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAttributesAttributeCodeOptionsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAttributesAttributeCodeOptionsCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAttributesAttributeCodeOptionsCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetAttributesAttributeCodeOptionsCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAttributesAttributeCodeOptionsCodeOK creates a GetAttributesAttributeCodeOptionsCodeOK with default headers values
func NewGetAttributesAttributeCodeOptionsCodeOK() *GetAttributesAttributeCodeOptionsCodeOK {
	return &GetAttributesAttributeCodeOptionsCodeOK{}
}

/*GetAttributesAttributeCodeOptionsCodeOK handles this case with default header values.

OK
*/
type GetAttributesAttributeCodeOptionsCodeOK struct {
	Payload *GetAttributesAttributeCodeOptionsCodeOKBody
}

func (o *GetAttributesAttributeCodeOptionsCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/attributes/{attribute_code}/options/{code}][%d] getAttributesAttributeCodeOptionsCodeOK  %+v", 200, o.Payload)
}

func (o *GetAttributesAttributeCodeOptionsCodeOK) GetPayload() *GetAttributesAttributeCodeOptionsCodeOKBody {
	return o.Payload
}

func (o *GetAttributesAttributeCodeOptionsCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAttributesAttributeCodeOptionsCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAttributesAttributeCodeOptionsCodeUnauthorized creates a GetAttributesAttributeCodeOptionsCodeUnauthorized with default headers values
func NewGetAttributesAttributeCodeOptionsCodeUnauthorized() *GetAttributesAttributeCodeOptionsCodeUnauthorized {
	return &GetAttributesAttributeCodeOptionsCodeUnauthorized{}
}

/*GetAttributesAttributeCodeOptionsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetAttributesAttributeCodeOptionsCodeUnauthorized struct {
	Payload *GetAttributesAttributeCodeOptionsCodeUnauthorizedBody
}

func (o *GetAttributesAttributeCodeOptionsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/attributes/{attribute_code}/options/{code}][%d] getAttributesAttributeCodeOptionsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAttributesAttributeCodeOptionsCodeUnauthorized) GetPayload() *GetAttributesAttributeCodeOptionsCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetAttributesAttributeCodeOptionsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAttributesAttributeCodeOptionsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAttributesAttributeCodeOptionsCodeForbidden creates a GetAttributesAttributeCodeOptionsCodeForbidden with default headers values
func NewGetAttributesAttributeCodeOptionsCodeForbidden() *GetAttributesAttributeCodeOptionsCodeForbidden {
	return &GetAttributesAttributeCodeOptionsCodeForbidden{}
}

/*GetAttributesAttributeCodeOptionsCodeForbidden handles this case with default header values.

Access forbidden
*/
type GetAttributesAttributeCodeOptionsCodeForbidden struct {
	Payload *GetAttributesAttributeCodeOptionsCodeForbiddenBody
}

func (o *GetAttributesAttributeCodeOptionsCodeForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/attributes/{attribute_code}/options/{code}][%d] getAttributesAttributeCodeOptionsCodeForbidden  %+v", 403, o.Payload)
}

func (o *GetAttributesAttributeCodeOptionsCodeForbidden) GetPayload() *GetAttributesAttributeCodeOptionsCodeForbiddenBody {
	return o.Payload
}

func (o *GetAttributesAttributeCodeOptionsCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAttributesAttributeCodeOptionsCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAttributesAttributeCodeOptionsCodeNotFound creates a GetAttributesAttributeCodeOptionsCodeNotFound with default headers values
func NewGetAttributesAttributeCodeOptionsCodeNotFound() *GetAttributesAttributeCodeOptionsCodeNotFound {
	return &GetAttributesAttributeCodeOptionsCodeNotFound{}
}

/*GetAttributesAttributeCodeOptionsCodeNotFound handles this case with default header values.

Resource not found
*/
type GetAttributesAttributeCodeOptionsCodeNotFound struct {
	Payload *GetAttributesAttributeCodeOptionsCodeNotFoundBody
}

func (o *GetAttributesAttributeCodeOptionsCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/attributes/{attribute_code}/options/{code}][%d] getAttributesAttributeCodeOptionsCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetAttributesAttributeCodeOptionsCodeNotFound) GetPayload() *GetAttributesAttributeCodeOptionsCodeNotFoundBody {
	return o.Payload
}

func (o *GetAttributesAttributeCodeOptionsCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAttributesAttributeCodeOptionsCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAttributesAttributeCodeOptionsCodeNotAcceptable creates a GetAttributesAttributeCodeOptionsCodeNotAcceptable with default headers values
func NewGetAttributesAttributeCodeOptionsCodeNotAcceptable() *GetAttributesAttributeCodeOptionsCodeNotAcceptable {
	return &GetAttributesAttributeCodeOptionsCodeNotAcceptable{}
}

/*GetAttributesAttributeCodeOptionsCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetAttributesAttributeCodeOptionsCodeNotAcceptable struct {
	Payload *GetAttributesAttributeCodeOptionsCodeNotAcceptableBody
}

func (o *GetAttributesAttributeCodeOptionsCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/attributes/{attribute_code}/options/{code}][%d] getAttributesAttributeCodeOptionsCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetAttributesAttributeCodeOptionsCodeNotAcceptable) GetPayload() *GetAttributesAttributeCodeOptionsCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetAttributesAttributeCodeOptionsCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAttributesAttributeCodeOptionsCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetAttributesAttributeCodeOptionsCodeForbiddenBody get attributes attribute code options code forbidden body
swagger:model GetAttributesAttributeCodeOptionsCodeForbiddenBody
*/
type GetAttributesAttributeCodeOptionsCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get attributes attribute code options code forbidden body
func (o *GetAttributesAttributeCodeOptionsCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetAttributesAttributeCodeOptionsCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAttributesAttributeCodeOptionsCodeNotAcceptableBody get attributes attribute code options code not acceptable body
swagger:model GetAttributesAttributeCodeOptionsCodeNotAcceptableBody
*/
type GetAttributesAttributeCodeOptionsCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get attributes attribute code options code not acceptable body
func (o *GetAttributesAttributeCodeOptionsCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetAttributesAttributeCodeOptionsCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAttributesAttributeCodeOptionsCodeNotFoundBody get attributes attribute code options code not found body
swagger:model GetAttributesAttributeCodeOptionsCodeNotFoundBody
*/
type GetAttributesAttributeCodeOptionsCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get attributes attribute code options code not found body
func (o *GetAttributesAttributeCodeOptionsCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetAttributesAttributeCodeOptionsCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAttributesAttributeCodeOptionsCodeOKBody get attributes attribute code options code o k body
swagger:model GetAttributesAttributeCodeOptionsCodeOKBody
*/
type GetAttributesAttributeCodeOptionsCodeOKBody struct {

	// Code of attribute related to the attribute option
	Attribute string `json:"attribute,omitempty"`

	// Code of option
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *GetAttributesAttributeCodeOptionsCodeOKBodyLabels `json:"labels,omitempty"`

	// Order of attribute option
	SortOrder int64 `json:"sort_order,omitempty"`
}

// Validate validates this get attributes attribute code options code o k body
func (o *GetAttributesAttributeCodeOptionsCodeOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetAttributesAttributeCodeOptionsCodeOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("getAttributesAttributeCodeOptionsCodeOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetAttributesAttributeCodeOptionsCodeOKBody) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getAttributesAttributeCodeOptionsCodeOK" + "." + "labels")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetAttributesAttributeCodeOptionsCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAttributesAttributeCodeOptionsCodeOKBodyLabels Attribute option labels for each locale
swagger:model GetAttributesAttributeCodeOptionsCodeOKBodyLabels
*/
type GetAttributesAttributeCodeOptionsCodeOKBodyLabels struct {

	// Attribute option label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this get attributes attribute code options code o k body labels
func (o *GetAttributesAttributeCodeOptionsCodeOKBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeOKBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeOKBodyLabels) UnmarshalBinary(b []byte) error {
	var res GetAttributesAttributeCodeOptionsCodeOKBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAttributesAttributeCodeOptionsCodeUnauthorizedBody get attributes attribute code options code unauthorized body
swagger:model GetAttributesAttributeCodeOptionsCodeUnauthorizedBody
*/
type GetAttributesAttributeCodeOptionsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get attributes attribute code options code unauthorized body
func (o *GetAttributesAttributeCodeOptionsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAttributesAttributeCodeOptionsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetAttributesAttributeCodeOptionsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
