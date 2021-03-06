// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_attribute_option

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

// GetReferenceEntityAttributesAttributeCodeOptionsCodeReader is a Reader for the GetReferenceEntityAttributesAttributeCodeOptionsCode structure.
type GetReferenceEntityAttributesAttributeCodeOptionsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetReferenceEntityAttributesAttributeCodeOptionsCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeOK creates a GetReferenceEntityAttributesAttributeCodeOptionsCodeOK with default headers values
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeOK() *GetReferenceEntityAttributesAttributeCodeOptionsCodeOK {
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeOK{}
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeOK handles this case with default header values.

OK
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeOK struct {
	Payload *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] getReferenceEntityAttributesAttributeCodeOptionsCodeOK  %+v", 200, o.Payload)
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOK) GetPayload() *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized creates a GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized with default headers values
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized() *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized {
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized{}
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized struct {
	Payload *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] getReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized) GetPayload() *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound creates a GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound with default headers values
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound() *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound {
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound{}
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound handles this case with default header values.

Resource not found
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound struct {
	Payload *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] getReferenceEntityAttributesAttributeCodeOptionsCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound) GetPayload() *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable creates a GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable with default headers values
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable() *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable {
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable{}
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable struct {
	Payload *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] getReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable) GetPayload() *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody get reference entity attributes attribute code options code not acceptable body
swagger:model GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity attributes attribute code options code not acceptable body
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesAttributeCodeOptionsCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody get reference entity attributes attribute code options code not found body
swagger:model GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity attributes attribute code options code not found body
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesAttributeCodeOptionsCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody get reference entity attributes attribute code options code o k body
swagger:model GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody struct {

	// Attribute's option code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels `json:"labels,omitempty"`
}

// Validate validates this get reference entity attributes attribute code options code o k body
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody) Validate(formats strfmt.Registry) error {
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

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("getReferenceEntityAttributesAttributeCodeOptionsCodeOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityAttributesAttributeCodeOptionsCodeOK" + "." + "labels")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels Attribute labels for each locale
swagger:model GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this get reference entity attributes attribute code options code o k body labels
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesAttributeCodeOptionsCodeOKBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody get reference entity attributes attribute code options code unauthorized body
swagger:model GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity attributes attribute code options code unauthorized body
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
