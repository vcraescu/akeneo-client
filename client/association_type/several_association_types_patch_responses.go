// Code generated by go-swagger; DO NOT EDIT.

package association_type

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

// SeveralAssociationTypesPatchReader is a Reader for the SeveralAssociationTypesPatch structure.
type SeveralAssociationTypesPatchReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SeveralAssociationTypesPatchReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSeveralAssociationTypesPatchOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSeveralAssociationTypesPatchUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSeveralAssociationTypesPatchForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 413:
		result := NewSeveralAssociationTypesPatchRequestEntityTooLarge()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewSeveralAssociationTypesPatchUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSeveralAssociationTypesPatchOK creates a SeveralAssociationTypesPatchOK with default headers values
func NewSeveralAssociationTypesPatchOK() *SeveralAssociationTypesPatchOK {
	return &SeveralAssociationTypesPatchOK{}
}

/*SeveralAssociationTypesPatchOK handles this case with default header values.

OK
*/
type SeveralAssociationTypesPatchOK struct {
	Payload *SeveralAssociationTypesPatchOKBody
}

func (o *SeveralAssociationTypesPatchOK) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/association-types][%d] severalAssociationTypesPatchOK  %+v", 200, o.Payload)
}

func (o *SeveralAssociationTypesPatchOK) GetPayload() *SeveralAssociationTypesPatchOKBody {
	return o.Payload
}

func (o *SeveralAssociationTypesPatchOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralAssociationTypesPatchOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralAssociationTypesPatchUnauthorized creates a SeveralAssociationTypesPatchUnauthorized with default headers values
func NewSeveralAssociationTypesPatchUnauthorized() *SeveralAssociationTypesPatchUnauthorized {
	return &SeveralAssociationTypesPatchUnauthorized{}
}

/*SeveralAssociationTypesPatchUnauthorized handles this case with default header values.

Authentication required
*/
type SeveralAssociationTypesPatchUnauthorized struct {
	Payload *SeveralAssociationTypesPatchUnauthorizedBody
}

func (o *SeveralAssociationTypesPatchUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/association-types][%d] severalAssociationTypesPatchUnauthorized  %+v", 401, o.Payload)
}

func (o *SeveralAssociationTypesPatchUnauthorized) GetPayload() *SeveralAssociationTypesPatchUnauthorizedBody {
	return o.Payload
}

func (o *SeveralAssociationTypesPatchUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralAssociationTypesPatchUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralAssociationTypesPatchForbidden creates a SeveralAssociationTypesPatchForbidden with default headers values
func NewSeveralAssociationTypesPatchForbidden() *SeveralAssociationTypesPatchForbidden {
	return &SeveralAssociationTypesPatchForbidden{}
}

/*SeveralAssociationTypesPatchForbidden handles this case with default header values.

Access forbidden
*/
type SeveralAssociationTypesPatchForbidden struct {
	Payload *SeveralAssociationTypesPatchForbiddenBody
}

func (o *SeveralAssociationTypesPatchForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/association-types][%d] severalAssociationTypesPatchForbidden  %+v", 403, o.Payload)
}

func (o *SeveralAssociationTypesPatchForbidden) GetPayload() *SeveralAssociationTypesPatchForbiddenBody {
	return o.Payload
}

func (o *SeveralAssociationTypesPatchForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralAssociationTypesPatchForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralAssociationTypesPatchRequestEntityTooLarge creates a SeveralAssociationTypesPatchRequestEntityTooLarge with default headers values
func NewSeveralAssociationTypesPatchRequestEntityTooLarge() *SeveralAssociationTypesPatchRequestEntityTooLarge {
	return &SeveralAssociationTypesPatchRequestEntityTooLarge{}
}

/*SeveralAssociationTypesPatchRequestEntityTooLarge handles this case with default header values.

Request Entity Too Large
*/
type SeveralAssociationTypesPatchRequestEntityTooLarge struct {
	Payload *SeveralAssociationTypesPatchRequestEntityTooLargeBody
}

func (o *SeveralAssociationTypesPatchRequestEntityTooLarge) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/association-types][%d] severalAssociationTypesPatchRequestEntityTooLarge  %+v", 413, o.Payload)
}

func (o *SeveralAssociationTypesPatchRequestEntityTooLarge) GetPayload() *SeveralAssociationTypesPatchRequestEntityTooLargeBody {
	return o.Payload
}

func (o *SeveralAssociationTypesPatchRequestEntityTooLarge) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralAssociationTypesPatchRequestEntityTooLargeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeveralAssociationTypesPatchUnsupportedMediaType creates a SeveralAssociationTypesPatchUnsupportedMediaType with default headers values
func NewSeveralAssociationTypesPatchUnsupportedMediaType() *SeveralAssociationTypesPatchUnsupportedMediaType {
	return &SeveralAssociationTypesPatchUnsupportedMediaType{}
}

/*SeveralAssociationTypesPatchUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type SeveralAssociationTypesPatchUnsupportedMediaType struct {
	Payload *SeveralAssociationTypesPatchUnsupportedMediaTypeBody
}

func (o *SeveralAssociationTypesPatchUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/association-types][%d] severalAssociationTypesPatchUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *SeveralAssociationTypesPatchUnsupportedMediaType) GetPayload() *SeveralAssociationTypesPatchUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *SeveralAssociationTypesPatchUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SeveralAssociationTypesPatchUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*SeveralAssociationTypesPatchBody several association types patch body
swagger:model SeveralAssociationTypesPatchBody
*/
type SeveralAssociationTypesPatchBody struct {

	// Association type code
	// Required: true
	Code *string `json:"code"`

	// When true, the association is a quantified association
	IsQuantified *bool `json:"is_quantified,omitempty"`

	// When true, the association is a two-way association
	IsTwoWay *bool `json:"is_two_way,omitempty"`

	// labels
	Labels *SeveralAssociationTypesPatchParamsBodyLabels `json:"labels,omitempty"`
}

// Validate validates this several association types patch body
func (o *SeveralAssociationTypesPatchBody) Validate(formats strfmt.Registry) error {
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

func (o *SeveralAssociationTypesPatchBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *SeveralAssociationTypesPatchBody) validateLabels(formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchBody) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralAssociationTypesPatchForbiddenBody several association types patch forbidden body
swagger:model SeveralAssociationTypesPatchForbiddenBody
*/
type SeveralAssociationTypesPatchForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several association types patch forbidden body
func (o *SeveralAssociationTypesPatchForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchForbiddenBody) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralAssociationTypesPatchOKBody several association types patch o k body
swagger:model SeveralAssociationTypesPatchOKBody
*/
type SeveralAssociationTypesPatchOKBody struct {

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

// Validate validates this several association types patch o k body
func (o *SeveralAssociationTypesPatchOKBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchOKBody) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralAssociationTypesPatchParamsBodyLabels Association type labels for each locale
swagger:model SeveralAssociationTypesPatchParamsBodyLabels
*/
type SeveralAssociationTypesPatchParamsBodyLabels struct {

	// Association type label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this several association types patch params body labels
func (o *SeveralAssociationTypesPatchParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralAssociationTypesPatchRequestEntityTooLargeBody several association types patch request entity too large body
swagger:model SeveralAssociationTypesPatchRequestEntityTooLargeBody
*/
type SeveralAssociationTypesPatchRequestEntityTooLargeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several association types patch request entity too large body
func (o *SeveralAssociationTypesPatchRequestEntityTooLargeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchRequestEntityTooLargeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchRequestEntityTooLargeBody) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchRequestEntityTooLargeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralAssociationTypesPatchUnauthorizedBody several association types patch unauthorized body
swagger:model SeveralAssociationTypesPatchUnauthorizedBody
*/
type SeveralAssociationTypesPatchUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several association types patch unauthorized body
func (o *SeveralAssociationTypesPatchUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*SeveralAssociationTypesPatchUnsupportedMediaTypeBody several association types patch unsupported media type body
swagger:model SeveralAssociationTypesPatchUnsupportedMediaTypeBody
*/
type SeveralAssociationTypesPatchUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this several association types patch unsupported media type body
func (o *SeveralAssociationTypesPatchUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SeveralAssociationTypesPatchUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res SeveralAssociationTypesPatchUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
