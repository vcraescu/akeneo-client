// Code generated by go-swagger; DO NOT EDIT.

package measure_family

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// MeasureFamiliesGetReader is a Reader for the MeasureFamiliesGet structure.
type MeasureFamiliesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MeasureFamiliesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMeasureFamiliesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewMeasureFamiliesGetUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewMeasureFamiliesGetForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewMeasureFamiliesGetNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewMeasureFamiliesGetNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewMeasureFamiliesGetOK creates a MeasureFamiliesGetOK with default headers values
func NewMeasureFamiliesGetOK() *MeasureFamiliesGetOK {
	return &MeasureFamiliesGetOK{}
}

/*MeasureFamiliesGetOK handles this case with default header values.

OK
*/
type MeasureFamiliesGetOK struct {
	Payload *MeasureFamiliesGetOKBody
}

func (o *MeasureFamiliesGetOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/measure-families/{code}][%d] measureFamiliesGetOK  %+v", 200, o.Payload)
}

func (o *MeasureFamiliesGetOK) GetPayload() *MeasureFamiliesGetOKBody {
	return o.Payload
}

func (o *MeasureFamiliesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(MeasureFamiliesGetOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMeasureFamiliesGetUnauthorized creates a MeasureFamiliesGetUnauthorized with default headers values
func NewMeasureFamiliesGetUnauthorized() *MeasureFamiliesGetUnauthorized {
	return &MeasureFamiliesGetUnauthorized{}
}

/*MeasureFamiliesGetUnauthorized handles this case with default header values.

Authentication required
*/
type MeasureFamiliesGetUnauthorized struct {
	Payload *MeasureFamiliesGetUnauthorizedBody
}

func (o *MeasureFamiliesGetUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/measure-families/{code}][%d] measureFamiliesGetUnauthorized  %+v", 401, o.Payload)
}

func (o *MeasureFamiliesGetUnauthorized) GetPayload() *MeasureFamiliesGetUnauthorizedBody {
	return o.Payload
}

func (o *MeasureFamiliesGetUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(MeasureFamiliesGetUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMeasureFamiliesGetForbidden creates a MeasureFamiliesGetForbidden with default headers values
func NewMeasureFamiliesGetForbidden() *MeasureFamiliesGetForbidden {
	return &MeasureFamiliesGetForbidden{}
}

/*MeasureFamiliesGetForbidden handles this case with default header values.

Access forbidden
*/
type MeasureFamiliesGetForbidden struct {
	Payload *MeasureFamiliesGetForbiddenBody
}

func (o *MeasureFamiliesGetForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/measure-families/{code}][%d] measureFamiliesGetForbidden  %+v", 403, o.Payload)
}

func (o *MeasureFamiliesGetForbidden) GetPayload() *MeasureFamiliesGetForbiddenBody {
	return o.Payload
}

func (o *MeasureFamiliesGetForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(MeasureFamiliesGetForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMeasureFamiliesGetNotFound creates a MeasureFamiliesGetNotFound with default headers values
func NewMeasureFamiliesGetNotFound() *MeasureFamiliesGetNotFound {
	return &MeasureFamiliesGetNotFound{}
}

/*MeasureFamiliesGetNotFound handles this case with default header values.

Resource not found
*/
type MeasureFamiliesGetNotFound struct {
	Payload *MeasureFamiliesGetNotFoundBody
}

func (o *MeasureFamiliesGetNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/measure-families/{code}][%d] measureFamiliesGetNotFound  %+v", 404, o.Payload)
}

func (o *MeasureFamiliesGetNotFound) GetPayload() *MeasureFamiliesGetNotFoundBody {
	return o.Payload
}

func (o *MeasureFamiliesGetNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(MeasureFamiliesGetNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMeasureFamiliesGetNotAcceptable creates a MeasureFamiliesGetNotAcceptable with default headers values
func NewMeasureFamiliesGetNotAcceptable() *MeasureFamiliesGetNotAcceptable {
	return &MeasureFamiliesGetNotAcceptable{}
}

/*MeasureFamiliesGetNotAcceptable handles this case with default header values.

Not Acceptable
*/
type MeasureFamiliesGetNotAcceptable struct {
	Payload *MeasureFamiliesGetNotAcceptableBody
}

func (o *MeasureFamiliesGetNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/measure-families/{code}][%d] measureFamiliesGetNotAcceptable  %+v", 406, o.Payload)
}

func (o *MeasureFamiliesGetNotAcceptable) GetPayload() *MeasureFamiliesGetNotAcceptableBody {
	return o.Payload
}

func (o *MeasureFamiliesGetNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(MeasureFamiliesGetNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*MeasureFamiliesGetForbiddenBody measure families get forbidden body
swagger:model MeasureFamiliesGetForbiddenBody
*/
type MeasureFamiliesGetForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this measure families get forbidden body
func (o *MeasureFamiliesGetForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *MeasureFamiliesGetForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *MeasureFamiliesGetForbiddenBody) UnmarshalBinary(b []byte) error {
	var res MeasureFamiliesGetForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*MeasureFamiliesGetNotAcceptableBody measure families get not acceptable body
swagger:model MeasureFamiliesGetNotAcceptableBody
*/
type MeasureFamiliesGetNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this measure families get not acceptable body
func (o *MeasureFamiliesGetNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *MeasureFamiliesGetNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *MeasureFamiliesGetNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res MeasureFamiliesGetNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*MeasureFamiliesGetNotFoundBody measure families get not found body
swagger:model MeasureFamiliesGetNotFoundBody
*/
type MeasureFamiliesGetNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this measure families get not found body
func (o *MeasureFamiliesGetNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *MeasureFamiliesGetNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *MeasureFamiliesGetNotFoundBody) UnmarshalBinary(b []byte) error {
	var res MeasureFamiliesGetNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*MeasureFamiliesGetOKBody measure families get o k body
swagger:model MeasureFamiliesGetOKBody
*/
type MeasureFamiliesGetOKBody struct {

	// Measure family code
	// Required: true
	Code *string `json:"code"`

	// Measure family standard
	Standard string `json:"standard,omitempty"`

	// Family units
	Units []*MeasureFamiliesGetOKBodyUnitsItems0 `json:"units"`
}

// Validate validates this measure families get o k body
func (o *MeasureFamiliesGetOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateUnits(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *MeasureFamiliesGetOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("measureFamiliesGetOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *MeasureFamiliesGetOKBody) validateUnits(formats strfmt.Registry) error {

	if swag.IsZero(o.Units) { // not required
		return nil
	}

	for i := 0; i < len(o.Units); i++ {
		if swag.IsZero(o.Units[i]) { // not required
			continue
		}

		if o.Units[i] != nil {
			if err := o.Units[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("measureFamiliesGetOK" + "." + "units" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *MeasureFamiliesGetOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *MeasureFamiliesGetOKBody) UnmarshalBinary(b []byte) error {
	var res MeasureFamiliesGetOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*MeasureFamiliesGetOKBodyUnitsItems0 measure families get o k body units items0
swagger:model MeasureFamiliesGetOKBodyUnitsItems0
*/
type MeasureFamiliesGetOKBodyUnitsItems0 struct {

	// Measure code
	Code string `json:"code,omitempty"`

	// Mathematic operation to convert the unit into the standard unit
	Convert interface{} `json:"convert,omitempty"`

	// Measure symbol
	Symbol string `json:"symbol,omitempty"`
}

// Validate validates this measure families get o k body units items0
func (o *MeasureFamiliesGetOKBodyUnitsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *MeasureFamiliesGetOKBodyUnitsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *MeasureFamiliesGetOKBodyUnitsItems0) UnmarshalBinary(b []byte) error {
	var res MeasureFamiliesGetOKBodyUnitsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*MeasureFamiliesGetUnauthorizedBody measure families get unauthorized body
swagger:model MeasureFamiliesGetUnauthorizedBody
*/
type MeasureFamiliesGetUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this measure families get unauthorized body
func (o *MeasureFamiliesGetUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *MeasureFamiliesGetUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *MeasureFamiliesGetUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res MeasureFamiliesGetUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}