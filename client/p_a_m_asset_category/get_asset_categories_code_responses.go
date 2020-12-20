// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset_category

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

// GetAssetCategoriesCodeReader is a Reader for the GetAssetCategoriesCode structure.
type GetAssetCategoriesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAssetCategoriesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAssetCategoriesCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAssetCategoriesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAssetCategoriesCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAssetCategoriesCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetAssetCategoriesCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAssetCategoriesCodeOK creates a GetAssetCategoriesCodeOK with default headers values
func NewGetAssetCategoriesCodeOK() *GetAssetCategoriesCodeOK {
	return &GetAssetCategoriesCodeOK{}
}

/*GetAssetCategoriesCodeOK handles this case with default header values.

OK
*/
type GetAssetCategoriesCodeOK struct {
	Payload *GetAssetCategoriesCodeOKBody
}

func (o *GetAssetCategoriesCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-categories/{code}][%d] getAssetCategoriesCodeOK  %+v", 200, o.Payload)
}

func (o *GetAssetCategoriesCodeOK) GetPayload() *GetAssetCategoriesCodeOKBody {
	return o.Payload
}

func (o *GetAssetCategoriesCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetCategoriesCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetCategoriesCodeUnauthorized creates a GetAssetCategoriesCodeUnauthorized with default headers values
func NewGetAssetCategoriesCodeUnauthorized() *GetAssetCategoriesCodeUnauthorized {
	return &GetAssetCategoriesCodeUnauthorized{}
}

/*GetAssetCategoriesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetAssetCategoriesCodeUnauthorized struct {
	Payload *GetAssetCategoriesCodeUnauthorizedBody
}

func (o *GetAssetCategoriesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-categories/{code}][%d] getAssetCategoriesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAssetCategoriesCodeUnauthorized) GetPayload() *GetAssetCategoriesCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetAssetCategoriesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetCategoriesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetCategoriesCodeForbidden creates a GetAssetCategoriesCodeForbidden with default headers values
func NewGetAssetCategoriesCodeForbidden() *GetAssetCategoriesCodeForbidden {
	return &GetAssetCategoriesCodeForbidden{}
}

/*GetAssetCategoriesCodeForbidden handles this case with default header values.

Access forbidden
*/
type GetAssetCategoriesCodeForbidden struct {
	Payload *GetAssetCategoriesCodeForbiddenBody
}

func (o *GetAssetCategoriesCodeForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-categories/{code}][%d] getAssetCategoriesCodeForbidden  %+v", 403, o.Payload)
}

func (o *GetAssetCategoriesCodeForbidden) GetPayload() *GetAssetCategoriesCodeForbiddenBody {
	return o.Payload
}

func (o *GetAssetCategoriesCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetCategoriesCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetCategoriesCodeNotFound creates a GetAssetCategoriesCodeNotFound with default headers values
func NewGetAssetCategoriesCodeNotFound() *GetAssetCategoriesCodeNotFound {
	return &GetAssetCategoriesCodeNotFound{}
}

/*GetAssetCategoriesCodeNotFound handles this case with default header values.

Resource not found
*/
type GetAssetCategoriesCodeNotFound struct {
	Payload *GetAssetCategoriesCodeNotFoundBody
}

func (o *GetAssetCategoriesCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-categories/{code}][%d] getAssetCategoriesCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetAssetCategoriesCodeNotFound) GetPayload() *GetAssetCategoriesCodeNotFoundBody {
	return o.Payload
}

func (o *GetAssetCategoriesCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetCategoriesCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetCategoriesCodeNotAcceptable creates a GetAssetCategoriesCodeNotAcceptable with default headers values
func NewGetAssetCategoriesCodeNotAcceptable() *GetAssetCategoriesCodeNotAcceptable {
	return &GetAssetCategoriesCodeNotAcceptable{}
}

/*GetAssetCategoriesCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetAssetCategoriesCodeNotAcceptable struct {
	Payload *GetAssetCategoriesCodeNotAcceptableBody
}

func (o *GetAssetCategoriesCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/asset-categories/{code}][%d] getAssetCategoriesCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetAssetCategoriesCodeNotAcceptable) GetPayload() *GetAssetCategoriesCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetAssetCategoriesCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetAssetCategoriesCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetAssetCategoriesCodeForbiddenBody get asset categories code forbidden body
swagger:model GetAssetCategoriesCodeForbiddenBody
*/
type GetAssetCategoriesCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get asset categories code forbidden body
func (o *GetAssetCategoriesCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetCategoriesCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetCategoriesCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetAssetCategoriesCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetCategoriesCodeNotAcceptableBody get asset categories code not acceptable body
swagger:model GetAssetCategoriesCodeNotAcceptableBody
*/
type GetAssetCategoriesCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get asset categories code not acceptable body
func (o *GetAssetCategoriesCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetCategoriesCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetCategoriesCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetAssetCategoriesCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetCategoriesCodeNotFoundBody get asset categories code not found body
swagger:model GetAssetCategoriesCodeNotFoundBody
*/
type GetAssetCategoriesCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get asset categories code not found body
func (o *GetAssetCategoriesCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetCategoriesCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetCategoriesCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetAssetCategoriesCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetCategoriesCodeOKBody get asset categories code o k body
swagger:model GetAssetCategoriesCodeOKBody
*/
type GetAssetCategoriesCodeOKBody struct {

	// PAM asset category code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *GetAssetCategoriesCodeOKBodyLabels `json:"labels,omitempty"`

	// PAM ssset category code of the parent's asset category
	Parent *string `json:"parent,omitempty"`
}

// Validate validates this get asset categories code o k body
func (o *GetAssetCategoriesCodeOKBody) Validate(formats strfmt.Registry) error {
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

func (o *GetAssetCategoriesCodeOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("getAssetCategoriesCodeOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetAssetCategoriesCodeOKBody) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getAssetCategoriesCodeOK" + "." + "labels")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetCategoriesCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetCategoriesCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetAssetCategoriesCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetCategoriesCodeOKBodyLabels PAM asset category labels for each locale
swagger:model GetAssetCategoriesCodeOKBodyLabels
*/
type GetAssetCategoriesCodeOKBodyLabels struct {

	// PAM asset category label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this get asset categories code o k body labels
func (o *GetAssetCategoriesCodeOKBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetCategoriesCodeOKBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetCategoriesCodeOKBodyLabels) UnmarshalBinary(b []byte) error {
	var res GetAssetCategoriesCodeOKBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetAssetCategoriesCodeUnauthorizedBody get asset categories code unauthorized body
swagger:model GetAssetCategoriesCodeUnauthorizedBody
*/
type GetAssetCategoriesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get asset categories code unauthorized body
func (o *GetAssetCategoriesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetAssetCategoriesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetAssetCategoriesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetAssetCategoriesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
