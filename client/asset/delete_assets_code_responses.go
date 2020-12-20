// Code generated by go-swagger; DO NOT EDIT.

package asset

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DeleteAssetsCodeReader is a Reader for the DeleteAssetsCode structure.
type DeleteAssetsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAssetsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteAssetsCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteAssetsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteAssetsCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteAssetsCodeNoContent creates a DeleteAssetsCodeNoContent with default headers values
func NewDeleteAssetsCodeNoContent() *DeleteAssetsCodeNoContent {
	return &DeleteAssetsCodeNoContent{}
}

/*DeleteAssetsCodeNoContent handles this case with default header values.

No content to return
*/
type DeleteAssetsCodeNoContent struct {
}

func (o *DeleteAssetsCodeNoContent) Error() string {
	return fmt.Sprintf("[DELETE /api/rest/v1/asset-families/{asset_family_code}/assets/{code}][%d] deleteAssetsCodeNoContent ", 204)
}

func (o *DeleteAssetsCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteAssetsCodeUnauthorized creates a DeleteAssetsCodeUnauthorized with default headers values
func NewDeleteAssetsCodeUnauthorized() *DeleteAssetsCodeUnauthorized {
	return &DeleteAssetsCodeUnauthorized{}
}

/*DeleteAssetsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type DeleteAssetsCodeUnauthorized struct {
	Payload *DeleteAssetsCodeUnauthorizedBody
}

func (o *DeleteAssetsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /api/rest/v1/asset-families/{asset_family_code}/assets/{code}][%d] deleteAssetsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteAssetsCodeUnauthorized) GetPayload() *DeleteAssetsCodeUnauthorizedBody {
	return o.Payload
}

func (o *DeleteAssetsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(DeleteAssetsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetsCodeNotFound creates a DeleteAssetsCodeNotFound with default headers values
func NewDeleteAssetsCodeNotFound() *DeleteAssetsCodeNotFound {
	return &DeleteAssetsCodeNotFound{}
}

/*DeleteAssetsCodeNotFound handles this case with default header values.

Resource not found
*/
type DeleteAssetsCodeNotFound struct {
	Payload *DeleteAssetsCodeNotFoundBody
}

func (o *DeleteAssetsCodeNotFound) Error() string {
	return fmt.Sprintf("[DELETE /api/rest/v1/asset-families/{asset_family_code}/assets/{code}][%d] deleteAssetsCodeNotFound  %+v", 404, o.Payload)
}

func (o *DeleteAssetsCodeNotFound) GetPayload() *DeleteAssetsCodeNotFoundBody {
	return o.Payload
}

func (o *DeleteAssetsCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(DeleteAssetsCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*DeleteAssetsCodeNotFoundBody delete assets code not found body
swagger:model DeleteAssetsCodeNotFoundBody
*/
type DeleteAssetsCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this delete assets code not found body
func (o *DeleteAssetsCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *DeleteAssetsCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *DeleteAssetsCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res DeleteAssetsCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*DeleteAssetsCodeUnauthorizedBody delete assets code unauthorized body
swagger:model DeleteAssetsCodeUnauthorizedBody
*/
type DeleteAssetsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this delete assets code unauthorized body
func (o *DeleteAssetsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *DeleteAssetsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *DeleteAssetsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res DeleteAssetsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
