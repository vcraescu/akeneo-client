// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_media_file

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GetReferenceEntityMediaFilesCodeReader is a Reader for the GetReferenceEntityMediaFilesCode structure.
type GetReferenceEntityMediaFilesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetReferenceEntityMediaFilesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetReferenceEntityMediaFilesCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetReferenceEntityMediaFilesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetReferenceEntityMediaFilesCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetReferenceEntityMediaFilesCodeOK creates a GetReferenceEntityMediaFilesCodeOK with default headers values
func NewGetReferenceEntityMediaFilesCodeOK() *GetReferenceEntityMediaFilesCodeOK {
	return &GetReferenceEntityMediaFilesCodeOK{}
}

/*GetReferenceEntityMediaFilesCodeOK handles this case with default header values.

OK
*/
type GetReferenceEntityMediaFilesCodeOK struct {
}

func (o *GetReferenceEntityMediaFilesCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities-media-files/{code}][%d] getReferenceEntityMediaFilesCodeOK ", 200)
}

func (o *GetReferenceEntityMediaFilesCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetReferenceEntityMediaFilesCodeUnauthorized creates a GetReferenceEntityMediaFilesCodeUnauthorized with default headers values
func NewGetReferenceEntityMediaFilesCodeUnauthorized() *GetReferenceEntityMediaFilesCodeUnauthorized {
	return &GetReferenceEntityMediaFilesCodeUnauthorized{}
}

/*GetReferenceEntityMediaFilesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetReferenceEntityMediaFilesCodeUnauthorized struct {
	Payload *GetReferenceEntityMediaFilesCodeUnauthorizedBody
}

func (o *GetReferenceEntityMediaFilesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities-media-files/{code}][%d] getReferenceEntityMediaFilesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetReferenceEntityMediaFilesCodeUnauthorized) GetPayload() *GetReferenceEntityMediaFilesCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetReferenceEntityMediaFilesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityMediaFilesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityMediaFilesCodeNotFound creates a GetReferenceEntityMediaFilesCodeNotFound with default headers values
func NewGetReferenceEntityMediaFilesCodeNotFound() *GetReferenceEntityMediaFilesCodeNotFound {
	return &GetReferenceEntityMediaFilesCodeNotFound{}
}

/*GetReferenceEntityMediaFilesCodeNotFound handles this case with default header values.

Resource not found
*/
type GetReferenceEntityMediaFilesCodeNotFound struct {
	Payload *GetReferenceEntityMediaFilesCodeNotFoundBody
}

func (o *GetReferenceEntityMediaFilesCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities-media-files/{code}][%d] getReferenceEntityMediaFilesCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetReferenceEntityMediaFilesCodeNotFound) GetPayload() *GetReferenceEntityMediaFilesCodeNotFoundBody {
	return o.Payload
}

func (o *GetReferenceEntityMediaFilesCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityMediaFilesCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetReferenceEntityMediaFilesCodeNotFoundBody get reference entity media files code not found body
swagger:model GetReferenceEntityMediaFilesCodeNotFoundBody
*/
type GetReferenceEntityMediaFilesCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity media files code not found body
func (o *GetReferenceEntityMediaFilesCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityMediaFilesCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityMediaFilesCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityMediaFilesCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityMediaFilesCodeUnauthorizedBody get reference entity media files code unauthorized body
swagger:model GetReferenceEntityMediaFilesCodeUnauthorizedBody
*/
type GetReferenceEntityMediaFilesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity media files code unauthorized body
func (o *GetReferenceEntityMediaFilesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityMediaFilesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityMediaFilesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityMediaFilesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}