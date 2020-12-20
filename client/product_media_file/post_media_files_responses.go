// Code generated by go-swagger; DO NOT EDIT.

package product_media_file

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

// PostMediaFilesReader is a Reader for the PostMediaFiles structure.
type PostMediaFilesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostMediaFilesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostMediaFilesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostMediaFilesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostMediaFilesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostMediaFilesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPostMediaFilesUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPostMediaFilesUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostMediaFilesCreated creates a PostMediaFilesCreated with default headers values
func NewPostMediaFilesCreated() *PostMediaFilesCreated {
	return &PostMediaFilesCreated{}
}

/*PostMediaFilesCreated handles this case with default header values.

Created
*/
type PostMediaFilesCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PostMediaFilesCreated) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/media-files][%d] postMediaFilesCreated ", 201)
}

func (o *PostMediaFilesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPostMediaFilesBadRequest creates a PostMediaFilesBadRequest with default headers values
func NewPostMediaFilesBadRequest() *PostMediaFilesBadRequest {
	return &PostMediaFilesBadRequest{}
}

/*PostMediaFilesBadRequest handles this case with default header values.

Bad request
*/
type PostMediaFilesBadRequest struct {
	Payload *PostMediaFilesBadRequestBody
}

func (o *PostMediaFilesBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/media-files][%d] postMediaFilesBadRequest  %+v", 400, o.Payload)
}

func (o *PostMediaFilesBadRequest) GetPayload() *PostMediaFilesBadRequestBody {
	return o.Payload
}

func (o *PostMediaFilesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostMediaFilesBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMediaFilesUnauthorized creates a PostMediaFilesUnauthorized with default headers values
func NewPostMediaFilesUnauthorized() *PostMediaFilesUnauthorized {
	return &PostMediaFilesUnauthorized{}
}

/*PostMediaFilesUnauthorized handles this case with default header values.

Authentication required
*/
type PostMediaFilesUnauthorized struct {
	Payload *PostMediaFilesUnauthorizedBody
}

func (o *PostMediaFilesUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/media-files][%d] postMediaFilesUnauthorized  %+v", 401, o.Payload)
}

func (o *PostMediaFilesUnauthorized) GetPayload() *PostMediaFilesUnauthorizedBody {
	return o.Payload
}

func (o *PostMediaFilesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostMediaFilesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMediaFilesForbidden creates a PostMediaFilesForbidden with default headers values
func NewPostMediaFilesForbidden() *PostMediaFilesForbidden {
	return &PostMediaFilesForbidden{}
}

/*PostMediaFilesForbidden handles this case with default header values.

Access forbidden
*/
type PostMediaFilesForbidden struct {
	Payload *PostMediaFilesForbiddenBody
}

func (o *PostMediaFilesForbidden) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/media-files][%d] postMediaFilesForbidden  %+v", 403, o.Payload)
}

func (o *PostMediaFilesForbidden) GetPayload() *PostMediaFilesForbiddenBody {
	return o.Payload
}

func (o *PostMediaFilesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostMediaFilesForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMediaFilesUnsupportedMediaType creates a PostMediaFilesUnsupportedMediaType with default headers values
func NewPostMediaFilesUnsupportedMediaType() *PostMediaFilesUnsupportedMediaType {
	return &PostMediaFilesUnsupportedMediaType{}
}

/*PostMediaFilesUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PostMediaFilesUnsupportedMediaType struct {
	Payload *PostMediaFilesUnsupportedMediaTypeBody
}

func (o *PostMediaFilesUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/media-files][%d] postMediaFilesUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PostMediaFilesUnsupportedMediaType) GetPayload() *PostMediaFilesUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PostMediaFilesUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostMediaFilesUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMediaFilesUnprocessableEntity creates a PostMediaFilesUnprocessableEntity with default headers values
func NewPostMediaFilesUnprocessableEntity() *PostMediaFilesUnprocessableEntity {
	return &PostMediaFilesUnprocessableEntity{}
}

/*PostMediaFilesUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PostMediaFilesUnprocessableEntity struct {
	Payload *PostMediaFilesUnprocessableEntityBody
}

func (o *PostMediaFilesUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/media-files][%d] postMediaFilesUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PostMediaFilesUnprocessableEntity) GetPayload() *PostMediaFilesUnprocessableEntityBody {
	return o.Payload
}

func (o *PostMediaFilesUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostMediaFilesUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PostMediaFilesBadRequestBody post media files bad request body
swagger:model PostMediaFilesBadRequestBody
*/
type PostMediaFilesBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post media files bad request body
func (o *PostMediaFilesBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostMediaFilesBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostMediaFilesBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PostMediaFilesBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostMediaFilesBody post media files body
swagger:model PostMediaFilesBody
*/
type PostMediaFilesBody struct {

	// The binaries of the file
	// Required: true
	// Format: binary
	File io.ReadCloser `json:"file"`

	// The product to which the media file will be associated. It is a JSON string that follows this format '{"identifier":"product_identifier", "attribute":"attribute_code", "scope":"channel_code","locale":"locale_code"}'. You have to either use this field or the `product_model` field, but not both at the same time.
	Product string `json:"product,omitempty"`

	// The product model to which the media file will be associated. It is a JSON string that follows this format '{"code":"product_model_code", "attribute":"attribute_code", "scope":"channel_code","locale":"locale_code"}'. You have to either use this field or the `product` field, but not both at the same time.
	ProductModel string `json:"product_model,omitempty"`
}

// Validate validates this post media files body
func (o *PostMediaFilesBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateFile(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostMediaFilesBody) validateFile(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"file", "body", io.ReadCloser(o.File)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostMediaFilesBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostMediaFilesBody) UnmarshalBinary(b []byte) error {
	var res PostMediaFilesBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostMediaFilesForbiddenBody post media files forbidden body
swagger:model PostMediaFilesForbiddenBody
*/
type PostMediaFilesForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post media files forbidden body
func (o *PostMediaFilesForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostMediaFilesForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostMediaFilesForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PostMediaFilesForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostMediaFilesUnauthorizedBody post media files unauthorized body
swagger:model PostMediaFilesUnauthorizedBody
*/
type PostMediaFilesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post media files unauthorized body
func (o *PostMediaFilesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostMediaFilesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostMediaFilesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PostMediaFilesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostMediaFilesUnprocessableEntityBody post media files unprocessable entity body
swagger:model PostMediaFilesUnprocessableEntityBody
*/
type PostMediaFilesUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post media files unprocessable entity body
func (o *PostMediaFilesUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostMediaFilesUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostMediaFilesUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PostMediaFilesUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostMediaFilesUnsupportedMediaTypeBody post media files unsupported media type body
swagger:model PostMediaFilesUnsupportedMediaTypeBody
*/
type PostMediaFilesUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post media files unsupported media type body
func (o *PostMediaFilesUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostMediaFilesUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostMediaFilesUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PostMediaFilesUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
