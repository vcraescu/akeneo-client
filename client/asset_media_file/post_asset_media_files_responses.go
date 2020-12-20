// Code generated by go-swagger; DO NOT EDIT.

package asset_media_file

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

// PostAssetMediaFilesReader is a Reader for the PostAssetMediaFiles structure.
type PostAssetMediaFilesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAssetMediaFilesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAssetMediaFilesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPostAssetMediaFilesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPostAssetMediaFilesUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPostAssetMediaFilesUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostAssetMediaFilesCreated creates a PostAssetMediaFilesCreated with default headers values
func NewPostAssetMediaFilesCreated() *PostAssetMediaFilesCreated {
	return &PostAssetMediaFilesCreated{}
}

/*PostAssetMediaFilesCreated handles this case with default header values.

Created
*/
type PostAssetMediaFilesCreated struct {
	/*Code of the media file
	 */
	AssetMediaFileCode string
	/*URI of the created resource
	 */
	Location string
}

func (o *PostAssetMediaFilesCreated) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/asset-media-files][%d] postAssetMediaFilesCreated ", 201)
}

func (o *PostAssetMediaFilesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Asset-media-file-code
	o.AssetMediaFileCode = response.GetHeader("Asset-media-file-code")

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPostAssetMediaFilesUnauthorized creates a PostAssetMediaFilesUnauthorized with default headers values
func NewPostAssetMediaFilesUnauthorized() *PostAssetMediaFilesUnauthorized {
	return &PostAssetMediaFilesUnauthorized{}
}

/*PostAssetMediaFilesUnauthorized handles this case with default header values.

Authentication required
*/
type PostAssetMediaFilesUnauthorized struct {
	Payload *PostAssetMediaFilesUnauthorizedBody
}

func (o *PostAssetMediaFilesUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/asset-media-files][%d] postAssetMediaFilesUnauthorized  %+v", 401, o.Payload)
}

func (o *PostAssetMediaFilesUnauthorized) GetPayload() *PostAssetMediaFilesUnauthorizedBody {
	return o.Payload
}

func (o *PostAssetMediaFilesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAssetMediaFilesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAssetMediaFilesUnsupportedMediaType creates a PostAssetMediaFilesUnsupportedMediaType with default headers values
func NewPostAssetMediaFilesUnsupportedMediaType() *PostAssetMediaFilesUnsupportedMediaType {
	return &PostAssetMediaFilesUnsupportedMediaType{}
}

/*PostAssetMediaFilesUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PostAssetMediaFilesUnsupportedMediaType struct {
	Payload *PostAssetMediaFilesUnsupportedMediaTypeBody
}

func (o *PostAssetMediaFilesUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/asset-media-files][%d] postAssetMediaFilesUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PostAssetMediaFilesUnsupportedMediaType) GetPayload() *PostAssetMediaFilesUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PostAssetMediaFilesUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAssetMediaFilesUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAssetMediaFilesUnprocessableEntity creates a PostAssetMediaFilesUnprocessableEntity with default headers values
func NewPostAssetMediaFilesUnprocessableEntity() *PostAssetMediaFilesUnprocessableEntity {
	return &PostAssetMediaFilesUnprocessableEntity{}
}

/*PostAssetMediaFilesUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PostAssetMediaFilesUnprocessableEntity struct {
	Payload *PostAssetMediaFilesUnprocessableEntityBody
}

func (o *PostAssetMediaFilesUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/asset-media-files][%d] postAssetMediaFilesUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PostAssetMediaFilesUnprocessableEntity) GetPayload() *PostAssetMediaFilesUnprocessableEntityBody {
	return o.Payload
}

func (o *PostAssetMediaFilesUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostAssetMediaFilesUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PostAssetMediaFilesBody post asset media files body
swagger:model PostAssetMediaFilesBody
*/
type PostAssetMediaFilesBody struct {

	// The binary of the media file
	// Required: true
	// Format: binary
	File io.ReadCloser `json:"file"`
}

// Validate validates this post asset media files body
func (o *PostAssetMediaFilesBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateFile(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostAssetMediaFilesBody) validateFile(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"file", "body", io.ReadCloser(o.File)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostAssetMediaFilesBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAssetMediaFilesBody) UnmarshalBinary(b []byte) error {
	var res PostAssetMediaFilesBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAssetMediaFilesUnauthorizedBody post asset media files unauthorized body
swagger:model PostAssetMediaFilesUnauthorizedBody
*/
type PostAssetMediaFilesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post asset media files unauthorized body
func (o *PostAssetMediaFilesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAssetMediaFilesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAssetMediaFilesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PostAssetMediaFilesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAssetMediaFilesUnprocessableEntityBody post asset media files unprocessable entity body
swagger:model PostAssetMediaFilesUnprocessableEntityBody
*/
type PostAssetMediaFilesUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post asset media files unprocessable entity body
func (o *PostAssetMediaFilesUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAssetMediaFilesUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAssetMediaFilesUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PostAssetMediaFilesUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostAssetMediaFilesUnsupportedMediaTypeBody post asset media files unsupported media type body
swagger:model PostAssetMediaFilesUnsupportedMediaTypeBody
*/
type PostAssetMediaFilesUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post asset media files unsupported media type body
func (o *PostAssetMediaFilesUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostAssetMediaFilesUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostAssetMediaFilesUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PostAssetMediaFilesUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
