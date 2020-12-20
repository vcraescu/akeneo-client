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
)

// GetMediaFilesCodeReader is a Reader for the GetMediaFilesCode structure.
type GetMediaFilesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMediaFilesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMediaFilesCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetMediaFilesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMediaFilesCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetMediaFilesCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetMediaFilesCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetMediaFilesCodeOK creates a GetMediaFilesCodeOK with default headers values
func NewGetMediaFilesCodeOK() *GetMediaFilesCodeOK {
	return &GetMediaFilesCodeOK{}
}

/*GetMediaFilesCodeOK handles this case with default header values.

OK
*/
type GetMediaFilesCodeOK struct {
	Payload *GetMediaFilesCodeOKBody
}

func (o *GetMediaFilesCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files/{code}][%d] getMediaFilesCodeOK  %+v", 200, o.Payload)
}

func (o *GetMediaFilesCodeOK) GetPayload() *GetMediaFilesCodeOKBody {
	return o.Payload
}

func (o *GetMediaFilesCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesCodeUnauthorized creates a GetMediaFilesCodeUnauthorized with default headers values
func NewGetMediaFilesCodeUnauthorized() *GetMediaFilesCodeUnauthorized {
	return &GetMediaFilesCodeUnauthorized{}
}

/*GetMediaFilesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetMediaFilesCodeUnauthorized struct {
	Payload *GetMediaFilesCodeUnauthorizedBody
}

func (o *GetMediaFilesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files/{code}][%d] getMediaFilesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetMediaFilesCodeUnauthorized) GetPayload() *GetMediaFilesCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetMediaFilesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesCodeForbidden creates a GetMediaFilesCodeForbidden with default headers values
func NewGetMediaFilesCodeForbidden() *GetMediaFilesCodeForbidden {
	return &GetMediaFilesCodeForbidden{}
}

/*GetMediaFilesCodeForbidden handles this case with default header values.

Access forbidden
*/
type GetMediaFilesCodeForbidden struct {
	Payload *GetMediaFilesCodeForbiddenBody
}

func (o *GetMediaFilesCodeForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files/{code}][%d] getMediaFilesCodeForbidden  %+v", 403, o.Payload)
}

func (o *GetMediaFilesCodeForbidden) GetPayload() *GetMediaFilesCodeForbiddenBody {
	return o.Payload
}

func (o *GetMediaFilesCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesCodeNotFound creates a GetMediaFilesCodeNotFound with default headers values
func NewGetMediaFilesCodeNotFound() *GetMediaFilesCodeNotFound {
	return &GetMediaFilesCodeNotFound{}
}

/*GetMediaFilesCodeNotFound handles this case with default header values.

Resource not found
*/
type GetMediaFilesCodeNotFound struct {
	Payload *GetMediaFilesCodeNotFoundBody
}

func (o *GetMediaFilesCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files/{code}][%d] getMediaFilesCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetMediaFilesCodeNotFound) GetPayload() *GetMediaFilesCodeNotFoundBody {
	return o.Payload
}

func (o *GetMediaFilesCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesCodeNotAcceptable creates a GetMediaFilesCodeNotAcceptable with default headers values
func NewGetMediaFilesCodeNotAcceptable() *GetMediaFilesCodeNotAcceptable {
	return &GetMediaFilesCodeNotAcceptable{}
}

/*GetMediaFilesCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetMediaFilesCodeNotAcceptable struct {
	Payload *GetMediaFilesCodeNotAcceptableBody
}

func (o *GetMediaFilesCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files/{code}][%d] getMediaFilesCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetMediaFilesCodeNotAcceptable) GetPayload() *GetMediaFilesCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetMediaFilesCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetMediaFilesCodeForbiddenBody get media files code forbidden body
swagger:model GetMediaFilesCodeForbiddenBody
*/
type GetMediaFilesCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files code forbidden body
func (o *GetMediaFilesCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesCodeNotAcceptableBody get media files code not acceptable body
swagger:model GetMediaFilesCodeNotAcceptableBody
*/
type GetMediaFilesCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files code not acceptable body
func (o *GetMediaFilesCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesCodeNotFoundBody get media files code not found body
swagger:model GetMediaFilesCodeNotFoundBody
*/
type GetMediaFilesCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files code not found body
func (o *GetMediaFilesCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesCodeOKBody get media files code o k body
swagger:model GetMediaFilesCodeOKBody
*/
type GetMediaFilesCodeOKBody struct {

	// links
	Links *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links `json:"_links,omitempty"`

	// Media file code
	Code string `json:"code,omitempty"`

	// Extension of the media file
	Extension string `json:"extension,omitempty"`

	// Mime type of the media file
	MimeType string `json:"mime_type,omitempty"`

	// Original filename of the media file
	OriginalFilename string `json:"original_filename,omitempty"`

	// Size of the media file
	Size int64 `json:"size,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetMediaFilesCodeOKBody) UnmarshalJSON(raw []byte) error {
	// GetMediaFilesCodeOKBodyAO0
	var dataGetMediaFilesCodeOKBodyAO0 struct {
		Links *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetMediaFilesCodeOKBodyAO0); err != nil {
		return err
	}

	o.Links = dataGetMediaFilesCodeOKBodyAO0.Links

	// GetMediaFilesCodeOKBodyAO1
	var dataGetMediaFilesCodeOKBodyAO1 struct {
		Code string `json:"code,omitempty"`

		Extension string `json:"extension,omitempty"`

		MimeType string `json:"mime_type,omitempty"`

		OriginalFilename string `json:"original_filename,omitempty"`

		Size int64 `json:"size,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetMediaFilesCodeOKBodyAO1); err != nil {
		return err
	}

	o.Code = dataGetMediaFilesCodeOKBodyAO1.Code

	o.Extension = dataGetMediaFilesCodeOKBodyAO1.Extension

	o.MimeType = dataGetMediaFilesCodeOKBodyAO1.MimeType

	o.OriginalFilename = dataGetMediaFilesCodeOKBodyAO1.OriginalFilename

	o.Size = dataGetMediaFilesCodeOKBodyAO1.Size

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetMediaFilesCodeOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataGetMediaFilesCodeOKBodyAO0 struct {
		Links *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links `json:"_links,omitempty"`
	}

	dataGetMediaFilesCodeOKBodyAO0.Links = o.Links

	jsonDataGetMediaFilesCodeOKBodyAO0, errGetMediaFilesCodeOKBodyAO0 := swag.WriteJSON(dataGetMediaFilesCodeOKBodyAO0)
	if errGetMediaFilesCodeOKBodyAO0 != nil {
		return nil, errGetMediaFilesCodeOKBodyAO0
	}
	_parts = append(_parts, jsonDataGetMediaFilesCodeOKBodyAO0)
	var dataGetMediaFilesCodeOKBodyAO1 struct {
		Code string `json:"code,omitempty"`

		Extension string `json:"extension,omitempty"`

		MimeType string `json:"mime_type,omitempty"`

		OriginalFilename string `json:"original_filename,omitempty"`

		Size int64 `json:"size,omitempty"`
	}

	dataGetMediaFilesCodeOKBodyAO1.Code = o.Code

	dataGetMediaFilesCodeOKBodyAO1.Extension = o.Extension

	dataGetMediaFilesCodeOKBodyAO1.MimeType = o.MimeType

	dataGetMediaFilesCodeOKBodyAO1.OriginalFilename = o.OriginalFilename

	dataGetMediaFilesCodeOKBodyAO1.Size = o.Size

	jsonDataGetMediaFilesCodeOKBodyAO1, errGetMediaFilesCodeOKBodyAO1 := swag.WriteJSON(dataGetMediaFilesCodeOKBodyAO1)
	if errGetMediaFilesCodeOKBodyAO1 != nil {
		return nil, errGetMediaFilesCodeOKBodyAO1
	}
	_parts = append(_parts, jsonDataGetMediaFilesCodeOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get media files code o k body
func (o *GetMediaFilesCodeOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesCodeOKBody) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesCodeOK" + "." + "_links")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links get media files code o k body get media files code o k body a o0 links
swagger:model GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links
*/
type GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links struct {

	// download
	Download *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload `json:"download,omitempty"`
}

// Validate validates this get media files code o k body get media files code o k body a o0 links
func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateDownload(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(o.Download) { // not required
		return nil
	}

	if o.Download != nil {
		if err := o.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesCodeOK" + "." + "_links" + "." + "download")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload get media files code o k body get media files code o k body a o0 links download
swagger:model GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload
*/
type GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload struct {

	// URI to download the binaries of the media file
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files code o k body get media files code o k body a o0 links download
func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeOKBodyGetMediaFilesCodeOKBodyAO0LinksDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesCodeUnauthorizedBody get media files code unauthorized body
swagger:model GetMediaFilesCodeUnauthorizedBody
*/
type GetMediaFilesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files code unauthorized body
func (o *GetMediaFilesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
