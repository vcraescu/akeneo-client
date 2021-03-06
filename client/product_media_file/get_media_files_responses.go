// Code generated by go-swagger; DO NOT EDIT.

package product_media_file

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
)

// GetMediaFilesReader is a Reader for the GetMediaFiles structure.
type GetMediaFilesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMediaFilesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMediaFilesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetMediaFilesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMediaFilesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetMediaFilesNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetMediaFilesOK creates a GetMediaFilesOK with default headers values
func NewGetMediaFilesOK() *GetMediaFilesOK {
	return &GetMediaFilesOK{}
}

/*GetMediaFilesOK handles this case with default header values.

Return media files paginated
*/
type GetMediaFilesOK struct {
	Payload *GetMediaFilesOKBody
}

func (o *GetMediaFilesOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files][%d] getMediaFilesOK  %+v", 200, o.Payload)
}

func (o *GetMediaFilesOK) GetPayload() *GetMediaFilesOKBody {
	return o.Payload
}

func (o *GetMediaFilesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesUnauthorized creates a GetMediaFilesUnauthorized with default headers values
func NewGetMediaFilesUnauthorized() *GetMediaFilesUnauthorized {
	return &GetMediaFilesUnauthorized{}
}

/*GetMediaFilesUnauthorized handles this case with default header values.

Authentication required
*/
type GetMediaFilesUnauthorized struct {
	Payload *GetMediaFilesUnauthorizedBody
}

func (o *GetMediaFilesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files][%d] getMediaFilesUnauthorized  %+v", 401, o.Payload)
}

func (o *GetMediaFilesUnauthorized) GetPayload() *GetMediaFilesUnauthorizedBody {
	return o.Payload
}

func (o *GetMediaFilesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesForbidden creates a GetMediaFilesForbidden with default headers values
func NewGetMediaFilesForbidden() *GetMediaFilesForbidden {
	return &GetMediaFilesForbidden{}
}

/*GetMediaFilesForbidden handles this case with default header values.

Access forbidden
*/
type GetMediaFilesForbidden struct {
	Payload *GetMediaFilesForbiddenBody
}

func (o *GetMediaFilesForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files][%d] getMediaFilesForbidden  %+v", 403, o.Payload)
}

func (o *GetMediaFilesForbidden) GetPayload() *GetMediaFilesForbiddenBody {
	return o.Payload
}

func (o *GetMediaFilesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMediaFilesNotAcceptable creates a GetMediaFilesNotAcceptable with default headers values
func NewGetMediaFilesNotAcceptable() *GetMediaFilesNotAcceptable {
	return &GetMediaFilesNotAcceptable{}
}

/*GetMediaFilesNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetMediaFilesNotAcceptable struct {
	Payload *GetMediaFilesNotAcceptableBody
}

func (o *GetMediaFilesNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/media-files][%d] getMediaFilesNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetMediaFilesNotAcceptable) GetPayload() *GetMediaFilesNotAcceptableBody {
	return o.Payload
}

func (o *GetMediaFilesNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetMediaFilesNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetMediaFilesForbiddenBody get media files forbidden body
swagger:model GetMediaFilesForbiddenBody
*/
type GetMediaFilesForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files forbidden body
func (o *GetMediaFilesForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesNotAcceptableBody get media files not acceptable body
swagger:model GetMediaFilesNotAcceptableBody
*/
type GetMediaFilesNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files not acceptable body
func (o *GetMediaFilesNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBody MediaFiles
swagger:model GetMediaFilesOKBody
*/
type GetMediaFilesOKBody struct {

	// links
	Links *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links `json:"_links,omitempty"`

	// Current page number
	CurrentPage int64 `json:"current_page,omitempty"`

	// embedded
	Embedded *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded `json:"_embedded,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetMediaFilesOKBody) UnmarshalJSON(raw []byte) error {
	// GetMediaFilesOKBodyAO0
	var dataGetMediaFilesOKBodyAO0 struct {
		Links *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetMediaFilesOKBodyAO0); err != nil {
		return err
	}

	o.Links = dataGetMediaFilesOKBodyAO0.Links

	o.CurrentPage = dataGetMediaFilesOKBodyAO0.CurrentPage

	// GetMediaFilesOKBodyAO1
	var dataGetMediaFilesOKBodyAO1 struct {
		Embedded *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetMediaFilesOKBodyAO1); err != nil {
		return err
	}

	o.Embedded = dataGetMediaFilesOKBodyAO1.Embedded

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetMediaFilesOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataGetMediaFilesOKBodyAO0 struct {
		Links *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}

	dataGetMediaFilesOKBodyAO0.Links = o.Links

	dataGetMediaFilesOKBodyAO0.CurrentPage = o.CurrentPage

	jsonDataGetMediaFilesOKBodyAO0, errGetMediaFilesOKBodyAO0 := swag.WriteJSON(dataGetMediaFilesOKBodyAO0)
	if errGetMediaFilesOKBodyAO0 != nil {
		return nil, errGetMediaFilesOKBodyAO0
	}
	_parts = append(_parts, jsonDataGetMediaFilesOKBodyAO0)
	var dataGetMediaFilesOKBodyAO1 struct {
		Embedded *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}

	dataGetMediaFilesOKBodyAO1.Embedded = o.Embedded

	jsonDataGetMediaFilesOKBodyAO1, errGetMediaFilesOKBodyAO1 := swag.WriteJSON(dataGetMediaFilesOKBodyAO1)
	if errGetMediaFilesOKBodyAO1 != nil {
		return nil, errGetMediaFilesOKBodyAO1
	}
	_parts = append(_parts, jsonDataGetMediaFilesOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get media files o k body
func (o *GetMediaFilesOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateEmbedded(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesOKBody) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesOK" + "." + "_links")
			}
			return err
		}
	}

	return nil
}

func (o *GetMediaFilesOKBody) validateEmbedded(formats strfmt.Registry) error {

	if swag.IsZero(o.Embedded) { // not required
		return nil
	}

	if o.Embedded != nil {
		if err := o.Embedded.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesOK" + "." + "_embedded")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links get media files o k body get media files o k body a o0 links
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links struct {

	// first
	First *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst `json:"first,omitempty"`

	// next
	Next *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext `json:"next,omitempty"`

	// previous
	Previous *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious `json:"previous,omitempty"`

	// self
	Self *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o0 links
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateFirst(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateNext(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validatePrevious(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) validateFirst(formats strfmt.Registry) error {

	if swag.IsZero(o.First) { // not required
		return nil
	}

	if o.First != nil {
		if err := o.First.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesOK" + "." + "_links" + "." + "first")
			}
			return err
		}
	}

	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) validateNext(formats strfmt.Registry) error {

	if swag.IsZero(o.Next) { // not required
		return nil
	}

	if o.Next != nil {
		if err := o.Next.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesOK" + "." + "_links" + "." + "next")
			}
			return err
		}
	}

	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) validatePrevious(formats strfmt.Registry) error {

	if swag.IsZero(o.Previous) { // not required
		return nil
	}

	if o.Previous != nil {
		if err := o.Previous.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesOK" + "." + "_links" + "." + "previous")
			}
			return err
		}
	}

	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getMediaFilesOK" + "." + "_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst get media files o k body get media files o k body a o0 links first
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst struct {

	// URI of the first page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o0 links first
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksFirst
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext get media files o k body get media files o k body a o0 links next
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext struct {

	// URI of the next page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o0 links next
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksNext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious get media files o k body get media files o k body a o0 links previous
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious struct {

	// URI of the previous page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o0 links previous
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksPrevious
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf get media files o k body get media files o k body a o0 links self
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf struct {

	// URI of the current page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o0 links self
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded get media files o k body get media files o k body a o1 embedded
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded struct {

	// items
	Items []*GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0 `json:"items"`
}

// Validate validates this get media files o k body get media files o k body a o1 embedded
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded) validateItems(formats strfmt.Registry) error {

	if swag.IsZero(o.Items) { // not required
		return nil
	}

	for i := 0; i < len(o.Items); i++ {
		if swag.IsZero(o.Items[i]) { // not required
			continue
		}

		if o.Items[i] != nil {
			if err := o.Items[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getMediaFilesOK" + "." + "_embedded" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO1Embedded
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0 get media files o k body get media files o k body a o1 embedded items items0
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0 struct {

	// links
	Links *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`

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
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	o.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code string `json:"code,omitempty"`

		Extension string `json:"extension,omitempty"`

		MimeType string `json:"mime_type,omitempty"`

		OriginalFilename string `json:"original_filename,omitempty"`

		Size int64 `json:"size,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	o.Code = dataAO1.Code

	o.Extension = dataAO1.Extension

	o.MimeType = dataAO1.MimeType

	o.OriginalFilename = dataAO1.OriginalFilename

	o.Size = dataAO1.Size

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = o.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code string `json:"code,omitempty"`

		Extension string `json:"extension,omitempty"`

		MimeType string `json:"mime_type,omitempty"`

		OriginalFilename string `json:"original_filename,omitempty"`

		Size int64 `json:"size,omitempty"`
	}

	dataAO1.Code = o.Code

	dataAO1.Extension = o.Extension

	dataAO1.MimeType = o.MimeType

	dataAO1.OriginalFilename = o.OriginalFilename

	dataAO1.Size = o.Size

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get media files o k body get media files o k body a o1 embedded items items0
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links get media files o k body get media files o k body a o1 embedded items items0 a o0 links
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links struct {

	// download
	Download *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload `json:"download,omitempty"`

	// self
	Self *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o1 embedded items items0 a o0 links
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateDownload(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(o.Download) { // not required
		return nil
	}

	if o.Download != nil {
		if err := o.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload get media files o k body get media files o k body a o1 embedded items items0 a o0 links download
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload struct {

	// URI to download the binaries of the media file
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o1 embedded items items0 a o0 links download
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf get media files o k body get media files o k body a o1 embedded items items0 a o0 links self
swagger:model GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
*/
type GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf struct {

	// URI to get the metadata of the media file
	Href string `json:"href,omitempty"`
}

// Validate validates this get media files o k body get media files o k body a o1 embedded items items0 a o0 links self
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesOKBodyGetMediaFilesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetMediaFilesUnauthorizedBody get media files unauthorized body
swagger:model GetMediaFilesUnauthorizedBody
*/
type GetMediaFilesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get media files unauthorized body
func (o *GetMediaFilesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetMediaFilesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetMediaFilesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetMediaFilesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
