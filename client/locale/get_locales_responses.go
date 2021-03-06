// Code generated by go-swagger; DO NOT EDIT.

package locale

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

// GetLocalesReader is a Reader for the GetLocales structure.
type GetLocalesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLocalesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLocalesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetLocalesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetLocalesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetLocalesNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetLocalesOK creates a GetLocalesOK with default headers values
func NewGetLocalesOK() *GetLocalesOK {
	return &GetLocalesOK{}
}

/*GetLocalesOK handles this case with default header values.

Return locales paginated
*/
type GetLocalesOK struct {
	Payload *GetLocalesOKBody
}

func (o *GetLocalesOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/locales][%d] getLocalesOK  %+v", 200, o.Payload)
}

func (o *GetLocalesOK) GetPayload() *GetLocalesOKBody {
	return o.Payload
}

func (o *GetLocalesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetLocalesOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLocalesUnauthorized creates a GetLocalesUnauthorized with default headers values
func NewGetLocalesUnauthorized() *GetLocalesUnauthorized {
	return &GetLocalesUnauthorized{}
}

/*GetLocalesUnauthorized handles this case with default header values.

Authentication required
*/
type GetLocalesUnauthorized struct {
	Payload *GetLocalesUnauthorizedBody
}

func (o *GetLocalesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/locales][%d] getLocalesUnauthorized  %+v", 401, o.Payload)
}

func (o *GetLocalesUnauthorized) GetPayload() *GetLocalesUnauthorizedBody {
	return o.Payload
}

func (o *GetLocalesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetLocalesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLocalesForbidden creates a GetLocalesForbidden with default headers values
func NewGetLocalesForbidden() *GetLocalesForbidden {
	return &GetLocalesForbidden{}
}

/*GetLocalesForbidden handles this case with default header values.

Access forbidden
*/
type GetLocalesForbidden struct {
	Payload *GetLocalesForbiddenBody
}

func (o *GetLocalesForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/locales][%d] getLocalesForbidden  %+v", 403, o.Payload)
}

func (o *GetLocalesForbidden) GetPayload() *GetLocalesForbiddenBody {
	return o.Payload
}

func (o *GetLocalesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetLocalesForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLocalesNotAcceptable creates a GetLocalesNotAcceptable with default headers values
func NewGetLocalesNotAcceptable() *GetLocalesNotAcceptable {
	return &GetLocalesNotAcceptable{}
}

/*GetLocalesNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetLocalesNotAcceptable struct {
	Payload *GetLocalesNotAcceptableBody
}

func (o *GetLocalesNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/locales][%d] getLocalesNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetLocalesNotAcceptable) GetPayload() *GetLocalesNotAcceptableBody {
	return o.Payload
}

func (o *GetLocalesNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetLocalesNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetLocalesForbiddenBody get locales forbidden body
swagger:model GetLocalesForbiddenBody
*/
type GetLocalesForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get locales forbidden body
func (o *GetLocalesForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetLocalesForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesNotAcceptableBody get locales not acceptable body
swagger:model GetLocalesNotAcceptableBody
*/
type GetLocalesNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get locales not acceptable body
func (o *GetLocalesNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetLocalesNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBody Locales
swagger:model GetLocalesOKBody
*/
type GetLocalesOKBody struct {

	// links
	Links *GetLocalesOKBodyGetLocalesOKBodyAO0Links `json:"_links,omitempty"`

	// Current page number
	CurrentPage int64 `json:"current_page,omitempty"`

	// embedded
	Embedded *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded `json:"_embedded,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetLocalesOKBody) UnmarshalJSON(raw []byte) error {
	// GetLocalesOKBodyAO0
	var dataGetLocalesOKBodyAO0 struct {
		Links *GetLocalesOKBodyGetLocalesOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetLocalesOKBodyAO0); err != nil {
		return err
	}

	o.Links = dataGetLocalesOKBodyAO0.Links

	o.CurrentPage = dataGetLocalesOKBodyAO0.CurrentPage

	// GetLocalesOKBodyAO1
	var dataGetLocalesOKBodyAO1 struct {
		Embedded *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetLocalesOKBodyAO1); err != nil {
		return err
	}

	o.Embedded = dataGetLocalesOKBodyAO1.Embedded

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetLocalesOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataGetLocalesOKBodyAO0 struct {
		Links *GetLocalesOKBodyGetLocalesOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}

	dataGetLocalesOKBodyAO0.Links = o.Links

	dataGetLocalesOKBodyAO0.CurrentPage = o.CurrentPage

	jsonDataGetLocalesOKBodyAO0, errGetLocalesOKBodyAO0 := swag.WriteJSON(dataGetLocalesOKBodyAO0)
	if errGetLocalesOKBodyAO0 != nil {
		return nil, errGetLocalesOKBodyAO0
	}
	_parts = append(_parts, jsonDataGetLocalesOKBodyAO0)
	var dataGetLocalesOKBodyAO1 struct {
		Embedded *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}

	dataGetLocalesOKBodyAO1.Embedded = o.Embedded

	jsonDataGetLocalesOKBodyAO1, errGetLocalesOKBodyAO1 := swag.WriteJSON(dataGetLocalesOKBodyAO1)
	if errGetLocalesOKBodyAO1 != nil {
		return nil, errGetLocalesOKBodyAO1
	}
	_parts = append(_parts, jsonDataGetLocalesOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get locales o k body
func (o *GetLocalesOKBody) Validate(formats strfmt.Registry) error {
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

func (o *GetLocalesOKBody) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getLocalesOK" + "." + "_links")
			}
			return err
		}
	}

	return nil
}

func (o *GetLocalesOKBody) validateEmbedded(formats strfmt.Registry) error {

	if swag.IsZero(o.Embedded) { // not required
		return nil
	}

	if o.Embedded != nil {
		if err := o.Embedded.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getLocalesOK" + "." + "_embedded")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBody) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO0Links get locales o k body get locales o k body a o0 links
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO0Links
*/
type GetLocalesOKBodyGetLocalesOKBodyAO0Links struct {

	// first
	First *GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst `json:"first,omitempty"`

	// next
	Next *GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext `json:"next,omitempty"`

	// previous
	Previous *GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious `json:"previous,omitempty"`

	// self
	Self *GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o0 links
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) Validate(formats strfmt.Registry) error {
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

func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) validateFirst(formats strfmt.Registry) error {

	if swag.IsZero(o.First) { // not required
		return nil
	}

	if o.First != nil {
		if err := o.First.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getLocalesOK" + "." + "_links" + "." + "first")
			}
			return err
		}
	}

	return nil
}

func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) validateNext(formats strfmt.Registry) error {

	if swag.IsZero(o.Next) { // not required
		return nil
	}

	if o.Next != nil {
		if err := o.Next.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getLocalesOK" + "." + "_links" + "." + "next")
			}
			return err
		}
	}

	return nil
}

func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) validatePrevious(formats strfmt.Registry) error {

	if swag.IsZero(o.Previous) { // not required
		return nil
	}

	if o.Previous != nil {
		if err := o.Previous.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getLocalesOK" + "." + "_links" + "." + "previous")
			}
			return err
		}
	}

	return nil
}

func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getLocalesOK" + "." + "_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0Links) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst get locales o k body get locales o k body a o0 links first
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst
*/
type GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst struct {

	// URI of the first page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o0 links first
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO0LinksFirst
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext get locales o k body get locales o k body a o0 links next
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext
*/
type GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext struct {

	// URI of the next page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o0 links next
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO0LinksNext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious get locales o k body get locales o k body a o0 links previous
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious
*/
type GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious struct {

	// URI of the previous page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o0 links previous
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO0LinksPrevious
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf get locales o k body get locales o k body a o0 links self
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf
*/
type GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf struct {

	// URI of the current page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o0 links self
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO1Embedded get locales o k body get locales o k body a o1 embedded
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO1Embedded
*/
type GetLocalesOKBodyGetLocalesOKBodyAO1Embedded struct {

	// items
	Items []*GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0 `json:"items"`
}

// Validate validates this get locales o k body get locales o k body a o1 embedded
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded) validateItems(formats strfmt.Registry) error {

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
					return ve.ValidateName("getLocalesOK" + "." + "_embedded" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1Embedded) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO1Embedded
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0 get locales o k body get locales o k body a o1 embedded items items0
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0
*/
type GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0 struct {

	// links
	Links *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`

	// Locale code
	// Required: true
	Code *string `json:"code"`

	// Whether the locale is enabled
	Enabled *bool `json:"enabled,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	o.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Enabled *bool `json:"enabled,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	o.Code = dataAO1.Code

	o.Enabled = dataAO1.Enabled

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = o.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Enabled *bool `json:"enabled,omitempty"`
	}

	dataAO1.Code = o.Code

	dataAO1.Enabled = o.Enabled

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get locales o k body get locales o k body a o1 embedded items items0
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) validateLinks(formats strfmt.Registry) error {

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

func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links get locales o k body get locales o k body a o1 embedded items items0 a o0 links
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links
*/
type GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links struct {

	// self
	Self *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o1 embedded items items0 a o0 links
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links) validateSelf(formats strfmt.Registry) error {

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
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf get locales o k body get locales o k body a o1 embedded items items0 a o0 links self
swagger:model GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
*/
type GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this get locales o k body get locales o k body a o1 embedded items items0 a o0 links self
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetLocalesOKBodyGetLocalesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetLocalesUnauthorizedBody get locales unauthorized body
swagger:model GetLocalesUnauthorizedBody
*/
type GetLocalesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get locales unauthorized body
func (o *GetLocalesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetLocalesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetLocalesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetLocalesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
