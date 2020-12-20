// Code generated by go-swagger; DO NOT EDIT.

package category

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

// GetCategoriesReader is a Reader for the GetCategories structure.
type GetCategoriesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCategoriesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetCategoriesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetCategoriesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetCategoriesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetCategoriesNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetCategoriesOK creates a GetCategoriesOK with default headers values
func NewGetCategoriesOK() *GetCategoriesOK {
	return &GetCategoriesOK{}
}

/*GetCategoriesOK handles this case with default header values.

Return categories paginated
*/
type GetCategoriesOK struct {
	Payload *GetCategoriesOKBody
}

func (o *GetCategoriesOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/categories][%d] getCategoriesOK  %+v", 200, o.Payload)
}

func (o *GetCategoriesOK) GetPayload() *GetCategoriesOKBody {
	return o.Payload
}

func (o *GetCategoriesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetCategoriesOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCategoriesUnauthorized creates a GetCategoriesUnauthorized with default headers values
func NewGetCategoriesUnauthorized() *GetCategoriesUnauthorized {
	return &GetCategoriesUnauthorized{}
}

/*GetCategoriesUnauthorized handles this case with default header values.

Authentication required
*/
type GetCategoriesUnauthorized struct {
	Payload *GetCategoriesUnauthorizedBody
}

func (o *GetCategoriesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/categories][%d] getCategoriesUnauthorized  %+v", 401, o.Payload)
}

func (o *GetCategoriesUnauthorized) GetPayload() *GetCategoriesUnauthorizedBody {
	return o.Payload
}

func (o *GetCategoriesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetCategoriesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCategoriesForbidden creates a GetCategoriesForbidden with default headers values
func NewGetCategoriesForbidden() *GetCategoriesForbidden {
	return &GetCategoriesForbidden{}
}

/*GetCategoriesForbidden handles this case with default header values.

Access forbidden
*/
type GetCategoriesForbidden struct {
	Payload *GetCategoriesForbiddenBody
}

func (o *GetCategoriesForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/categories][%d] getCategoriesForbidden  %+v", 403, o.Payload)
}

func (o *GetCategoriesForbidden) GetPayload() *GetCategoriesForbiddenBody {
	return o.Payload
}

func (o *GetCategoriesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetCategoriesForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCategoriesNotAcceptable creates a GetCategoriesNotAcceptable with default headers values
func NewGetCategoriesNotAcceptable() *GetCategoriesNotAcceptable {
	return &GetCategoriesNotAcceptable{}
}

/*GetCategoriesNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetCategoriesNotAcceptable struct {
	Payload *GetCategoriesNotAcceptableBody
}

func (o *GetCategoriesNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/categories][%d] getCategoriesNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetCategoriesNotAcceptable) GetPayload() *GetCategoriesNotAcceptableBody {
	return o.Payload
}

func (o *GetCategoriesNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetCategoriesNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetCategoriesForbiddenBody get categories forbidden body
swagger:model GetCategoriesForbiddenBody
*/
type GetCategoriesForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get categories forbidden body
func (o *GetCategoriesForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetCategoriesForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesNotAcceptableBody get categories not acceptable body
swagger:model GetCategoriesNotAcceptableBody
*/
type GetCategoriesNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get categories not acceptable body
func (o *GetCategoriesNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetCategoriesNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBody Categories
swagger:model GetCategoriesOKBody
*/
type GetCategoriesOKBody struct {

	// links
	Links *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links `json:"_links,omitempty"`

	// Current page number
	CurrentPage int64 `json:"current_page,omitempty"`

	// embedded
	Embedded *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded `json:"_embedded,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetCategoriesOKBody) UnmarshalJSON(raw []byte) error {
	// GetCategoriesOKBodyAO0
	var dataGetCategoriesOKBodyAO0 struct {
		Links *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetCategoriesOKBodyAO0); err != nil {
		return err
	}

	o.Links = dataGetCategoriesOKBodyAO0.Links

	o.CurrentPage = dataGetCategoriesOKBodyAO0.CurrentPage

	// GetCategoriesOKBodyAO1
	var dataGetCategoriesOKBodyAO1 struct {
		Embedded *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetCategoriesOKBodyAO1); err != nil {
		return err
	}

	o.Embedded = dataGetCategoriesOKBodyAO1.Embedded

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetCategoriesOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataGetCategoriesOKBodyAO0 struct {
		Links *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}

	dataGetCategoriesOKBodyAO0.Links = o.Links

	dataGetCategoriesOKBodyAO0.CurrentPage = o.CurrentPage

	jsonDataGetCategoriesOKBodyAO0, errGetCategoriesOKBodyAO0 := swag.WriteJSON(dataGetCategoriesOKBodyAO0)
	if errGetCategoriesOKBodyAO0 != nil {
		return nil, errGetCategoriesOKBodyAO0
	}
	_parts = append(_parts, jsonDataGetCategoriesOKBodyAO0)
	var dataGetCategoriesOKBodyAO1 struct {
		Embedded *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}

	dataGetCategoriesOKBodyAO1.Embedded = o.Embedded

	jsonDataGetCategoriesOKBodyAO1, errGetCategoriesOKBodyAO1 := swag.WriteJSON(dataGetCategoriesOKBodyAO1)
	if errGetCategoriesOKBodyAO1 != nil {
		return nil, errGetCategoriesOKBodyAO1
	}
	_parts = append(_parts, jsonDataGetCategoriesOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get categories o k body
func (o *GetCategoriesOKBody) Validate(formats strfmt.Registry) error {
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

func (o *GetCategoriesOKBody) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getCategoriesOK" + "." + "_links")
			}
			return err
		}
	}

	return nil
}

func (o *GetCategoriesOKBody) validateEmbedded(formats strfmt.Registry) error {

	if swag.IsZero(o.Embedded) { // not required
		return nil
	}

	if o.Embedded != nil {
		if err := o.Embedded.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getCategoriesOK" + "." + "_embedded")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBody) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO0Links get categories o k body get categories o k body a o0 links
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO0Links
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO0Links struct {

	// first
	First *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst `json:"first,omitempty"`

	// next
	Next *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext `json:"next,omitempty"`

	// previous
	Previous *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious `json:"previous,omitempty"`

	// self
	Self *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o0 links
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) Validate(formats strfmt.Registry) error {
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

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) validateFirst(formats strfmt.Registry) error {

	if swag.IsZero(o.First) { // not required
		return nil
	}

	if o.First != nil {
		if err := o.First.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getCategoriesOK" + "." + "_links" + "." + "first")
			}
			return err
		}
	}

	return nil
}

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) validateNext(formats strfmt.Registry) error {

	if swag.IsZero(o.Next) { // not required
		return nil
	}

	if o.Next != nil {
		if err := o.Next.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getCategoriesOK" + "." + "_links" + "." + "next")
			}
			return err
		}
	}

	return nil
}

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) validatePrevious(formats strfmt.Registry) error {

	if swag.IsZero(o.Previous) { // not required
		return nil
	}

	if o.Previous != nil {
		if err := o.Previous.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getCategoriesOK" + "." + "_links" + "." + "previous")
			}
			return err
		}
	}

	return nil
}

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getCategoriesOK" + "." + "_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0Links) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst get categories o k body get categories o k body a o0 links first
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst struct {

	// URI of the first page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o0 links first
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksFirst
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext get categories o k body get categories o k body a o0 links next
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext struct {

	// URI of the next page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o0 links next
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksNext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious get categories o k body get categories o k body a o0 links previous
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious struct {

	// URI of the previous page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o0 links previous
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksPrevious
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf get categories o k body get categories o k body a o0 links self
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf struct {

	// URI of the current page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o0 links self
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded get categories o k body get categories o k body a o1 embedded
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded struct {

	// items
	Items []*GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0 `json:"items"`
}

// Validate validates this get categories o k body get categories o k body a o1 embedded
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded) validateItems(formats strfmt.Registry) error {

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
					return ve.ValidateName("getCategoriesOK" + "." + "_embedded" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO1Embedded
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0 get categories o k body get categories o k body a o1 embedded items items0
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0 struct {

	// links
	Links *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`

	// Category code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels `json:"labels,omitempty"`

	// Category code of the parent's category
	Parent *string `json:"parent,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	o.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Labels *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels `json:"labels,omitempty"`

		Parent *string `json:"parent,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	o.Code = dataAO1.Code

	o.Labels = dataAO1.Labels

	o.Parent = dataAO1.Parent

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = o.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Labels *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels `json:"labels,omitempty"`

		Parent *string `json:"parent,omitempty"`
	}

	dataAO1.Code = o.Code

	dataAO1.Labels = o.Labels

	dataAO1.Parent = o.Parent

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get categories o k body get categories o k body a o1 embedded items items0
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinks(formats); err != nil {
		res = append(res, err)
	}

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

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) validateLinks(formats strfmt.Registry) error {

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

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("labels")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links get categories o k body get categories o k body a o1 embedded items items0 a o0 links
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links struct {

	// self
	Self *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o1 embedded items items0 a o0 links
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links) validateSelf(formats strfmt.Registry) error {

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
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf get categories o k body get categories o k body a o1 embedded items items0 a o0 links self
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o1 embedded items items0 a o0 links self
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels Category labels for each locale
swagger:model GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels
*/
type GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels struct {

	// Category label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this get categories o k body get categories o k body a o1 embedded items items0 a o1 labels
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels) UnmarshalBinary(b []byte) error {
	var res GetCategoriesOKBodyGetCategoriesOKBodyAO1EmbeddedItemsItems0AO1Labels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetCategoriesUnauthorizedBody get categories unauthorized body
swagger:model GetCategoriesUnauthorizedBody
*/
type GetCategoriesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get categories unauthorized body
func (o *GetCategoriesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetCategoriesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetCategoriesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetCategoriesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}