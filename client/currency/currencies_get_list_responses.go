// Code generated by go-swagger; DO NOT EDIT.

package currency

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

// CurrenciesGetListReader is a Reader for the CurrenciesGetList structure.
type CurrenciesGetListReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CurrenciesGetListReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCurrenciesGetListOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewCurrenciesGetListUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCurrenciesGetListForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCurrenciesGetListNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCurrenciesGetListOK creates a CurrenciesGetListOK with default headers values
func NewCurrenciesGetListOK() *CurrenciesGetListOK {
	return &CurrenciesGetListOK{}
}

/*CurrenciesGetListOK handles this case with default header values.

Return currencies paginated
*/
type CurrenciesGetListOK struct {
	Payload *CurrenciesGetListOKBody
}

func (o *CurrenciesGetListOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/currencies][%d] currenciesGetListOK  %+v", 200, o.Payload)
}

func (o *CurrenciesGetListOK) GetPayload() *CurrenciesGetListOKBody {
	return o.Payload
}

func (o *CurrenciesGetListOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(CurrenciesGetListOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCurrenciesGetListUnauthorized creates a CurrenciesGetListUnauthorized with default headers values
func NewCurrenciesGetListUnauthorized() *CurrenciesGetListUnauthorized {
	return &CurrenciesGetListUnauthorized{}
}

/*CurrenciesGetListUnauthorized handles this case with default header values.

Authentication required
*/
type CurrenciesGetListUnauthorized struct {
	Payload *CurrenciesGetListUnauthorizedBody
}

func (o *CurrenciesGetListUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/currencies][%d] currenciesGetListUnauthorized  %+v", 401, o.Payload)
}

func (o *CurrenciesGetListUnauthorized) GetPayload() *CurrenciesGetListUnauthorizedBody {
	return o.Payload
}

func (o *CurrenciesGetListUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(CurrenciesGetListUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCurrenciesGetListForbidden creates a CurrenciesGetListForbidden with default headers values
func NewCurrenciesGetListForbidden() *CurrenciesGetListForbidden {
	return &CurrenciesGetListForbidden{}
}

/*CurrenciesGetListForbidden handles this case with default header values.

Access forbidden
*/
type CurrenciesGetListForbidden struct {
	Payload *CurrenciesGetListForbiddenBody
}

func (o *CurrenciesGetListForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/currencies][%d] currenciesGetListForbidden  %+v", 403, o.Payload)
}

func (o *CurrenciesGetListForbidden) GetPayload() *CurrenciesGetListForbiddenBody {
	return o.Payload
}

func (o *CurrenciesGetListForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(CurrenciesGetListForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCurrenciesGetListNotAcceptable creates a CurrenciesGetListNotAcceptable with default headers values
func NewCurrenciesGetListNotAcceptable() *CurrenciesGetListNotAcceptable {
	return &CurrenciesGetListNotAcceptable{}
}

/*CurrenciesGetListNotAcceptable handles this case with default header values.

Not Acceptable
*/
type CurrenciesGetListNotAcceptable struct {
	Payload *CurrenciesGetListNotAcceptableBody
}

func (o *CurrenciesGetListNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/currencies][%d] currenciesGetListNotAcceptable  %+v", 406, o.Payload)
}

func (o *CurrenciesGetListNotAcceptable) GetPayload() *CurrenciesGetListNotAcceptableBody {
	return o.Payload
}

func (o *CurrenciesGetListNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(CurrenciesGetListNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*CurrenciesGetListForbiddenBody currencies get list forbidden body
swagger:model CurrenciesGetListForbiddenBody
*/
type CurrenciesGetListForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this currencies get list forbidden body
func (o *CurrenciesGetListForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListForbiddenBody) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListNotAcceptableBody currencies get list not acceptable body
swagger:model CurrenciesGetListNotAcceptableBody
*/
type CurrenciesGetListNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this currencies get list not acceptable body
func (o *CurrenciesGetListNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBody Currencies
swagger:model CurrenciesGetListOKBody
*/
type CurrenciesGetListOKBody struct {

	// links
	Links *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links `json:"_links,omitempty"`

	// Current page number
	CurrentPage int64 `json:"current_page,omitempty"`

	// embedded
	Embedded *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded `json:"_embedded,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *CurrenciesGetListOKBody) UnmarshalJSON(raw []byte) error {
	// CurrenciesGetListOKBodyAO0
	var dataCurrenciesGetListOKBodyAO0 struct {
		Links *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataCurrenciesGetListOKBodyAO0); err != nil {
		return err
	}

	o.Links = dataCurrenciesGetListOKBodyAO0.Links

	o.CurrentPage = dataCurrenciesGetListOKBodyAO0.CurrentPage

	// CurrenciesGetListOKBodyAO1
	var dataCurrenciesGetListOKBodyAO1 struct {
		Embedded *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataCurrenciesGetListOKBodyAO1); err != nil {
		return err
	}

	o.Embedded = dataCurrenciesGetListOKBodyAO1.Embedded

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o CurrenciesGetListOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataCurrenciesGetListOKBodyAO0 struct {
		Links *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links `json:"_links,omitempty"`

		CurrentPage int64 `json:"current_page,omitempty"`
	}

	dataCurrenciesGetListOKBodyAO0.Links = o.Links

	dataCurrenciesGetListOKBodyAO0.CurrentPage = o.CurrentPage

	jsonDataCurrenciesGetListOKBodyAO0, errCurrenciesGetListOKBodyAO0 := swag.WriteJSON(dataCurrenciesGetListOKBodyAO0)
	if errCurrenciesGetListOKBodyAO0 != nil {
		return nil, errCurrenciesGetListOKBodyAO0
	}
	_parts = append(_parts, jsonDataCurrenciesGetListOKBodyAO0)
	var dataCurrenciesGetListOKBodyAO1 struct {
		Embedded *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}

	dataCurrenciesGetListOKBodyAO1.Embedded = o.Embedded

	jsonDataCurrenciesGetListOKBodyAO1, errCurrenciesGetListOKBodyAO1 := swag.WriteJSON(dataCurrenciesGetListOKBodyAO1)
	if errCurrenciesGetListOKBodyAO1 != nil {
		return nil, errCurrenciesGetListOKBodyAO1
	}
	_parts = append(_parts, jsonDataCurrenciesGetListOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this currencies get list o k body
func (o *CurrenciesGetListOKBody) Validate(formats strfmt.Registry) error {
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

func (o *CurrenciesGetListOKBody) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("currenciesGetListOK" + "." + "_links")
			}
			return err
		}
	}

	return nil
}

func (o *CurrenciesGetListOKBody) validateEmbedded(formats strfmt.Registry) error {

	if swag.IsZero(o.Embedded) { // not required
		return nil
	}

	if o.Embedded != nil {
		if err := o.Embedded.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("currenciesGetListOK" + "." + "_embedded")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBody) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links currencies get list o k body currencies get list o k body a o0 links
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links struct {

	// first
	First *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst `json:"first,omitempty"`

	// next
	Next *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext `json:"next,omitempty"`

	// previous
	Previous *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious `json:"previous,omitempty"`

	// self
	Self *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o0 links
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) Validate(formats strfmt.Registry) error {
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

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) validateFirst(formats strfmt.Registry) error {

	if swag.IsZero(o.First) { // not required
		return nil
	}

	if o.First != nil {
		if err := o.First.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("currenciesGetListOK" + "." + "_links" + "." + "first")
			}
			return err
		}
	}

	return nil
}

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) validateNext(formats strfmt.Registry) error {

	if swag.IsZero(o.Next) { // not required
		return nil
	}

	if o.Next != nil {
		if err := o.Next.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("currenciesGetListOK" + "." + "_links" + "." + "next")
			}
			return err
		}
	}

	return nil
}

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) validatePrevious(formats strfmt.Registry) error {

	if swag.IsZero(o.Previous) { // not required
		return nil
	}

	if o.Previous != nil {
		if err := o.Previous.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("currenciesGetListOK" + "." + "_links" + "." + "previous")
			}
			return err
		}
	}

	return nil
}

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("currenciesGetListOK" + "." + "_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst currencies get list o k body currencies get list o k body a o0 links first
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst struct {

	// URI of the first page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o0 links first
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksFirst
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext currencies get list o k body currencies get list o k body a o0 links next
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext struct {

	// URI of the next page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o0 links next
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksNext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious currencies get list o k body currencies get list o k body a o0 links previous
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious struct {

	// URI of the previous page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o0 links previous
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksPrevious
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf currencies get list o k body currencies get list o k body a o0 links self
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf struct {

	// URI of the current page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o0 links self
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded currencies get list o k body currencies get list o k body a o1 embedded
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded struct {

	// items
	Items []*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0 `json:"items"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o1 embedded
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded) validateItems(formats strfmt.Registry) error {

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
					return ve.ValidateName("currenciesGetListOK" + "." + "_embedded" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1Embedded
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0 currencies get list o k body currencies get list o k body a o1 embedded items items0
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0 struct {

	// links
	Links *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`

	// Currency code
	// Required: true
	Code *string `json:"code"`

	// Whether the currency is enabled
	Enabled bool `json:"enabled,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	o.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Enabled bool `json:"enabled,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	o.Code = dataAO1.Code

	o.Enabled = dataAO1.Enabled

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = o.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Enabled bool `json:"enabled,omitempty"`
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

// Validate validates this currencies get list o k body currencies get list o k body a o1 embedded items items0
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) Validate(formats strfmt.Registry) error {
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

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) validateLinks(formats strfmt.Registry) error {

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

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links currencies get list o k body currencies get list o k body a o1 embedded items items0 a o0 links
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links struct {

	// self
	Self *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o1 embedded items items0 a o0 links
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links) validateSelf(formats strfmt.Registry) error {

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
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf currencies get list o k body currencies get list o k body a o1 embedded items items0 a o0 links self
swagger:model CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
*/
type CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this currencies get list o k body currencies get list o k body a o1 embedded items items0 a o0 links self
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListOKBodyCurrenciesGetListOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*CurrenciesGetListUnauthorizedBody currencies get list unauthorized body
swagger:model CurrenciesGetListUnauthorizedBody
*/
type CurrenciesGetListUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this currencies get list unauthorized body
func (o *CurrenciesGetListUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *CurrenciesGetListUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CurrenciesGetListUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res CurrenciesGetListUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
