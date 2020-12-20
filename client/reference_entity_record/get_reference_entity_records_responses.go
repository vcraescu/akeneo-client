// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_record

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

// GetReferenceEntityRecordsReader is a Reader for the GetReferenceEntityRecords structure.
type GetReferenceEntityRecordsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetReferenceEntityRecordsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetReferenceEntityRecordsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetReferenceEntityRecordsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetReferenceEntityRecordsNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetReferenceEntityRecordsOK creates a GetReferenceEntityRecordsOK with default headers values
func NewGetReferenceEntityRecordsOK() *GetReferenceEntityRecordsOK {
	return &GetReferenceEntityRecordsOK{}
}

/*GetReferenceEntityRecordsOK handles this case with default header values.

Return the records of the given reference entity paginated
*/
type GetReferenceEntityRecordsOK struct {
	Payload *GetReferenceEntityRecordsOKBody
}

func (o *GetReferenceEntityRecordsOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/records][%d] getReferenceEntityRecordsOK  %+v", 200, o.Payload)
}

func (o *GetReferenceEntityRecordsOK) GetPayload() *GetReferenceEntityRecordsOKBody {
	return o.Payload
}

func (o *GetReferenceEntityRecordsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityRecordsOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityRecordsUnauthorized creates a GetReferenceEntityRecordsUnauthorized with default headers values
func NewGetReferenceEntityRecordsUnauthorized() *GetReferenceEntityRecordsUnauthorized {
	return &GetReferenceEntityRecordsUnauthorized{}
}

/*GetReferenceEntityRecordsUnauthorized handles this case with default header values.

Authentication required
*/
type GetReferenceEntityRecordsUnauthorized struct {
	Payload *GetReferenceEntityRecordsUnauthorizedBody
}

func (o *GetReferenceEntityRecordsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/records][%d] getReferenceEntityRecordsUnauthorized  %+v", 401, o.Payload)
}

func (o *GetReferenceEntityRecordsUnauthorized) GetPayload() *GetReferenceEntityRecordsUnauthorizedBody {
	return o.Payload
}

func (o *GetReferenceEntityRecordsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityRecordsUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetReferenceEntityRecordsNotAcceptable creates a GetReferenceEntityRecordsNotAcceptable with default headers values
func NewGetReferenceEntityRecordsNotAcceptable() *GetReferenceEntityRecordsNotAcceptable {
	return &GetReferenceEntityRecordsNotAcceptable{}
}

/*GetReferenceEntityRecordsNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetReferenceEntityRecordsNotAcceptable struct {
	Payload *GetReferenceEntityRecordsNotAcceptableBody
}

func (o *GetReferenceEntityRecordsNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/reference-entities/{reference_entity_code}/records][%d] getReferenceEntityRecordsNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetReferenceEntityRecordsNotAcceptable) GetPayload() *GetReferenceEntityRecordsNotAcceptableBody {
	return o.Payload
}

func (o *GetReferenceEntityRecordsNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetReferenceEntityRecordsNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetReferenceEntityRecordsNotAcceptableBody get reference entity records not acceptable body
swagger:model GetReferenceEntityRecordsNotAcceptableBody
*/
type GetReferenceEntityRecordsNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity records not acceptable body
func (o *GetReferenceEntityRecordsNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBody Reference entity record
swagger:model GetReferenceEntityRecordsOKBody
*/
type GetReferenceEntityRecordsOKBody struct {

	// links
	Links *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links `json:"_links,omitempty"`

	// embedded
	Embedded *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded `json:"_embedded,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetReferenceEntityRecordsOKBody) UnmarshalJSON(raw []byte) error {
	// GetReferenceEntityRecordsOKBodyAO0
	var dataGetReferenceEntityRecordsOKBodyAO0 struct {
		Links *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetReferenceEntityRecordsOKBodyAO0); err != nil {
		return err
	}

	o.Links = dataGetReferenceEntityRecordsOKBodyAO0.Links

	// GetReferenceEntityRecordsOKBodyAO1
	var dataGetReferenceEntityRecordsOKBodyAO1 struct {
		Embedded *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataGetReferenceEntityRecordsOKBodyAO1); err != nil {
		return err
	}

	o.Embedded = dataGetReferenceEntityRecordsOKBodyAO1.Embedded

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetReferenceEntityRecordsOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataGetReferenceEntityRecordsOKBodyAO0 struct {
		Links *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links `json:"_links,omitempty"`
	}

	dataGetReferenceEntityRecordsOKBodyAO0.Links = o.Links

	jsonDataGetReferenceEntityRecordsOKBodyAO0, errGetReferenceEntityRecordsOKBodyAO0 := swag.WriteJSON(dataGetReferenceEntityRecordsOKBodyAO0)
	if errGetReferenceEntityRecordsOKBodyAO0 != nil {
		return nil, errGetReferenceEntityRecordsOKBodyAO0
	}
	_parts = append(_parts, jsonDataGetReferenceEntityRecordsOKBodyAO0)
	var dataGetReferenceEntityRecordsOKBodyAO1 struct {
		Embedded *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded `json:"_embedded,omitempty"`
	}

	dataGetReferenceEntityRecordsOKBodyAO1.Embedded = o.Embedded

	jsonDataGetReferenceEntityRecordsOKBodyAO1, errGetReferenceEntityRecordsOKBodyAO1 := swag.WriteJSON(dataGetReferenceEntityRecordsOKBodyAO1)
	if errGetReferenceEntityRecordsOKBodyAO1 != nil {
		return nil, errGetReferenceEntityRecordsOKBodyAO1
	}
	_parts = append(_parts, jsonDataGetReferenceEntityRecordsOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get reference entity records o k body
func (o *GetReferenceEntityRecordsOKBody) Validate(formats strfmt.Registry) error {
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

func (o *GetReferenceEntityRecordsOKBody) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(o.Links) { // not required
		return nil
	}

	if o.Links != nil {
		if err := o.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityRecordsOK" + "." + "_links")
			}
			return err
		}
	}

	return nil
}

func (o *GetReferenceEntityRecordsOKBody) validateEmbedded(formats strfmt.Registry) error {

	if swag.IsZero(o.Embedded) { // not required
		return nil
	}

	if o.Embedded != nil {
		if err := o.Embedded.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityRecordsOK" + "." + "_embedded")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links get reference entity records o k body get reference entity records o k body a o0 links
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links struct {

	// first
	First *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst `json:"first,omitempty"`

	// next
	Next *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext `json:"next,omitempty"`

	// self
	Self *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o0 links
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateFirst(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateNext(formats); err != nil {
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

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links) validateFirst(formats strfmt.Registry) error {

	if swag.IsZero(o.First) { // not required
		return nil
	}

	if o.First != nil {
		if err := o.First.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityRecordsOK" + "." + "_links" + "." + "first")
			}
			return err
		}
	}

	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links) validateNext(formats strfmt.Registry) error {

	if swag.IsZero(o.Next) { // not required
		return nil
	}

	if o.Next != nil {
		if err := o.Next.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityRecordsOK" + "." + "_links" + "." + "next")
			}
			return err
		}
	}

	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getReferenceEntityRecordsOK" + "." + "_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst get reference entity records o k body get reference entity records o k body a o0 links first
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst struct {

	// URI of the first page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o0 links first
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksFirst
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext get reference entity records o k body get reference entity records o k body a o0 links next
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext struct {

	// URI of the next page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o0 links next
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksNext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf get reference entity records o k body get reference entity records o k body a o0 links self
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf struct {

	// URI of the current page of resources
	Href string `json:"href,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o0 links self
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded get reference entity records o k body get reference entity records o k body a o1 embedded
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded struct {

	// items
	Items []*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0 `json:"items"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o1 embedded
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded) validateItems(formats strfmt.Registry) error {

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
					return ve.ValidateName("getReferenceEntityRecordsOK" + "." + "_embedded" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1Embedded
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0 get reference entity records o k body get reference entity records o k body a o1 embedded items items0
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0 struct {

	// links
	Links *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`

	// Code of the record
	// Required: true
	Code *string `json:"code"`

	// values
	Values *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values `json:"values,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) UnmarshalJSON(raw []byte) error {
	// AO0
	var dataAO0 struct {
		Links *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO0); err != nil {
		return err
	}

	o.Links = dataAO0.Links

	// AO1
	var dataAO1 struct {
		Code *string `json:"code"`

		Values *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values `json:"values,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	o.Code = dataAO1.Code

	o.Values = dataAO1.Values

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataAO0 struct {
		Links *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links `json:"_links,omitempty"`
	}

	dataAO0.Links = o.Links

	jsonDataAO0, errAO0 := swag.WriteJSON(dataAO0)
	if errAO0 != nil {
		return nil, errAO0
	}
	_parts = append(_parts, jsonDataAO0)
	var dataAO1 struct {
		Code *string `json:"code"`

		Values *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values `json:"values,omitempty"`
	}

	dataAO1.Code = o.Code

	dataAO1.Values = o.Values

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o1 embedded items items0
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateValues(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) validateLinks(formats strfmt.Registry) error {

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

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) validateValues(formats strfmt.Registry) error {

	if swag.IsZero(o.Values) { // not required
		return nil
	}

	if o.Values != nil {
		if err := o.Values.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("values")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o0 links
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links struct {

	// self
	Self *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf `json:"self,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o0 links
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links) validateSelf(formats strfmt.Registry) error {

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
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0Links
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o0 links self
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf struct {

	// URI of the resource
	Href string `json:"href,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o0 links self
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO0LinksSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values Record attributes values, see <a href='/concepts/reference-entities.html#focus-on-the-reference-entity-record-values'>Reference entity record values</a> section for more details
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values struct {

	// attribute code
	AttributeCode []*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0 `json:"attributeCode"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o1 values
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAttributeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values) validateAttributeCode(formats strfmt.Registry) error {

	if swag.IsZero(o.AttributeCode) { // not required
		return nil
	}

	for i := 0; i < len(o.AttributeCode); i++ {
		if swag.IsZero(o.AttributeCode[i]) { // not required
			continue
		}

		if o.AttributeCode[i] != nil {
			if err := o.AttributeCode[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("values" + "." + "attributeCode" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1Values
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0 get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o1 values attribute code items0
swagger:model GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0
*/
type GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0 struct {

	// Channel code of the reference entity record value
	Channel string `json:"channel,omitempty"`

	// Reference entity record value
	Data interface{} `json:"data,omitempty"`

	// Locale code of the reference entity record value
	Locale string `json:"locale,omitempty"`
}

// Validate validates this get reference entity records o k body get reference entity records o k body a o1 embedded items items0 a o1 values attribute code items0
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsOKBodyGetReferenceEntityRecordsOKBodyAO1EmbeddedItemsItems0AO1ValuesAttributeCodeItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetReferenceEntityRecordsUnauthorizedBody get reference entity records unauthorized body
swagger:model GetReferenceEntityRecordsUnauthorizedBody
*/
type GetReferenceEntityRecordsUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get reference entity records unauthorized body
func (o *GetReferenceEntityRecordsUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetReferenceEntityRecordsUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetReferenceEntityRecordsUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetReferenceEntityRecordsUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
