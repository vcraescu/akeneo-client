// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_attribute_option

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

// PatchReferenceEntityAttributesAttributeCodeOptionsCodeReader is a Reader for the PatchReferenceEntityAttributesAttributeCodeOptionsCode structure.
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated creates a PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated with default headers values
func NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated {
	return &PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated{}
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated handles this case with default header values.

Created
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] patchReferenceEntityAttributesAttributeCodeOptionsCodeCreated ", 201)
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent creates a PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent with default headers values
func NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent {
	return &PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent{}
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent handles this case with default header values.

No content to return
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent struct {
	/*URI of the updated resource
	 */
	Location string
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] patchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent ", 204)
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized creates a PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized with default headers values
func NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized {
	return &PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized{}
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized struct {
	Payload *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] patchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized) GetPayload() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody {
	return o.Payload
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType creates a PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType with default headers values
func NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType {
	return &PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType{}
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType struct {
	Payload *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] patchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType) GetPayload() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity creates a PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity with default headers values
func NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity {
	return &PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity{}
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity struct {
	Payload *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}][%d] patchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity) GetPayload() *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody {
	return o.Payload
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody patch reference entity attributes attribute code options code body
swagger:model PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody struct {

	// Attribute's option code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels `json:"labels,omitempty"`
}

// Validate validates this patch reference entity attributes attribute code options code body
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody) Validate(formats strfmt.Registry) error {
	var res []error

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

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody) validateLabels(formats strfmt.Registry) error {

	if swag.IsZero(o.Labels) { // not required
		return nil
	}

	if o.Labels != nil {
		if err := o.Labels.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "labels")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesAttributeCodeOptionsCodeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels Attribute labels for each locale
swagger:model PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels struct {

	// Attribute label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch reference entity attributes attribute code options code params body labels
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesAttributeCodeOptionsCodeParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody patch reference entity attributes attribute code options code unauthorized body
swagger:model PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch reference entity attributes attribute code options code unauthorized body
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody patch reference entity attributes attribute code options code unprocessable entity body
swagger:model PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch reference entity attributes attribute code options code unprocessable entity body
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody patch reference entity attributes attribute code options code unsupported media type body
swagger:model PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody
*/
type PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch reference entity attributes attribute code options code unsupported media type body
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchReferenceEntityAttributesAttributeCodeOptionsCodeUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
