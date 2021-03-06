// Code generated by go-swagger; DO NOT EDIT.

package category

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

// PatchCategoriesCodeReader is a Reader for the PatchCategoriesCode structure.
type PatchCategoriesCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchCategoriesCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchCategoriesCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewPatchCategoriesCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchCategoriesCodeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchCategoriesCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchCategoriesCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchCategoriesCodeUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchCategoriesCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchCategoriesCodeCreated creates a PatchCategoriesCodeCreated with default headers values
func NewPatchCategoriesCodeCreated() *PatchCategoriesCodeCreated {
	return &PatchCategoriesCodeCreated{}
}

/*PatchCategoriesCodeCreated handles this case with default header values.

Created
*/
type PatchCategoriesCodeCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PatchCategoriesCodeCreated) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeCreated ", 201)
}

func (o *PatchCategoriesCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchCategoriesCodeNoContent creates a PatchCategoriesCodeNoContent with default headers values
func NewPatchCategoriesCodeNoContent() *PatchCategoriesCodeNoContent {
	return &PatchCategoriesCodeNoContent{}
}

/*PatchCategoriesCodeNoContent handles this case with default header values.

No content to return
*/
type PatchCategoriesCodeNoContent struct {
	/*URI of the updated resource
	 */
	Location string
}

func (o *PatchCategoriesCodeNoContent) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeNoContent ", 204)
}

func (o *PatchCategoriesCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchCategoriesCodeBadRequest creates a PatchCategoriesCodeBadRequest with default headers values
func NewPatchCategoriesCodeBadRequest() *PatchCategoriesCodeBadRequest {
	return &PatchCategoriesCodeBadRequest{}
}

/*PatchCategoriesCodeBadRequest handles this case with default header values.

Bad request
*/
type PatchCategoriesCodeBadRequest struct {
	Payload *PatchCategoriesCodeBadRequestBody
}

func (o *PatchCategoriesCodeBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeBadRequest  %+v", 400, o.Payload)
}

func (o *PatchCategoriesCodeBadRequest) GetPayload() *PatchCategoriesCodeBadRequestBody {
	return o.Payload
}

func (o *PatchCategoriesCodeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchCategoriesCodeBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchCategoriesCodeUnauthorized creates a PatchCategoriesCodeUnauthorized with default headers values
func NewPatchCategoriesCodeUnauthorized() *PatchCategoriesCodeUnauthorized {
	return &PatchCategoriesCodeUnauthorized{}
}

/*PatchCategoriesCodeUnauthorized handles this case with default header values.

Authentication required
*/
type PatchCategoriesCodeUnauthorized struct {
	Payload *PatchCategoriesCodeUnauthorizedBody
}

func (o *PatchCategoriesCodeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchCategoriesCodeUnauthorized) GetPayload() *PatchCategoriesCodeUnauthorizedBody {
	return o.Payload
}

func (o *PatchCategoriesCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchCategoriesCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchCategoriesCodeForbidden creates a PatchCategoriesCodeForbidden with default headers values
func NewPatchCategoriesCodeForbidden() *PatchCategoriesCodeForbidden {
	return &PatchCategoriesCodeForbidden{}
}

/*PatchCategoriesCodeForbidden handles this case with default header values.

Access forbidden
*/
type PatchCategoriesCodeForbidden struct {
	Payload *PatchCategoriesCodeForbiddenBody
}

func (o *PatchCategoriesCodeForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeForbidden  %+v", 403, o.Payload)
}

func (o *PatchCategoriesCodeForbidden) GetPayload() *PatchCategoriesCodeForbiddenBody {
	return o.Payload
}

func (o *PatchCategoriesCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchCategoriesCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchCategoriesCodeUnsupportedMediaType creates a PatchCategoriesCodeUnsupportedMediaType with default headers values
func NewPatchCategoriesCodeUnsupportedMediaType() *PatchCategoriesCodeUnsupportedMediaType {
	return &PatchCategoriesCodeUnsupportedMediaType{}
}

/*PatchCategoriesCodeUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchCategoriesCodeUnsupportedMediaType struct {
	Payload *PatchCategoriesCodeUnsupportedMediaTypeBody
}

func (o *PatchCategoriesCodeUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchCategoriesCodeUnsupportedMediaType) GetPayload() *PatchCategoriesCodeUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchCategoriesCodeUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchCategoriesCodeUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchCategoriesCodeUnprocessableEntity creates a PatchCategoriesCodeUnprocessableEntity with default headers values
func NewPatchCategoriesCodeUnprocessableEntity() *PatchCategoriesCodeUnprocessableEntity {
	return &PatchCategoriesCodeUnprocessableEntity{}
}

/*PatchCategoriesCodeUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PatchCategoriesCodeUnprocessableEntity struct {
	Payload *PatchCategoriesCodeUnprocessableEntityBody
}

func (o *PatchCategoriesCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/categories/{code}][%d] patchCategoriesCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchCategoriesCodeUnprocessableEntity) GetPayload() *PatchCategoriesCodeUnprocessableEntityBody {
	return o.Payload
}

func (o *PatchCategoriesCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchCategoriesCodeUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchCategoriesCodeBadRequestBody patch categories code bad request body
swagger:model PatchCategoriesCodeBadRequestBody
*/
type PatchCategoriesCodeBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch categories code bad request body
func (o *PatchCategoriesCodeBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchCategoriesCodeBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchCategoriesCodeBody patch categories code body
swagger:model PatchCategoriesCodeBody
*/
type PatchCategoriesCodeBody struct {

	// Category code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *PatchCategoriesCodeParamsBodyLabels `json:"labels,omitempty"`

	// Category code of the parent's category
	Parent *string `json:"parent,omitempty"`
}

// Validate validates this patch categories code body
func (o *PatchCategoriesCodeBody) Validate(formats strfmt.Registry) error {
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

func (o *PatchCategoriesCodeBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PatchCategoriesCodeBody) validateLabels(formats strfmt.Registry) error {

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
func (o *PatchCategoriesCodeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeBody) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchCategoriesCodeForbiddenBody patch categories code forbidden body
swagger:model PatchCategoriesCodeForbiddenBody
*/
type PatchCategoriesCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch categories code forbidden body
func (o *PatchCategoriesCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchCategoriesCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchCategoriesCodeParamsBodyLabels Category labels for each locale
swagger:model PatchCategoriesCodeParamsBodyLabels
*/
type PatchCategoriesCodeParamsBodyLabels struct {

	// Category label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch categories code params body labels
func (o *PatchCategoriesCodeParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchCategoriesCodeParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchCategoriesCodeUnauthorizedBody patch categories code unauthorized body
swagger:model PatchCategoriesCodeUnauthorizedBody
*/
type PatchCategoriesCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch categories code unauthorized body
func (o *PatchCategoriesCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchCategoriesCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchCategoriesCodeUnprocessableEntityBody patch categories code unprocessable entity body
swagger:model PatchCategoriesCodeUnprocessableEntityBody
*/
type PatchCategoriesCodeUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch categories code unprocessable entity body
func (o *PatchCategoriesCodeUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchCategoriesCodeUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchCategoriesCodeUnsupportedMediaTypeBody patch categories code unsupported media type body
swagger:model PatchCategoriesCodeUnsupportedMediaTypeBody
*/
type PatchCategoriesCodeUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch categories code unsupported media type body
func (o *PatchCategoriesCodeUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchCategoriesCodeUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchCategoriesCodeUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchCategoriesCodeUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
