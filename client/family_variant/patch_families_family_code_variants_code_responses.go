// Code generated by go-swagger; DO NOT EDIT.

package family_variant

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

// PatchFamiliesFamilyCodeVariantsCodeReader is a Reader for the PatchFamiliesFamilyCodeVariantsCode structure.
type PatchFamiliesFamilyCodeVariantsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchFamiliesFamilyCodeVariantsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchFamiliesFamilyCodeVariantsCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewPatchFamiliesFamilyCodeVariantsCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchFamiliesFamilyCodeVariantsCodeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchFamiliesFamilyCodeVariantsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchFamiliesFamilyCodeVariantsCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchFamiliesFamilyCodeVariantsCodeCreated creates a PatchFamiliesFamilyCodeVariantsCodeCreated with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeCreated() *PatchFamiliesFamilyCodeVariantsCodeCreated {
	return &PatchFamiliesFamilyCodeVariantsCodeCreated{}
}

/*PatchFamiliesFamilyCodeVariantsCodeCreated handles this case with default header values.

Created
*/
type PatchFamiliesFamilyCodeVariantsCodeCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PatchFamiliesFamilyCodeVariantsCodeCreated) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeCreated ", 201)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsCodeNoContent creates a PatchFamiliesFamilyCodeVariantsCodeNoContent with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeNoContent() *PatchFamiliesFamilyCodeVariantsCodeNoContent {
	return &PatchFamiliesFamilyCodeVariantsCodeNoContent{}
}

/*PatchFamiliesFamilyCodeVariantsCodeNoContent handles this case with default header values.

No content to return
*/
type PatchFamiliesFamilyCodeVariantsCodeNoContent struct {
	/*URI of the updated resource
	 */
	Location string
}

func (o *PatchFamiliesFamilyCodeVariantsCodeNoContent) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeNoContent ", 204)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsCodeBadRequest creates a PatchFamiliesFamilyCodeVariantsCodeBadRequest with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeBadRequest() *PatchFamiliesFamilyCodeVariantsCodeBadRequest {
	return &PatchFamiliesFamilyCodeVariantsCodeBadRequest{}
}

/*PatchFamiliesFamilyCodeVariantsCodeBadRequest handles this case with default header values.

Bad request
*/
type PatchFamiliesFamilyCodeVariantsCodeBadRequest struct {
	Payload *PatchFamiliesFamilyCodeVariantsCodeBadRequestBody
}

func (o *PatchFamiliesFamilyCodeVariantsCodeBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeBadRequest  %+v", 400, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeBadRequest) GetPayload() *PatchFamiliesFamilyCodeVariantsCodeBadRequestBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsCodeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsCodeBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsCodeUnauthorized creates a PatchFamiliesFamilyCodeVariantsCodeUnauthorized with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeUnauthorized() *PatchFamiliesFamilyCodeVariantsCodeUnauthorized {
	return &PatchFamiliesFamilyCodeVariantsCodeUnauthorized{}
}

/*PatchFamiliesFamilyCodeVariantsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type PatchFamiliesFamilyCodeVariantsCodeUnauthorized struct {
	Payload *PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnauthorized) GetPayload() *PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsCodeForbidden creates a PatchFamiliesFamilyCodeVariantsCodeForbidden with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeForbidden() *PatchFamiliesFamilyCodeVariantsCodeForbidden {
	return &PatchFamiliesFamilyCodeVariantsCodeForbidden{}
}

/*PatchFamiliesFamilyCodeVariantsCodeForbidden handles this case with default header values.

Access forbidden
*/
type PatchFamiliesFamilyCodeVariantsCodeForbidden struct {
	Payload *PatchFamiliesFamilyCodeVariantsCodeForbiddenBody
}

func (o *PatchFamiliesFamilyCodeVariantsCodeForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeForbidden  %+v", 403, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeForbidden) GetPayload() *PatchFamiliesFamilyCodeVariantsCodeForbiddenBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType creates a PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType() *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType {
	return &PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType{}
}

/*PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType struct {
	Payload *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType) GetPayload() *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity creates a PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity with default headers values
func NewPatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity() *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity {
	return &PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity{}
}

/*PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity struct {
	Payload *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants/{code}][%d] patchFamiliesFamilyCodeVariantsCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity) GetPayload() *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeBadRequestBody patch families family code variants code bad request body
swagger:model PatchFamiliesFamilyCodeVariantsCodeBadRequestBody
*/
type PatchFamiliesFamilyCodeVariantsCodeBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants code bad request body
func (o *PatchFamiliesFamilyCodeVariantsCodeBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeBody patch families family code variants code body
swagger:model PatchFamiliesFamilyCodeVariantsCodeBody
*/
type PatchFamiliesFamilyCodeVariantsCodeBody struct {

	// Family variant code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels `json:"labels,omitempty"`

	// Attributes distribution according to the enrichment level
	// Required: true
	VariantAttributeSets []*PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0 `json:"variant_attribute_sets"`
}

// Validate validates this patch families family code variants code body
func (o *PatchFamiliesFamilyCodeVariantsCodeBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateVariantAttributeSets(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchFamiliesFamilyCodeVariantsCodeBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PatchFamiliesFamilyCodeVariantsCodeBody) validateLabels(formats strfmt.Registry) error {

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

func (o *PatchFamiliesFamilyCodeVariantsCodeBody) validateVariantAttributeSets(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"variant_attribute_sets", "body", o.VariantAttributeSets); err != nil {
		return err
	}

	for i := 0; i < len(o.VariantAttributeSets); i++ {
		if swag.IsZero(o.VariantAttributeSets[i]) { // not required
			continue
		}

		if o.VariantAttributeSets[i] != nil {
			if err := o.VariantAttributeSets[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("body" + "." + "variant_attribute_sets" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeForbiddenBody patch families family code variants code forbidden body
swagger:model PatchFamiliesFamilyCodeVariantsCodeForbiddenBody
*/
type PatchFamiliesFamilyCodeVariantsCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants code forbidden body
func (o *PatchFamiliesFamilyCodeVariantsCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels Family variant labels for each locale
swagger:model PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels
*/
type PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels struct {

	// Family variant label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch families family code variants code params body labels
func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0 Enrichment level
swagger:model PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0
*/
type PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0 struct {

	// Codes of attributes bind to this enrichment level
	Attributes []string `json:"attributes"`

	// Codes of attributes used as variant axes
	// Required: true
	Axes []string `json:"axes"`

	// Enrichment level
	// Required: true
	Level *int64 `json:"level"`
}

// Validate validates this patch families family code variants code params body variant attribute sets items0
func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAxes(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateLevel(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0) validateAxes(formats strfmt.Registry) error {

	if err := validate.Required("axes", "body", o.Axes); err != nil {
		return err
	}

	return nil
}

func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0) validateLevel(formats strfmt.Registry) error {

	if err := validate.Required("level", "body", o.Level); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeParamsBodyVariantAttributeSetsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody patch families family code variants code unauthorized body
swagger:model PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody
*/
type PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants code unauthorized body
func (o *PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody patch families family code variants code unprocessable entity body
swagger:model PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody
*/
type PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants code unprocessable entity body
func (o *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody patch families family code variants code unsupported media type body
swagger:model PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody
*/
type PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants code unsupported media type body
func (o *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsCodeUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
