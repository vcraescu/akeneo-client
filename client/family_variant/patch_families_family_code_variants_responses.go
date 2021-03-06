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

// PatchFamiliesFamilyCodeVariantsReader is a Reader for the PatchFamiliesFamilyCodeVariants structure.
type PatchFamiliesFamilyCodeVariantsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchFamiliesFamilyCodeVariantsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchFamiliesFamilyCodeVariantsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPatchFamiliesFamilyCodeVariantsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchFamiliesFamilyCodeVariantsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 413:
		result := NewPatchFamiliesFamilyCodeVariantsRequestEntityTooLarge()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchFamiliesFamilyCodeVariantsUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchFamiliesFamilyCodeVariantsOK creates a PatchFamiliesFamilyCodeVariantsOK with default headers values
func NewPatchFamiliesFamilyCodeVariantsOK() *PatchFamiliesFamilyCodeVariantsOK {
	return &PatchFamiliesFamilyCodeVariantsOK{}
}

/*PatchFamiliesFamilyCodeVariantsOK handles this case with default header values.

OK
*/
type PatchFamiliesFamilyCodeVariantsOK struct {
	Payload *PatchFamiliesFamilyCodeVariantsOKBody
}

func (o *PatchFamiliesFamilyCodeVariantsOK) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants][%d] patchFamiliesFamilyCodeVariantsOK  %+v", 200, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsOK) GetPayload() *PatchFamiliesFamilyCodeVariantsOKBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsUnauthorized creates a PatchFamiliesFamilyCodeVariantsUnauthorized with default headers values
func NewPatchFamiliesFamilyCodeVariantsUnauthorized() *PatchFamiliesFamilyCodeVariantsUnauthorized {
	return &PatchFamiliesFamilyCodeVariantsUnauthorized{}
}

/*PatchFamiliesFamilyCodeVariantsUnauthorized handles this case with default header values.

Authentication required
*/
type PatchFamiliesFamilyCodeVariantsUnauthorized struct {
	Payload *PatchFamiliesFamilyCodeVariantsUnauthorizedBody
}

func (o *PatchFamiliesFamilyCodeVariantsUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants][%d] patchFamiliesFamilyCodeVariantsUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsUnauthorized) GetPayload() *PatchFamiliesFamilyCodeVariantsUnauthorizedBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsForbidden creates a PatchFamiliesFamilyCodeVariantsForbidden with default headers values
func NewPatchFamiliesFamilyCodeVariantsForbidden() *PatchFamiliesFamilyCodeVariantsForbidden {
	return &PatchFamiliesFamilyCodeVariantsForbidden{}
}

/*PatchFamiliesFamilyCodeVariantsForbidden handles this case with default header values.

Access forbidden
*/
type PatchFamiliesFamilyCodeVariantsForbidden struct {
	Payload *PatchFamiliesFamilyCodeVariantsForbiddenBody
}

func (o *PatchFamiliesFamilyCodeVariantsForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants][%d] patchFamiliesFamilyCodeVariantsForbidden  %+v", 403, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsForbidden) GetPayload() *PatchFamiliesFamilyCodeVariantsForbiddenBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsRequestEntityTooLarge creates a PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge with default headers values
func NewPatchFamiliesFamilyCodeVariantsRequestEntityTooLarge() *PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge {
	return &PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge{}
}

/*PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge handles this case with default header values.

Request Entity Too Large
*/
type PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge struct {
	Payload *PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody
}

func (o *PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants][%d] patchFamiliesFamilyCodeVariantsRequestEntityTooLarge  %+v", 413, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge) GetPayload() *PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsRequestEntityTooLarge) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchFamiliesFamilyCodeVariantsUnsupportedMediaType creates a PatchFamiliesFamilyCodeVariantsUnsupportedMediaType with default headers values
func NewPatchFamiliesFamilyCodeVariantsUnsupportedMediaType() *PatchFamiliesFamilyCodeVariantsUnsupportedMediaType {
	return &PatchFamiliesFamilyCodeVariantsUnsupportedMediaType{}
}

/*PatchFamiliesFamilyCodeVariantsUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchFamiliesFamilyCodeVariantsUnsupportedMediaType struct {
	Payload *PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody
}

func (o *PatchFamiliesFamilyCodeVariantsUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/families/{family_code}/variants][%d] patchFamiliesFamilyCodeVariantsUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchFamiliesFamilyCodeVariantsUnsupportedMediaType) GetPayload() *PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchFamiliesFamilyCodeVariantsUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchFamiliesFamilyCodeVariantsBody patch families family code variants body
swagger:model PatchFamiliesFamilyCodeVariantsBody
*/
type PatchFamiliesFamilyCodeVariantsBody struct {

	// Family variant code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *PatchFamiliesFamilyCodeVariantsParamsBodyLabels `json:"labels,omitempty"`

	// Attributes distribution according to the enrichment level
	// Required: true
	VariantAttributeSets []*PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0 `json:"variant_attribute_sets"`
}

// Validate validates this patch families family code variants body
func (o *PatchFamiliesFamilyCodeVariantsBody) Validate(formats strfmt.Registry) error {
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

func (o *PatchFamiliesFamilyCodeVariantsBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PatchFamiliesFamilyCodeVariantsBody) validateLabels(formats strfmt.Registry) error {

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

func (o *PatchFamiliesFamilyCodeVariantsBody) validateVariantAttributeSets(formats strfmt.Registry) error {

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
func (o *PatchFamiliesFamilyCodeVariantsBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsForbiddenBody patch families family code variants forbidden body
swagger:model PatchFamiliesFamilyCodeVariantsForbiddenBody
*/
type PatchFamiliesFamilyCodeVariantsForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants forbidden body
func (o *PatchFamiliesFamilyCodeVariantsForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsOKBody patch families family code variants o k body
swagger:model PatchFamiliesFamilyCodeVariantsOKBody
*/
type PatchFamiliesFamilyCodeVariantsOKBody struct {

	// Resource code, only filled when the resource is not a product
	Code string `json:"code,omitempty"`

	// Resource identifier, only filled when the resource is a product
	Identifier string `json:"identifier,omitempty"`

	// Line number
	Line int64 `json:"line,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`

	// HTTP status code, see <a href="/documentation/responses.html#client-errors">Client errors</a> to understand the meaning of each code
	StatusCode int64 `json:"status_code,omitempty"`
}

// Validate validates this patch families family code variants o k body
func (o *PatchFamiliesFamilyCodeVariantsOKBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsOKBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsParamsBodyLabels Family variant labels for each locale
swagger:model PatchFamiliesFamilyCodeVariantsParamsBodyLabels
*/
type PatchFamiliesFamilyCodeVariantsParamsBodyLabels struct {

	// Family variant label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this patch families family code variants params body labels
func (o *PatchFamiliesFamilyCodeVariantsParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0 Enrichment level
swagger:model PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0
*/
type PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0 struct {

	// Codes of attributes bind to this enrichment level
	Attributes []string `json:"attributes"`

	// Codes of attributes used as variant axes
	// Required: true
	Axes []string `json:"axes"`

	// Enrichment level
	// Required: true
	Level *int64 `json:"level"`
}

// Validate validates this patch families family code variants params body variant attribute sets items0
func (o *PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0) Validate(formats strfmt.Registry) error {
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

func (o *PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0) validateAxes(formats strfmt.Registry) error {

	if err := validate.Required("axes", "body", o.Axes); err != nil {
		return err
	}

	return nil
}

func (o *PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0) validateLevel(formats strfmt.Registry) error {

	if err := validate.Required("level", "body", o.Level); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsParamsBodyVariantAttributeSetsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody patch families family code variants request entity too large body
swagger:model PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody
*/
type PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants request entity too large body
func (o *PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsRequestEntityTooLargeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsUnauthorizedBody patch families family code variants unauthorized body
swagger:model PatchFamiliesFamilyCodeVariantsUnauthorizedBody
*/
type PatchFamiliesFamilyCodeVariantsUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants unauthorized body
func (o *PatchFamiliesFamilyCodeVariantsUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody patch families family code variants unsupported media type body
swagger:model PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody
*/
type PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch families family code variants unsupported media type body
func (o *PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchFamiliesFamilyCodeVariantsUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
