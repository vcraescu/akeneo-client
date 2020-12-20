// Code generated by go-swagger; DO NOT EDIT.

package family

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

// PostFamiliesReader is a Reader for the PostFamilies structure.
type PostFamiliesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostFamiliesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostFamiliesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostFamiliesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostFamiliesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostFamiliesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPostFamiliesUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPostFamiliesUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostFamiliesCreated creates a PostFamiliesCreated with default headers values
func NewPostFamiliesCreated() *PostFamiliesCreated {
	return &PostFamiliesCreated{}
}

/*PostFamiliesCreated handles this case with default header values.

Created
*/
type PostFamiliesCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PostFamiliesCreated) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/families][%d] postFamiliesCreated ", 201)
}

func (o *PostFamiliesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPostFamiliesBadRequest creates a PostFamiliesBadRequest with default headers values
func NewPostFamiliesBadRequest() *PostFamiliesBadRequest {
	return &PostFamiliesBadRequest{}
}

/*PostFamiliesBadRequest handles this case with default header values.

Bad request
*/
type PostFamiliesBadRequest struct {
	Payload *PostFamiliesBadRequestBody
}

func (o *PostFamiliesBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/families][%d] postFamiliesBadRequest  %+v", 400, o.Payload)
}

func (o *PostFamiliesBadRequest) GetPayload() *PostFamiliesBadRequestBody {
	return o.Payload
}

func (o *PostFamiliesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostFamiliesBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostFamiliesUnauthorized creates a PostFamiliesUnauthorized with default headers values
func NewPostFamiliesUnauthorized() *PostFamiliesUnauthorized {
	return &PostFamiliesUnauthorized{}
}

/*PostFamiliesUnauthorized handles this case with default header values.

Authentication required
*/
type PostFamiliesUnauthorized struct {
	Payload *PostFamiliesUnauthorizedBody
}

func (o *PostFamiliesUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/families][%d] postFamiliesUnauthorized  %+v", 401, o.Payload)
}

func (o *PostFamiliesUnauthorized) GetPayload() *PostFamiliesUnauthorizedBody {
	return o.Payload
}

func (o *PostFamiliesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostFamiliesUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostFamiliesForbidden creates a PostFamiliesForbidden with default headers values
func NewPostFamiliesForbidden() *PostFamiliesForbidden {
	return &PostFamiliesForbidden{}
}

/*PostFamiliesForbidden handles this case with default header values.

Access forbidden
*/
type PostFamiliesForbidden struct {
	Payload *PostFamiliesForbiddenBody
}

func (o *PostFamiliesForbidden) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/families][%d] postFamiliesForbidden  %+v", 403, o.Payload)
}

func (o *PostFamiliesForbidden) GetPayload() *PostFamiliesForbiddenBody {
	return o.Payload
}

func (o *PostFamiliesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostFamiliesForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostFamiliesUnsupportedMediaType creates a PostFamiliesUnsupportedMediaType with default headers values
func NewPostFamiliesUnsupportedMediaType() *PostFamiliesUnsupportedMediaType {
	return &PostFamiliesUnsupportedMediaType{}
}

/*PostFamiliesUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PostFamiliesUnsupportedMediaType struct {
	Payload *PostFamiliesUnsupportedMediaTypeBody
}

func (o *PostFamiliesUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/families][%d] postFamiliesUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PostFamiliesUnsupportedMediaType) GetPayload() *PostFamiliesUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PostFamiliesUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostFamiliesUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostFamiliesUnprocessableEntity creates a PostFamiliesUnprocessableEntity with default headers values
func NewPostFamiliesUnprocessableEntity() *PostFamiliesUnprocessableEntity {
	return &PostFamiliesUnprocessableEntity{}
}

/*PostFamiliesUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PostFamiliesUnprocessableEntity struct {
	Payload *PostFamiliesUnprocessableEntityBody
}

func (o *PostFamiliesUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/families][%d] postFamiliesUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PostFamiliesUnprocessableEntity) GetPayload() *PostFamiliesUnprocessableEntityBody {
	return o.Payload
}

func (o *PostFamiliesUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostFamiliesUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PostFamiliesBadRequestBody post families bad request body
swagger:model PostFamiliesBadRequestBody
*/
type PostFamiliesBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post families bad request body
func (o *PostFamiliesBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PostFamiliesBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesBody post families body
swagger:model PostFamiliesBody
*/
type PostFamiliesBody struct {

	// Attribute code used as the main picture in the user interface (only since v2.0)
	AttributeAsImage *string `json:"attribute_as_image,omitempty"`

	// Attribute code used as label
	// Required: true
	AttributeAsLabel *string `json:"attribute_as_label"`

	// attribute requirements
	AttributeRequirements *PostFamiliesParamsBodyAttributeRequirements `json:"attribute_requirements,omitempty"`

	// Attributes codes that compose the family
	Attributes []string `json:"attributes"`

	// Family code
	// Required: true
	Code *string `json:"code"`

	// labels
	Labels *PostFamiliesParamsBodyLabels `json:"labels,omitempty"`
}

// Validate validates this post families body
func (o *PostFamiliesBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAttributeAsLabel(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateAttributeRequirements(formats); err != nil {
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

func (o *PostFamiliesBody) validateAttributeAsLabel(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"attribute_as_label", "body", o.AttributeAsLabel); err != nil {
		return err
	}

	return nil
}

func (o *PostFamiliesBody) validateAttributeRequirements(formats strfmt.Registry) error {

	if swag.IsZero(o.AttributeRequirements) { // not required
		return nil
	}

	if o.AttributeRequirements != nil {
		if err := o.AttributeRequirements.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "attribute_requirements")
			}
			return err
		}
	}

	return nil
}

func (o *PostFamiliesBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PostFamiliesBody) validateLabels(formats strfmt.Registry) error {

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
func (o *PostFamiliesBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesBody) UnmarshalBinary(b []byte) error {
	var res PostFamiliesBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesForbiddenBody post families forbidden body
swagger:model PostFamiliesForbiddenBody
*/
type PostFamiliesForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post families forbidden body
func (o *PostFamiliesForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PostFamiliesForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesParamsBodyAttributeRequirements Attributes codes of the family that are required for the completeness calculation for each channel
swagger:model PostFamiliesParamsBodyAttributeRequirements
*/
type PostFamiliesParamsBodyAttributeRequirements struct {

	// channel code
	ChannelCode []string `json:"channelCode"`
}

// Validate validates this post families params body attribute requirements
func (o *PostFamiliesParamsBodyAttributeRequirements) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesParamsBodyAttributeRequirements) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesParamsBodyAttributeRequirements) UnmarshalBinary(b []byte) error {
	var res PostFamiliesParamsBodyAttributeRequirements
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesParamsBodyLabels Family labels for each locale
swagger:model PostFamiliesParamsBodyLabels
*/
type PostFamiliesParamsBodyLabels struct {

	// Family label for the locale `localeCode`
	LocaleCode string `json:"localeCode,omitempty"`
}

// Validate validates this post families params body labels
func (o *PostFamiliesParamsBodyLabels) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesParamsBodyLabels) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesParamsBodyLabels) UnmarshalBinary(b []byte) error {
	var res PostFamiliesParamsBodyLabels
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesUnauthorizedBody post families unauthorized body
swagger:model PostFamiliesUnauthorizedBody
*/
type PostFamiliesUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post families unauthorized body
func (o *PostFamiliesUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PostFamiliesUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesUnprocessableEntityBody post families unprocessable entity body
swagger:model PostFamiliesUnprocessableEntityBody
*/
type PostFamiliesUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post families unprocessable entity body
func (o *PostFamiliesUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PostFamiliesUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostFamiliesUnsupportedMediaTypeBody post families unsupported media type body
swagger:model PostFamiliesUnsupportedMediaTypeBody
*/
type PostFamiliesUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post families unsupported media type body
func (o *PostFamiliesUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostFamiliesUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostFamiliesUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PostFamiliesUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
