// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset_variation_file

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GetVariationFilesChannelCodeLocaleCodeDownloadReader is a Reader for the GetVariationFilesChannelCodeLocaleCodeDownload structure.
type GetVariationFilesChannelCodeLocaleCodeDownloadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetVariationFilesChannelCodeLocaleCodeDownloadOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetVariationFilesChannelCodeLocaleCodeDownloadForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetVariationFilesChannelCodeLocaleCodeDownloadNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadOK creates a GetVariationFilesChannelCodeLocaleCodeDownloadOK with default headers values
func NewGetVariationFilesChannelCodeLocaleCodeDownloadOK() *GetVariationFilesChannelCodeLocaleCodeDownloadOK {
	return &GetVariationFilesChannelCodeLocaleCodeDownloadOK{}
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadOK handles this case with default header values.

OK
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadOK struct {
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{asset_code}/variation-files/{channel_code}/{locale_code}/download][%d] getVariationFilesChannelCodeLocaleCodeDownloadOK ", 200)
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized creates a GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized with default headers values
func NewGetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized() *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized {
	return &GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized{}
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized handles this case with default header values.

Authentication required
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized struct {
	Payload *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{asset_code}/variation-files/{channel_code}/{locale_code}/download][%d] getVariationFilesChannelCodeLocaleCodeDownloadUnauthorized  %+v", 401, o.Payload)
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized) GetPayload() *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody {
	return o.Payload
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadForbidden creates a GetVariationFilesChannelCodeLocaleCodeDownloadForbidden with default headers values
func NewGetVariationFilesChannelCodeLocaleCodeDownloadForbidden() *GetVariationFilesChannelCodeLocaleCodeDownloadForbidden {
	return &GetVariationFilesChannelCodeLocaleCodeDownloadForbidden{}
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadForbidden handles this case with default header values.

Access forbidden
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadForbidden struct {
	Payload *GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{asset_code}/variation-files/{channel_code}/{locale_code}/download][%d] getVariationFilesChannelCodeLocaleCodeDownloadForbidden  %+v", 403, o.Payload)
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadForbidden) GetPayload() *GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody {
	return o.Payload
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadNotFound creates a GetVariationFilesChannelCodeLocaleCodeDownloadNotFound with default headers values
func NewGetVariationFilesChannelCodeLocaleCodeDownloadNotFound() *GetVariationFilesChannelCodeLocaleCodeDownloadNotFound {
	return &GetVariationFilesChannelCodeLocaleCodeDownloadNotFound{}
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadNotFound handles this case with default header values.

Resource not found
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadNotFound struct {
	Payload *GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{asset_code}/variation-files/{channel_code}/{locale_code}/download][%d] getVariationFilesChannelCodeLocaleCodeDownloadNotFound  %+v", 404, o.Payload)
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadNotFound) GetPayload() *GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody {
	return o.Payload
}

func (o *GetVariationFilesChannelCodeLocaleCodeDownloadNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody get variation files channel code locale code download forbidden body
swagger:model GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get variation files channel code locale code download forbidden body
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetVariationFilesChannelCodeLocaleCodeDownloadForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody get variation files channel code locale code download not found body
swagger:model GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get variation files channel code locale code download not found body
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetVariationFilesChannelCodeLocaleCodeDownloadNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody get variation files channel code locale code download unauthorized body
swagger:model GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get variation files channel code locale code download unauthorized body
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetVariationFilesChannelCodeLocaleCodeDownloadUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
