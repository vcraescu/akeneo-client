// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset

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

// GetPamAssetsCodeReader is a Reader for the GetPamAssetsCode structure.
type GetPamAssetsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPamAssetsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPamAssetsCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetPamAssetsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetPamAssetsCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetPamAssetsCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetPamAssetsCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetPamAssetsCodeOK creates a GetPamAssetsCodeOK with default headers values
func NewGetPamAssetsCodeOK() *GetPamAssetsCodeOK {
	return &GetPamAssetsCodeOK{}
}

/*GetPamAssetsCodeOK handles this case with default header values.

OK
*/
type GetPamAssetsCodeOK struct {
	Payload *GetPamAssetsCodeOKBody
}

func (o *GetPamAssetsCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{code}][%d] getPamAssetsCodeOK  %+v", 200, o.Payload)
}

func (o *GetPamAssetsCodeOK) GetPayload() *GetPamAssetsCodeOKBody {
	return o.Payload
}

func (o *GetPamAssetsCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPamAssetsCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPamAssetsCodeUnauthorized creates a GetPamAssetsCodeUnauthorized with default headers values
func NewGetPamAssetsCodeUnauthorized() *GetPamAssetsCodeUnauthorized {
	return &GetPamAssetsCodeUnauthorized{}
}

/*GetPamAssetsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetPamAssetsCodeUnauthorized struct {
	Payload *GetPamAssetsCodeUnauthorizedBody
}

func (o *GetPamAssetsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{code}][%d] getPamAssetsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPamAssetsCodeUnauthorized) GetPayload() *GetPamAssetsCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetPamAssetsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPamAssetsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPamAssetsCodeForbidden creates a GetPamAssetsCodeForbidden with default headers values
func NewGetPamAssetsCodeForbidden() *GetPamAssetsCodeForbidden {
	return &GetPamAssetsCodeForbidden{}
}

/*GetPamAssetsCodeForbidden handles this case with default header values.

Access forbidden
*/
type GetPamAssetsCodeForbidden struct {
	Payload *GetPamAssetsCodeForbiddenBody
}

func (o *GetPamAssetsCodeForbidden) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{code}][%d] getPamAssetsCodeForbidden  %+v", 403, o.Payload)
}

func (o *GetPamAssetsCodeForbidden) GetPayload() *GetPamAssetsCodeForbiddenBody {
	return o.Payload
}

func (o *GetPamAssetsCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPamAssetsCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPamAssetsCodeNotFound creates a GetPamAssetsCodeNotFound with default headers values
func NewGetPamAssetsCodeNotFound() *GetPamAssetsCodeNotFound {
	return &GetPamAssetsCodeNotFound{}
}

/*GetPamAssetsCodeNotFound handles this case with default header values.

Resource not found
*/
type GetPamAssetsCodeNotFound struct {
	Payload *GetPamAssetsCodeNotFoundBody
}

func (o *GetPamAssetsCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{code}][%d] getPamAssetsCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetPamAssetsCodeNotFound) GetPayload() *GetPamAssetsCodeNotFoundBody {
	return o.Payload
}

func (o *GetPamAssetsCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPamAssetsCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPamAssetsCodeNotAcceptable creates a GetPamAssetsCodeNotAcceptable with default headers values
func NewGetPamAssetsCodeNotAcceptable() *GetPamAssetsCodeNotAcceptable {
	return &GetPamAssetsCodeNotAcceptable{}
}

/*GetPamAssetsCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetPamAssetsCodeNotAcceptable struct {
	Payload *GetPamAssetsCodeNotAcceptableBody
}

func (o *GetPamAssetsCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/assets/{code}][%d] getPamAssetsCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetPamAssetsCodeNotAcceptable) GetPayload() *GetPamAssetsCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetPamAssetsCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPamAssetsCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetPamAssetsCodeForbiddenBody get pam assets code forbidden body
swagger:model GetPamAssetsCodeForbiddenBody
*/
type GetPamAssetsCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get pam assets code forbidden body
func (o *GetPamAssetsCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeNotAcceptableBody get pam assets code not acceptable body
swagger:model GetPamAssetsCodeNotAcceptableBody
*/
type GetPamAssetsCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get pam assets code not acceptable body
func (o *GetPamAssetsCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeNotFoundBody get pam assets code not found body
swagger:model GetPamAssetsCodeNotFoundBody
*/
type GetPamAssetsCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get pam assets code not found body
func (o *GetPamAssetsCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBody get pam assets code o k body
swagger:model GetPamAssetsCodeOKBody
*/
type GetPamAssetsCodeOKBody struct {

	// Codes of the PAM asset categories in which the asset is classified
	Categories []string `json:"categories"`

	// PAM asset code
	// Required: true
	Code *string `json:"code"`

	// Description of the PAM asset
	Description string `json:"description,omitempty"`

	// Date on which the PAM asset expire
	EndOfUse string `json:"end_of_use,omitempty"`

	// Whether the asset is localized or not, meaning if you want to have different reference files for each of your locale
	Localizable *bool `json:"localizable,omitempty"`

	// Reference files of the PAM asset
	ReferenceFiles []*GetPamAssetsCodeOKBodyReferenceFilesItems0 `json:"reference_files"`

	// Tags of the PAM asset
	Tags []string `json:"tags"`

	// Variations of the PAM asset
	VariationFiles []*GetPamAssetsCodeOKBodyVariationFilesItems0 `json:"variation_files"`
}

// Validate validates this get pam assets code o k body
func (o *GetPamAssetsCodeOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateReferenceFiles(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateVariationFiles(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPamAssetsCodeOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("getPamAssetsCodeOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetPamAssetsCodeOKBody) validateReferenceFiles(formats strfmt.Registry) error {

	if swag.IsZero(o.ReferenceFiles) { // not required
		return nil
	}

	for i := 0; i < len(o.ReferenceFiles); i++ {
		if swag.IsZero(o.ReferenceFiles[i]) { // not required
			continue
		}

		if o.ReferenceFiles[i] != nil {
			if err := o.ReferenceFiles[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getPamAssetsCodeOK" + "." + "reference_files" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (o *GetPamAssetsCodeOKBody) validateVariationFiles(formats strfmt.Registry) error {

	if swag.IsZero(o.VariationFiles) { // not required
		return nil
	}

	for i := 0; i < len(o.VariationFiles); i++ {
		if swag.IsZero(o.VariationFiles[i]) { // not required
			continue
		}

		if o.VariationFiles[i] != nil {
			if err := o.VariationFiles[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getPamAssetsCodeOK" + "." + "variation_files" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyReferenceFilesItems0 get pam assets code o k body reference files items0
swagger:model GetPamAssetsCodeOKBodyReferenceFilesItems0
*/
type GetPamAssetsCodeOKBodyReferenceFilesItems0 struct {

	// link
	Link *GetPamAssetsCodeOKBodyReferenceFilesItems0Link `json:"_link,omitempty"`

	// Code of the reference file
	Code string `json:"code,omitempty"`

	// Locale code of the reference file
	Locale string `json:"locale,omitempty"`
}

// Validate validates this get pam assets code o k body reference files items0
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLink(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0) validateLink(formats strfmt.Registry) error {

	if swag.IsZero(o.Link) { // not required
		return nil
	}

	if o.Link != nil {
		if err := o.Link.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyReferenceFilesItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyReferenceFilesItems0Link Links to get and download the reference file
swagger:model GetPamAssetsCodeOKBodyReferenceFilesItems0Link
*/
type GetPamAssetsCodeOKBodyReferenceFilesItems0Link struct {

	// download
	Download *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload `json:"download,omitempty"`

	// self
	Self *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf `json:"self,omitempty"`
}

// Validate validates this get pam assets code o k body reference files items0 link
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0Link) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateDownload(formats); err != nil {
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

func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0Link) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(o.Download) { // not required
		return nil
	}

	if o.Download != nil {
		if err := o.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0Link) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0Link) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0Link) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyReferenceFilesItems0Link
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload get pam assets code o k body reference files items0 link download
swagger:model GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload
*/
type GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload struct {

	// URI to download the reference file
	Href string `json:"href,omitempty"`
}

// Validate validates this get pam assets code o k body reference files items0 link download
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyReferenceFilesItems0LinkDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf get pam assets code o k body reference files items0 link self
swagger:model GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf
*/
type GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf struct {

	// URI of the reference file entity
	Href string `json:"href,omitempty"`
}

// Validate validates this get pam assets code o k body reference files items0 link self
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyReferenceFilesItems0LinkSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyVariationFilesItems0 get pam assets code o k body variation files items0
swagger:model GetPamAssetsCodeOKBodyVariationFilesItems0
*/
type GetPamAssetsCodeOKBodyVariationFilesItems0 struct {

	// link
	Link *GetPamAssetsCodeOKBodyVariationFilesItems0Link `json:"_link,omitempty"`

	// Code of the variation
	Code string `json:"code,omitempty"`

	// Locale code of the variation
	Locale string `json:"locale,omitempty"`

	// Channel code of the variation
	Scope string `json:"scope,omitempty"`
}

// Validate validates this get pam assets code o k body variation files items0
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLink(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPamAssetsCodeOKBodyVariationFilesItems0) validateLink(formats strfmt.Registry) error {

	if swag.IsZero(o.Link) { // not required
		return nil
	}

	if o.Link != nil {
		if err := o.Link.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyVariationFilesItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyVariationFilesItems0Link Links to get and download the variation file
swagger:model GetPamAssetsCodeOKBodyVariationFilesItems0Link
*/
type GetPamAssetsCodeOKBodyVariationFilesItems0Link struct {

	// download
	Download *GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload `json:"download,omitempty"`

	// self
	Self *GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf `json:"self,omitempty"`
}

// Validate validates this get pam assets code o k body variation files items0 link
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0Link) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateDownload(formats); err != nil {
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

func (o *GetPamAssetsCodeOKBodyVariationFilesItems0Link) validateDownload(formats strfmt.Registry) error {

	if swag.IsZero(o.Download) { // not required
		return nil
	}

	if o.Download != nil {
		if err := o.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (o *GetPamAssetsCodeOKBodyVariationFilesItems0Link) validateSelf(formats strfmt.Registry) error {

	if swag.IsZero(o.Self) { // not required
		return nil
	}

	if o.Self != nil {
		if err := o.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_link" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0Link) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0Link) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyVariationFilesItems0Link
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload get pam assets code o k body variation files items0 link download
swagger:model GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload
*/
type GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload struct {

	// URI to download the variation file
	Href string `json:"href,omitempty"`
}

// Validate validates this get pam assets code o k body variation files items0 link download
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyVariationFilesItems0LinkDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf get pam assets code o k body variation files items0 link self
swagger:model GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf
*/
type GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf struct {

	// URI of the variation entity
	Href string `json:"href,omitempty"`
}

// Validate validates this get pam assets code o k body variation files items0 link self
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeOKBodyVariationFilesItems0LinkSelf
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetPamAssetsCodeUnauthorizedBody get pam assets code unauthorized body
swagger:model GetPamAssetsCodeUnauthorizedBody
*/
type GetPamAssetsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get pam assets code unauthorized body
func (o *GetPamAssetsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPamAssetsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPamAssetsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetPamAssetsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}