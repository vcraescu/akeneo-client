// Code generated by go-swagger; DO NOT EDIT.

package product_model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// GetProductModelsCodeReader is a Reader for the GetProductModelsCode structure.
type GetProductModelsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetProductModelsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetProductModelsCodeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetProductModelsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetProductModelsCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetProductModelsCodeNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetProductModelsCodeOK creates a GetProductModelsCodeOK with default headers values
func NewGetProductModelsCodeOK() *GetProductModelsCodeOK {
	return &GetProductModelsCodeOK{}
}

/*GetProductModelsCodeOK handles this case with default header values.

OK
*/
type GetProductModelsCodeOK struct {
	Payload *GetProductModelsCodeOKBody
}

func (o *GetProductModelsCodeOK) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/product-models/{code}][%d] getProductModelsCodeOK  %+v", 200, o.Payload)
}

func (o *GetProductModelsCodeOK) GetPayload() *GetProductModelsCodeOKBody {
	return o.Payload
}

func (o *GetProductModelsCodeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetProductModelsCodeOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProductModelsCodeUnauthorized creates a GetProductModelsCodeUnauthorized with default headers values
func NewGetProductModelsCodeUnauthorized() *GetProductModelsCodeUnauthorized {
	return &GetProductModelsCodeUnauthorized{}
}

/*GetProductModelsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type GetProductModelsCodeUnauthorized struct {
	Payload *GetProductModelsCodeUnauthorizedBody
}

func (o *GetProductModelsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/product-models/{code}][%d] getProductModelsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GetProductModelsCodeUnauthorized) GetPayload() *GetProductModelsCodeUnauthorizedBody {
	return o.Payload
}

func (o *GetProductModelsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetProductModelsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProductModelsCodeNotFound creates a GetProductModelsCodeNotFound with default headers values
func NewGetProductModelsCodeNotFound() *GetProductModelsCodeNotFound {
	return &GetProductModelsCodeNotFound{}
}

/*GetProductModelsCodeNotFound handles this case with default header values.

Resource not found
*/
type GetProductModelsCodeNotFound struct {
	Payload *GetProductModelsCodeNotFoundBody
}

func (o *GetProductModelsCodeNotFound) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/product-models/{code}][%d] getProductModelsCodeNotFound  %+v", 404, o.Payload)
}

func (o *GetProductModelsCodeNotFound) GetPayload() *GetProductModelsCodeNotFoundBody {
	return o.Payload
}

func (o *GetProductModelsCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetProductModelsCodeNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProductModelsCodeNotAcceptable creates a GetProductModelsCodeNotAcceptable with default headers values
func NewGetProductModelsCodeNotAcceptable() *GetProductModelsCodeNotAcceptable {
	return &GetProductModelsCodeNotAcceptable{}
}

/*GetProductModelsCodeNotAcceptable handles this case with default header values.

Not Acceptable
*/
type GetProductModelsCodeNotAcceptable struct {
	Payload *GetProductModelsCodeNotAcceptableBody
}

func (o *GetProductModelsCodeNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /api/rest/v1/product-models/{code}][%d] getProductModelsCodeNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetProductModelsCodeNotAcceptable) GetPayload() *GetProductModelsCodeNotAcceptableBody {
	return o.Payload
}

func (o *GetProductModelsCodeNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetProductModelsCodeNotAcceptableBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*GetProductModelsCodeNotAcceptableBody get product models code not acceptable body
swagger:model GetProductModelsCodeNotAcceptableBody
*/
type GetProductModelsCodeNotAcceptableBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get product models code not acceptable body
func (o *GetProductModelsCodeNotAcceptableBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeNotAcceptableBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeNotAcceptableBody) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeNotAcceptableBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeNotFoundBody get product models code not found body
swagger:model GetProductModelsCodeNotFoundBody
*/
type GetProductModelsCodeNotFoundBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get product models code not found body
func (o *GetProductModelsCodeNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBody get product models code o k body
swagger:model GetProductModelsCodeOKBody
*/
type GetProductModelsCodeOKBody struct {

	// associations
	Associations *GetProductModelsCodeOKBodyAssociations `json:"associations,omitempty"`

	// Codes of the categories in which the product model is categorized
	Categories []string `json:"categories"`

	// Product model code
	// Required: true
	Code *string `json:"code"`

	// Date of creation
	Created string `json:"created,omitempty"`

	// Family code  from which the product inherits its attributes and attributes requirements (since the 3.2)
	Family string `json:"family,omitempty"`

	// Family variant code from which the product model inherits its attributes and variant attributes
	// Required: true
	FamilyVariant *string `json:"family_variant"`

	// metadata
	Metadata *GetProductModelsCodeOKBodyMetadata `json:"metadata,omitempty"`

	// Code of the parent product model. This parent can be modified since the 2.3.
	Parent *string `json:"parent,omitempty"`

	// quantified associations
	QuantifiedAssociations *GetProductModelsCodeOKBodyQuantifiedAssociations `json:"quantified_associations,omitempty"`

	// Date of the last update
	Updated string `json:"updated,omitempty"`

	// values
	Values *GetProductModelsCodeOKBodyValues `json:"values,omitempty"`
}

// Validate validates this get product models code o k body
func (o *GetProductModelsCodeOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAssociations(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateFamilyVariant(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateQuantifiedAssociations(formats); err != nil {
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

func (o *GetProductModelsCodeOKBody) validateAssociations(formats strfmt.Registry) error {

	if swag.IsZero(o.Associations) { // not required
		return nil
	}

	if o.Associations != nil {
		if err := o.Associations.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getProductModelsCodeOK" + "." + "associations")
			}
			return err
		}
	}

	return nil
}

func (o *GetProductModelsCodeOKBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("getProductModelsCodeOK"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *GetProductModelsCodeOKBody) validateFamilyVariant(formats strfmt.Registry) error {

	if err := validate.Required("getProductModelsCodeOK"+"."+"family_variant", "body", o.FamilyVariant); err != nil {
		return err
	}

	return nil
}

func (o *GetProductModelsCodeOKBody) validateMetadata(formats strfmt.Registry) error {

	if swag.IsZero(o.Metadata) { // not required
		return nil
	}

	if o.Metadata != nil {
		if err := o.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getProductModelsCodeOK" + "." + "metadata")
			}
			return err
		}
	}

	return nil
}

func (o *GetProductModelsCodeOKBody) validateQuantifiedAssociations(formats strfmt.Registry) error {

	if swag.IsZero(o.QuantifiedAssociations) { // not required
		return nil
	}

	if o.QuantifiedAssociations != nil {
		if err := o.QuantifiedAssociations.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getProductModelsCodeOK" + "." + "quantified_associations")
			}
			return err
		}
	}

	return nil
}

func (o *GetProductModelsCodeOKBody) validateValues(formats strfmt.Registry) error {

	if swag.IsZero(o.Values) { // not required
		return nil
	}

	if o.Values != nil {
		if err := o.Values.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getProductModelsCodeOK" + "." + "values")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBody) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyAssociations Several associations related to groups, product and/or other product models, grouped by association types
swagger:model GetProductModelsCodeOKBodyAssociations
*/
type GetProductModelsCodeOKBodyAssociations struct {

	// association type code
	AssociationTypeCode *GetProductModelsCodeOKBodyAssociationsAssociationTypeCode `json:"associationTypeCode,omitempty"`
}

// Validate validates this get product models code o k body associations
func (o *GetProductModelsCodeOKBodyAssociations) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAssociationTypeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetProductModelsCodeOKBodyAssociations) validateAssociationTypeCode(formats strfmt.Registry) error {

	if swag.IsZero(o.AssociationTypeCode) { // not required
		return nil
	}

	if o.AssociationTypeCode != nil {
		if err := o.AssociationTypeCode.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getProductModelsCodeOK" + "." + "associations" + "." + "associationTypeCode")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyAssociations) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyAssociations) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyAssociations
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyAssociationsAssociationTypeCode get product models code o k body associations association type code
swagger:model GetProductModelsCodeOKBodyAssociationsAssociationTypeCode
*/
type GetProductModelsCodeOKBodyAssociationsAssociationTypeCode struct {

	// Array of groups codes with which the product is in relation
	Groups []string `json:"groups"`

	// Array of product model codes with which the product is in relation (only available since the v2.1)
	ProductModels []string `json:"product_models"`

	// Array of product identifiers with which the product is in relation
	Products []string `json:"products"`
}

// Validate validates this get product models code o k body associations association type code
func (o *GetProductModelsCodeOKBodyAssociationsAssociationTypeCode) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyAssociationsAssociationTypeCode) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyAssociationsAssociationTypeCode) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyAssociationsAssociationTypeCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyMetadata More information around the product model (only available since the v2.3 in the Enterprise Edition)
swagger:model GetProductModelsCodeOKBodyMetadata
*/
type GetProductModelsCodeOKBodyMetadata struct {

	// Status of the product model regarding the user permissions (only available since the v2.3 in the Enterprise Edition)
	// Enum: [read_only draft_in_progress proposal_waiting_for_approval working_copy]
	WorkflowStatus string `json:"workflow_status,omitempty"`
}

// Validate validates this get product models code o k body metadata
func (o *GetProductModelsCodeOKBodyMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateWorkflowStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var getProductModelsCodeOKBodyMetadataTypeWorkflowStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["read_only","draft_in_progress","proposal_waiting_for_approval","working_copy"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getProductModelsCodeOKBodyMetadataTypeWorkflowStatusPropEnum = append(getProductModelsCodeOKBodyMetadataTypeWorkflowStatusPropEnum, v)
	}
}

const (

	// GetProductModelsCodeOKBodyMetadataWorkflowStatusReadOnly captures enum value "read_only"
	GetProductModelsCodeOKBodyMetadataWorkflowStatusReadOnly string = "read_only"

	// GetProductModelsCodeOKBodyMetadataWorkflowStatusDraftInProgress captures enum value "draft_in_progress"
	GetProductModelsCodeOKBodyMetadataWorkflowStatusDraftInProgress string = "draft_in_progress"

	// GetProductModelsCodeOKBodyMetadataWorkflowStatusProposalWaitingForApproval captures enum value "proposal_waiting_for_approval"
	GetProductModelsCodeOKBodyMetadataWorkflowStatusProposalWaitingForApproval string = "proposal_waiting_for_approval"

	// GetProductModelsCodeOKBodyMetadataWorkflowStatusWorkingCopy captures enum value "working_copy"
	GetProductModelsCodeOKBodyMetadataWorkflowStatusWorkingCopy string = "working_copy"
)

// prop value enum
func (o *GetProductModelsCodeOKBodyMetadata) validateWorkflowStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getProductModelsCodeOKBodyMetadataTypeWorkflowStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *GetProductModelsCodeOKBodyMetadata) validateWorkflowStatus(formats strfmt.Registry) error {

	if swag.IsZero(o.WorkflowStatus) { // not required
		return nil
	}

	// value enum
	if err := o.validateWorkflowStatusEnum("getProductModelsCodeOK"+"."+"metadata"+"."+"workflow_status", "body", o.WorkflowStatus); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyMetadata) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyMetadata) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyQuantifiedAssociations Several quantified associations related to products and/or product models, grouped by quantified association types (only available in Serenity)
swagger:model GetProductModelsCodeOKBodyQuantifiedAssociations
*/
type GetProductModelsCodeOKBodyQuantifiedAssociations struct {

	// quantified association type code
	QuantifiedAssociationTypeCode *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode `json:"quantifiedAssociationTypeCode,omitempty"`
}

// Validate validates this get product models code o k body quantified associations
func (o *GetProductModelsCodeOKBodyQuantifiedAssociations) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateQuantifiedAssociationTypeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetProductModelsCodeOKBodyQuantifiedAssociations) validateQuantifiedAssociationTypeCode(formats strfmt.Registry) error {

	if swag.IsZero(o.QuantifiedAssociationTypeCode) { // not required
		return nil
	}

	if o.QuantifiedAssociationTypeCode != nil {
		if err := o.QuantifiedAssociationTypeCode.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("getProductModelsCodeOK" + "." + "quantified_associations" + "." + "quantifiedAssociationTypeCode")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociations) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociations) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyQuantifiedAssociations
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode get product models code o k body quantified associations quantified association type code
swagger:model GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode
*/
type GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode struct {

	// Array of objects containing product model codes and quantities with which the product model is in relation
	ProductModels []*GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 `json:"product_models"`

	// Array of objects containing product identifiers and quantities with which the product model is in relation
	Products []*GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 `json:"products"`
}

// Validate validates this get product models code o k body quantified associations quantified association type code
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateProductModels(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateProducts(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) validateProductModels(formats strfmt.Registry) error {

	if swag.IsZero(o.ProductModels) { // not required
		return nil
	}

	for i := 0; i < len(o.ProductModels); i++ {
		if swag.IsZero(o.ProductModels[i]) { // not required
			continue
		}

		if o.ProductModels[i] != nil {
			if err := o.ProductModels[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getProductModelsCodeOK" + "." + "quantified_associations" + "." + "quantifiedAssociationTypeCode" + "." + "product_models" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) validateProducts(formats strfmt.Registry) error {

	if swag.IsZero(o.Products) { // not required
		return nil
	}

	for i := 0; i < len(o.Products); i++ {
		if swag.IsZero(o.Products[i]) { // not required
			continue
		}

		if o.Products[i] != nil {
			if err := o.Products[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getProductModelsCodeOK" + "." + "quantified_associations" + "." + "quantifiedAssociationTypeCode" + "." + "products" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 get product models code o k body quantified associations quantified association type code product models items0
swagger:model GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0
*/
type GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 struct {

	// code
	Code string `json:"code,omitempty"`

	// quantity
	Quantity int64 `json:"quantity,omitempty"`
}

// Validate validates this get product models code o k body quantified associations quantified association type code product models items0
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 get product models code o k body quantified associations quantified association type code products items0
swagger:model GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0
*/
type GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 struct {

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// quantity
	Quantity int64 `json:"quantity,omitempty"`
}

// Validate validates this get product models code o k body quantified associations quantified association type code products items0
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyValues Product model attributes values, see <a href='/concepts/products.html#focus-on-the-products-values'>Product values</a> section for more details
swagger:model GetProductModelsCodeOKBodyValues
*/
type GetProductModelsCodeOKBodyValues struct {

	// attribute code
	AttributeCode []*GetProductModelsCodeOKBodyValuesAttributeCodeItems0 `json:"attributeCode"`
}

// Validate validates this get product models code o k body values
func (o *GetProductModelsCodeOKBodyValues) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAttributeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetProductModelsCodeOKBodyValues) validateAttributeCode(formats strfmt.Registry) error {

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
					return ve.ValidateName("getProductModelsCodeOK" + "." + "values" + "." + "attributeCode" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyValues) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyValues) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyValues
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeOKBodyValuesAttributeCodeItems0 get product models code o k body values attribute code items0
swagger:model GetProductModelsCodeOKBodyValuesAttributeCodeItems0
*/
type GetProductModelsCodeOKBodyValuesAttributeCodeItems0 struct {

	// Product value
	Data interface{} `json:"data,omitempty"`

	// Locale code of the product value
	Locale string `json:"locale,omitempty"`

	// Channel code of the product value
	Scope string `json:"scope,omitempty"`
}

// Validate validates this get product models code o k body values attribute code items0
func (o *GetProductModelsCodeOKBodyValuesAttributeCodeItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyValuesAttributeCodeItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeOKBodyValuesAttributeCodeItems0) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeOKBodyValuesAttributeCodeItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*GetProductModelsCodeUnauthorizedBody get product models code unauthorized body
swagger:model GetProductModelsCodeUnauthorizedBody
*/
type GetProductModelsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this get product models code unauthorized body
func (o *GetProductModelsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetProductModelsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetProductModelsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetProductModelsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}