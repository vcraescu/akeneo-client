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

// PostProductModelsReader is a Reader for the PostProductModels structure.
type PostProductModelsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostProductModelsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostProductModelsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostProductModelsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostProductModelsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPostProductModelsUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPostProductModelsUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostProductModelsCreated creates a PostProductModelsCreated with default headers values
func NewPostProductModelsCreated() *PostProductModelsCreated {
	return &PostProductModelsCreated{}
}

/*PostProductModelsCreated handles this case with default header values.

Created
*/
type PostProductModelsCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PostProductModelsCreated) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/product-models][%d] postProductModelsCreated ", 201)
}

func (o *PostProductModelsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPostProductModelsBadRequest creates a PostProductModelsBadRequest with default headers values
func NewPostProductModelsBadRequest() *PostProductModelsBadRequest {
	return &PostProductModelsBadRequest{}
}

/*PostProductModelsBadRequest handles this case with default header values.

Bad request
*/
type PostProductModelsBadRequest struct {
	Payload *PostProductModelsBadRequestBody
}

func (o *PostProductModelsBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/product-models][%d] postProductModelsBadRequest  %+v", 400, o.Payload)
}

func (o *PostProductModelsBadRequest) GetPayload() *PostProductModelsBadRequestBody {
	return o.Payload
}

func (o *PostProductModelsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostProductModelsBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostProductModelsUnauthorized creates a PostProductModelsUnauthorized with default headers values
func NewPostProductModelsUnauthorized() *PostProductModelsUnauthorized {
	return &PostProductModelsUnauthorized{}
}

/*PostProductModelsUnauthorized handles this case with default header values.

Authentication required
*/
type PostProductModelsUnauthorized struct {
	Payload *PostProductModelsUnauthorizedBody
}

func (o *PostProductModelsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/product-models][%d] postProductModelsUnauthorized  %+v", 401, o.Payload)
}

func (o *PostProductModelsUnauthorized) GetPayload() *PostProductModelsUnauthorizedBody {
	return o.Payload
}

func (o *PostProductModelsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostProductModelsUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostProductModelsUnsupportedMediaType creates a PostProductModelsUnsupportedMediaType with default headers values
func NewPostProductModelsUnsupportedMediaType() *PostProductModelsUnsupportedMediaType {
	return &PostProductModelsUnsupportedMediaType{}
}

/*PostProductModelsUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PostProductModelsUnsupportedMediaType struct {
	Payload *PostProductModelsUnsupportedMediaTypeBody
}

func (o *PostProductModelsUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/product-models][%d] postProductModelsUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PostProductModelsUnsupportedMediaType) GetPayload() *PostProductModelsUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PostProductModelsUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostProductModelsUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostProductModelsUnprocessableEntity creates a PostProductModelsUnprocessableEntity with default headers values
func NewPostProductModelsUnprocessableEntity() *PostProductModelsUnprocessableEntity {
	return &PostProductModelsUnprocessableEntity{}
}

/*PostProductModelsUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PostProductModelsUnprocessableEntity struct {
	Payload *PostProductModelsUnprocessableEntityBody
}

func (o *PostProductModelsUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/rest/v1/product-models][%d] postProductModelsUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PostProductModelsUnprocessableEntity) GetPayload() *PostProductModelsUnprocessableEntityBody {
	return o.Payload
}

func (o *PostProductModelsUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostProductModelsUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PostProductModelsBadRequestBody post product models bad request body
swagger:model PostProductModelsBadRequestBody
*/
type PostProductModelsBadRequestBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post product models bad request body
func (o *PostProductModelsBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PostProductModelsBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsBody post product models body
swagger:model PostProductModelsBody
*/
type PostProductModelsBody struct {

	// associations
	Associations *PostProductModelsParamsBodyAssociations `json:"associations,omitempty"`

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
	Metadata *PostProductModelsParamsBodyMetadata `json:"metadata,omitempty"`

	// Code of the parent product model. This parent can be modified since the 2.3.
	Parent *string `json:"parent,omitempty"`

	// quantified associations
	QuantifiedAssociations *PostProductModelsParamsBodyQuantifiedAssociations `json:"quantified_associations,omitempty"`

	// Date of the last update
	Updated string `json:"updated,omitempty"`

	// values
	Values *PostProductModelsParamsBodyValues `json:"values,omitempty"`
}

// Validate validates this post product models body
func (o *PostProductModelsBody) Validate(formats strfmt.Registry) error {
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

func (o *PostProductModelsBody) validateAssociations(formats strfmt.Registry) error {

	if swag.IsZero(o.Associations) { // not required
		return nil
	}

	if o.Associations != nil {
		if err := o.Associations.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "associations")
			}
			return err
		}
	}

	return nil
}

func (o *PostProductModelsBody) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"code", "body", o.Code); err != nil {
		return err
	}

	return nil
}

func (o *PostProductModelsBody) validateFamilyVariant(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"family_variant", "body", o.FamilyVariant); err != nil {
		return err
	}

	return nil
}

func (o *PostProductModelsBody) validateMetadata(formats strfmt.Registry) error {

	if swag.IsZero(o.Metadata) { // not required
		return nil
	}

	if o.Metadata != nil {
		if err := o.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "metadata")
			}
			return err
		}
	}

	return nil
}

func (o *PostProductModelsBody) validateQuantifiedAssociations(formats strfmt.Registry) error {

	if swag.IsZero(o.QuantifiedAssociations) { // not required
		return nil
	}

	if o.QuantifiedAssociations != nil {
		if err := o.QuantifiedAssociations.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "quantified_associations")
			}
			return err
		}
	}

	return nil
}

func (o *PostProductModelsBody) validateValues(formats strfmt.Registry) error {

	if swag.IsZero(o.Values) { // not required
		return nil
	}

	if o.Values != nil {
		if err := o.Values.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "values")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsBody) UnmarshalBinary(b []byte) error {
	var res PostProductModelsBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyAssociations Several associations related to groups, product and/or other product models, grouped by association types
swagger:model PostProductModelsParamsBodyAssociations
*/
type PostProductModelsParamsBodyAssociations struct {

	// association type code
	AssociationTypeCode *PostProductModelsParamsBodyAssociationsAssociationTypeCode `json:"associationTypeCode,omitempty"`
}

// Validate validates this post product models params body associations
func (o *PostProductModelsParamsBodyAssociations) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAssociationTypeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostProductModelsParamsBodyAssociations) validateAssociationTypeCode(formats strfmt.Registry) error {

	if swag.IsZero(o.AssociationTypeCode) { // not required
		return nil
	}

	if o.AssociationTypeCode != nil {
		if err := o.AssociationTypeCode.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "associations" + "." + "associationTypeCode")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyAssociations) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyAssociations) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyAssociations
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyAssociationsAssociationTypeCode post product models params body associations association type code
swagger:model PostProductModelsParamsBodyAssociationsAssociationTypeCode
*/
type PostProductModelsParamsBodyAssociationsAssociationTypeCode struct {

	// Array of groups codes with which the product is in relation
	Groups []string `json:"groups"`

	// Array of product model codes with which the product is in relation (only available since the v2.1)
	ProductModels []string `json:"product_models"`

	// Array of product identifiers with which the product is in relation
	Products []string `json:"products"`
}

// Validate validates this post product models params body associations association type code
func (o *PostProductModelsParamsBodyAssociationsAssociationTypeCode) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyAssociationsAssociationTypeCode) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyAssociationsAssociationTypeCode) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyAssociationsAssociationTypeCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyMetadata More information around the product model (only available since the v2.3 in the Enterprise Edition)
swagger:model PostProductModelsParamsBodyMetadata
*/
type PostProductModelsParamsBodyMetadata struct {

	// Status of the product model regarding the user permissions (only available since the v2.3 in the Enterprise Edition)
	// Enum: [read_only draft_in_progress proposal_waiting_for_approval working_copy]
	WorkflowStatus string `json:"workflow_status,omitempty"`
}

// Validate validates this post product models params body metadata
func (o *PostProductModelsParamsBodyMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateWorkflowStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var postProductModelsParamsBodyMetadataTypeWorkflowStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["read_only","draft_in_progress","proposal_waiting_for_approval","working_copy"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		postProductModelsParamsBodyMetadataTypeWorkflowStatusPropEnum = append(postProductModelsParamsBodyMetadataTypeWorkflowStatusPropEnum, v)
	}
}

const (

	// PostProductModelsParamsBodyMetadataWorkflowStatusReadOnly captures enum value "read_only"
	PostProductModelsParamsBodyMetadataWorkflowStatusReadOnly string = "read_only"

	// PostProductModelsParamsBodyMetadataWorkflowStatusDraftInProgress captures enum value "draft_in_progress"
	PostProductModelsParamsBodyMetadataWorkflowStatusDraftInProgress string = "draft_in_progress"

	// PostProductModelsParamsBodyMetadataWorkflowStatusProposalWaitingForApproval captures enum value "proposal_waiting_for_approval"
	PostProductModelsParamsBodyMetadataWorkflowStatusProposalWaitingForApproval string = "proposal_waiting_for_approval"

	// PostProductModelsParamsBodyMetadataWorkflowStatusWorkingCopy captures enum value "working_copy"
	PostProductModelsParamsBodyMetadataWorkflowStatusWorkingCopy string = "working_copy"
)

// prop value enum
func (o *PostProductModelsParamsBodyMetadata) validateWorkflowStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, postProductModelsParamsBodyMetadataTypeWorkflowStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PostProductModelsParamsBodyMetadata) validateWorkflowStatus(formats strfmt.Registry) error {

	if swag.IsZero(o.WorkflowStatus) { // not required
		return nil
	}

	// value enum
	if err := o.validateWorkflowStatusEnum("body"+"."+"metadata"+"."+"workflow_status", "body", o.WorkflowStatus); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyMetadata) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyMetadata) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyQuantifiedAssociations Several quantified associations related to products and/or product models, grouped by quantified association types (only available in Serenity)
swagger:model PostProductModelsParamsBodyQuantifiedAssociations
*/
type PostProductModelsParamsBodyQuantifiedAssociations struct {

	// quantified association type code
	QuantifiedAssociationTypeCode *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode `json:"quantifiedAssociationTypeCode,omitempty"`
}

// Validate validates this post product models params body quantified associations
func (o *PostProductModelsParamsBodyQuantifiedAssociations) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateQuantifiedAssociationTypeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostProductModelsParamsBodyQuantifiedAssociations) validateQuantifiedAssociationTypeCode(formats strfmt.Registry) error {

	if swag.IsZero(o.QuantifiedAssociationTypeCode) { // not required
		return nil
	}

	if o.QuantifiedAssociationTypeCode != nil {
		if err := o.QuantifiedAssociationTypeCode.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "quantified_associations" + "." + "quantifiedAssociationTypeCode")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociations) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociations) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyQuantifiedAssociations
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode post product models params body quantified associations quantified association type code
swagger:model PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode
*/
type PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode struct {

	// Array of objects containing product model codes and quantities with which the product model is in relation
	ProductModels []*PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 `json:"product_models"`

	// Array of objects containing product identifiers and quantities with which the product model is in relation
	Products []*PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 `json:"products"`
}

// Validate validates this post product models params body quantified associations quantified association type code
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) Validate(formats strfmt.Registry) error {
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

func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) validateProductModels(formats strfmt.Registry) error {

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
					return ve.ValidateName("body" + "." + "quantified_associations" + "." + "quantifiedAssociationTypeCode" + "." + "product_models" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) validateProducts(formats strfmt.Registry) error {

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
					return ve.ValidateName("body" + "." + "quantified_associations" + "." + "quantifiedAssociationTypeCode" + "." + "products" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 post product models params body quantified associations quantified association type code product models items0
swagger:model PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0
*/
type PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 struct {

	// code
	Code string `json:"code,omitempty"`

	// quantity
	Quantity int64 `json:"quantity,omitempty"`
}

// Validate validates this post product models params body quantified associations quantified association type code product models items0
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 post product models params body quantified associations quantified association type code products items0
swagger:model PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0
*/
type PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 struct {

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// quantity
	Quantity int64 `json:"quantity,omitempty"`
}

// Validate validates this post product models params body quantified associations quantified association type code products items0
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyValues Product model attributes values, see <a href='/concepts/products.html#focus-on-the-products-values'>Product values</a> section for more details
swagger:model PostProductModelsParamsBodyValues
*/
type PostProductModelsParamsBodyValues struct {

	// attribute code
	AttributeCode []*PostProductModelsParamsBodyValuesAttributeCodeItems0 `json:"attributeCode"`
}

// Validate validates this post product models params body values
func (o *PostProductModelsParamsBodyValues) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAttributeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostProductModelsParamsBodyValues) validateAttributeCode(formats strfmt.Registry) error {

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
					return ve.ValidateName("body" + "." + "values" + "." + "attributeCode" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyValues) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyValues) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyValues
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsParamsBodyValuesAttributeCodeItems0 post product models params body values attribute code items0
swagger:model PostProductModelsParamsBodyValuesAttributeCodeItems0
*/
type PostProductModelsParamsBodyValuesAttributeCodeItems0 struct {

	// Product value
	Data interface{} `json:"data,omitempty"`

	// Locale code of the product value
	Locale string `json:"locale,omitempty"`

	// Channel code of the product value
	Scope string `json:"scope,omitempty"`
}

// Validate validates this post product models params body values attribute code items0
func (o *PostProductModelsParamsBodyValuesAttributeCodeItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsParamsBodyValuesAttributeCodeItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsParamsBodyValuesAttributeCodeItems0) UnmarshalBinary(b []byte) error {
	var res PostProductModelsParamsBodyValuesAttributeCodeItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsUnauthorizedBody post product models unauthorized body
swagger:model PostProductModelsUnauthorizedBody
*/
type PostProductModelsUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post product models unauthorized body
func (o *PostProductModelsUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PostProductModelsUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsUnprocessableEntityBody post product models unprocessable entity body
swagger:model PostProductModelsUnprocessableEntityBody
*/
type PostProductModelsUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post product models unprocessable entity body
func (o *PostProductModelsUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PostProductModelsUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PostProductModelsUnsupportedMediaTypeBody post product models unsupported media type body
swagger:model PostProductModelsUnsupportedMediaTypeBody
*/
type PostProductModelsUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this post product models unsupported media type body
func (o *PostProductModelsUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostProductModelsUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostProductModelsUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PostProductModelsUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
