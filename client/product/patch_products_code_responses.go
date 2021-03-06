// Code generated by go-swagger; DO NOT EDIT.

package product

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

// PatchProductsCodeReader is a Reader for the PatchProductsCode structure.
type PatchProductsCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchProductsCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchProductsCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewPatchProductsCodeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPatchProductsCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchProductsCodeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchProductsCodeUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchProductsCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchProductsCodeCreated creates a PatchProductsCodeCreated with default headers values
func NewPatchProductsCodeCreated() *PatchProductsCodeCreated {
	return &PatchProductsCodeCreated{}
}

/*PatchProductsCodeCreated handles this case with default header values.

Created
*/
type PatchProductsCodeCreated struct {
	/*URI of the created resource
	 */
	Location string
}

func (o *PatchProductsCodeCreated) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/products/{code}][%d] patchProductsCodeCreated ", 201)
}

func (o *PatchProductsCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchProductsCodeNoContent creates a PatchProductsCodeNoContent with default headers values
func NewPatchProductsCodeNoContent() *PatchProductsCodeNoContent {
	return &PatchProductsCodeNoContent{}
}

/*PatchProductsCodeNoContent handles this case with default header values.

No content to return
*/
type PatchProductsCodeNoContent struct {
	/*URI of the updated resource
	 */
	Location string
}

func (o *PatchProductsCodeNoContent) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/products/{code}][%d] patchProductsCodeNoContent ", 204)
}

func (o *PatchProductsCodeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response header Location
	o.Location = response.GetHeader("Location")

	return nil
}

// NewPatchProductsCodeUnauthorized creates a PatchProductsCodeUnauthorized with default headers values
func NewPatchProductsCodeUnauthorized() *PatchProductsCodeUnauthorized {
	return &PatchProductsCodeUnauthorized{}
}

/*PatchProductsCodeUnauthorized handles this case with default header values.

Authentication required
*/
type PatchProductsCodeUnauthorized struct {
	Payload *PatchProductsCodeUnauthorizedBody
}

func (o *PatchProductsCodeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/products/{code}][%d] patchProductsCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchProductsCodeUnauthorized) GetPayload() *PatchProductsCodeUnauthorizedBody {
	return o.Payload
}

func (o *PatchProductsCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchProductsCodeUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchProductsCodeForbidden creates a PatchProductsCodeForbidden with default headers values
func NewPatchProductsCodeForbidden() *PatchProductsCodeForbidden {
	return &PatchProductsCodeForbidden{}
}

/*PatchProductsCodeForbidden handles this case with default header values.

Access forbidden
*/
type PatchProductsCodeForbidden struct {
	Payload *PatchProductsCodeForbiddenBody
}

func (o *PatchProductsCodeForbidden) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/products/{code}][%d] patchProductsCodeForbidden  %+v", 403, o.Payload)
}

func (o *PatchProductsCodeForbidden) GetPayload() *PatchProductsCodeForbiddenBody {
	return o.Payload
}

func (o *PatchProductsCodeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchProductsCodeForbiddenBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchProductsCodeUnsupportedMediaType creates a PatchProductsCodeUnsupportedMediaType with default headers values
func NewPatchProductsCodeUnsupportedMediaType() *PatchProductsCodeUnsupportedMediaType {
	return &PatchProductsCodeUnsupportedMediaType{}
}

/*PatchProductsCodeUnsupportedMediaType handles this case with default header values.

Unsupported Media type
*/
type PatchProductsCodeUnsupportedMediaType struct {
	Payload *PatchProductsCodeUnsupportedMediaTypeBody
}

func (o *PatchProductsCodeUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/products/{code}][%d] patchProductsCodeUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchProductsCodeUnsupportedMediaType) GetPayload() *PatchProductsCodeUnsupportedMediaTypeBody {
	return o.Payload
}

func (o *PatchProductsCodeUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchProductsCodeUnsupportedMediaTypeBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchProductsCodeUnprocessableEntity creates a PatchProductsCodeUnprocessableEntity with default headers values
func NewPatchProductsCodeUnprocessableEntity() *PatchProductsCodeUnprocessableEntity {
	return &PatchProductsCodeUnprocessableEntity{}
}

/*PatchProductsCodeUnprocessableEntity handles this case with default header values.

Unprocessable entity
*/
type PatchProductsCodeUnprocessableEntity struct {
	Payload *PatchProductsCodeUnprocessableEntityBody
}

func (o *PatchProductsCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /api/rest/v1/products/{code}][%d] patchProductsCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchProductsCodeUnprocessableEntity) GetPayload() *PatchProductsCodeUnprocessableEntityBody {
	return o.Payload
}

func (o *PatchProductsCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PatchProductsCodeUnprocessableEntityBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*PatchProductsCodeBody patch products code body
swagger:model PatchProductsCodeBody
*/
type PatchProductsCodeBody struct {

	// associations
	Associations *PatchProductsCodeParamsBodyAssociations `json:"associations,omitempty"`

	// Codes of the categories in which the product is classified
	Categories []string `json:"categories"`

	// Date of creation
	Created string `json:"created,omitempty"`

	// Whether the product is enable
	Enabled *bool `json:"enabled,omitempty"`

	// Family code from which the product inherits its attributes and attributes requirements
	Family *string `json:"family,omitempty"`

	// Codes of the groups to which the product belong
	Groups []string `json:"groups"`

	// Product identifier, i.e. the value of the only `pim_catalog_identifier` attribute
	// Required: true
	Identifier *string `json:"identifier"`

	// metadata
	Metadata *PatchProductsCodeParamsBodyMetadata `json:"metadata,omitempty"`

	// Code of the parent product model when the product is a variant (only available since the 2.0). This parent can be modified since the 2.3.
	Parent *string `json:"parent,omitempty"`

	// Product quality scores for each channel/locale combination (only available in Serenity and when the "with_quality_scores" query parameter is set to "true")
	QualityScores interface{} `json:"quality_scores,omitempty"`

	// quantified associations
	QuantifiedAssociations *PatchProductsCodeParamsBodyQuantifiedAssociations `json:"quantified_associations,omitempty"`

	// Date of the last update
	Updated string `json:"updated,omitempty"`

	// values
	Values *PatchProductsCodeParamsBodyValues `json:"values,omitempty"`
}

// Validate validates this patch products code body
func (o *PatchProductsCodeBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAssociations(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateIdentifier(formats); err != nil {
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

func (o *PatchProductsCodeBody) validateAssociations(formats strfmt.Registry) error {

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

func (o *PatchProductsCodeBody) validateIdentifier(formats strfmt.Registry) error {

	if err := validate.Required("body"+"."+"identifier", "body", o.Identifier); err != nil {
		return err
	}

	return nil
}

func (o *PatchProductsCodeBody) validateMetadata(formats strfmt.Registry) error {

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

func (o *PatchProductsCodeBody) validateQuantifiedAssociations(formats strfmt.Registry) error {

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

func (o *PatchProductsCodeBody) validateValues(formats strfmt.Registry) error {

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
func (o *PatchProductsCodeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeBody) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeForbiddenBody patch products code forbidden body
swagger:model PatchProductsCodeForbiddenBody
*/
type PatchProductsCodeForbiddenBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch products code forbidden body
func (o *PatchProductsCodeForbiddenBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeForbiddenBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeForbiddenBody) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeForbiddenBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyAssociations Several associations related to groups, product models and/or other products, grouped by association types
swagger:model PatchProductsCodeParamsBodyAssociations
*/
type PatchProductsCodeParamsBodyAssociations struct {

	// association type code
	AssociationTypeCode *PatchProductsCodeParamsBodyAssociationsAssociationTypeCode `json:"associationTypeCode,omitempty"`
}

// Validate validates this patch products code params body associations
func (o *PatchProductsCodeParamsBodyAssociations) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAssociationTypeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchProductsCodeParamsBodyAssociations) validateAssociationTypeCode(formats strfmt.Registry) error {

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
func (o *PatchProductsCodeParamsBodyAssociations) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyAssociations) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyAssociations
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyAssociationsAssociationTypeCode patch products code params body associations association type code
swagger:model PatchProductsCodeParamsBodyAssociationsAssociationTypeCode
*/
type PatchProductsCodeParamsBodyAssociationsAssociationTypeCode struct {

	// Array of groups codes with which the product is in relation
	Groups []string `json:"groups"`

	// Array of product model codes with which the product is in relation (only available since the v2.1)
	ProductModels []string `json:"product_models"`

	// Array of product identifiers with which the product is in relation
	Products []string `json:"products"`
}

// Validate validates this patch products code params body associations association type code
func (o *PatchProductsCodeParamsBodyAssociationsAssociationTypeCode) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyAssociationsAssociationTypeCode) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyAssociationsAssociationTypeCode) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyAssociationsAssociationTypeCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyMetadata More information around the product (only available since the v2.0 in the Enterprise Edition)
swagger:model PatchProductsCodeParamsBodyMetadata
*/
type PatchProductsCodeParamsBodyMetadata struct {

	// Status of the product regarding the user permissions (only available since the v2.0 in the Enterprise Edition)
	// Enum: [read_only draft_in_progress proposal_waiting_for_approval working_copy]
	WorkflowStatus string `json:"workflow_status,omitempty"`
}

// Validate validates this patch products code params body metadata
func (o *PatchProductsCodeParamsBodyMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateWorkflowStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var patchProductsCodeParamsBodyMetadataTypeWorkflowStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["read_only","draft_in_progress","proposal_waiting_for_approval","working_copy"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		patchProductsCodeParamsBodyMetadataTypeWorkflowStatusPropEnum = append(patchProductsCodeParamsBodyMetadataTypeWorkflowStatusPropEnum, v)
	}
}

const (

	// PatchProductsCodeParamsBodyMetadataWorkflowStatusReadOnly captures enum value "read_only"
	PatchProductsCodeParamsBodyMetadataWorkflowStatusReadOnly string = "read_only"

	// PatchProductsCodeParamsBodyMetadataWorkflowStatusDraftInProgress captures enum value "draft_in_progress"
	PatchProductsCodeParamsBodyMetadataWorkflowStatusDraftInProgress string = "draft_in_progress"

	// PatchProductsCodeParamsBodyMetadataWorkflowStatusProposalWaitingForApproval captures enum value "proposal_waiting_for_approval"
	PatchProductsCodeParamsBodyMetadataWorkflowStatusProposalWaitingForApproval string = "proposal_waiting_for_approval"

	// PatchProductsCodeParamsBodyMetadataWorkflowStatusWorkingCopy captures enum value "working_copy"
	PatchProductsCodeParamsBodyMetadataWorkflowStatusWorkingCopy string = "working_copy"
)

// prop value enum
func (o *PatchProductsCodeParamsBodyMetadata) validateWorkflowStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, patchProductsCodeParamsBodyMetadataTypeWorkflowStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PatchProductsCodeParamsBodyMetadata) validateWorkflowStatus(formats strfmt.Registry) error {

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
func (o *PatchProductsCodeParamsBodyMetadata) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyMetadata) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyQuantifiedAssociations Several quantified associations related to products and/or product models, grouped by quantified association types (only available in Serenity)
swagger:model PatchProductsCodeParamsBodyQuantifiedAssociations
*/
type PatchProductsCodeParamsBodyQuantifiedAssociations struct {

	// quantified association type code
	QuantifiedAssociationTypeCode *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode `json:"quantifiedAssociationTypeCode,omitempty"`
}

// Validate validates this patch products code params body quantified associations
func (o *PatchProductsCodeParamsBodyQuantifiedAssociations) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateQuantifiedAssociationTypeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchProductsCodeParamsBodyQuantifiedAssociations) validateQuantifiedAssociationTypeCode(formats strfmt.Registry) error {

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
func (o *PatchProductsCodeParamsBodyQuantifiedAssociations) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyQuantifiedAssociations) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyQuantifiedAssociations
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode patch products code params body quantified associations quantified association type code
swagger:model PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode
*/
type PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode struct {

	// Array of objects containing product model codes and quantities with which the product is in relation
	ProductModels []*PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 `json:"product_models"`

	// Array of objects containing product identifiers and quantities with which the product is in relation
	Products []*PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 `json:"products"`
}

// Validate validates this patch products code params body quantified associations quantified association type code
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) Validate(formats strfmt.Registry) error {
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

func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) validateProductModels(formats strfmt.Registry) error {

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

func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) validateProducts(formats strfmt.Registry) error {

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
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 patch products code params body quantified associations quantified association type code product models items0
swagger:model PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0
*/
type PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0 struct {

	// code
	Code string `json:"code,omitempty"`

	// quantity
	Quantity int64 `json:"quantity,omitempty"`
}

// Validate validates this patch products code params body quantified associations quantified association type code product models items0
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductModelsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 patch products code params body quantified associations quantified association type code products items0
swagger:model PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0
*/
type PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0 struct {

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// quantity
	Quantity int64 `json:"quantity,omitempty"`
}

// Validate validates this patch products code params body quantified associations quantified association type code products items0
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyQuantifiedAssociationsQuantifiedAssociationTypeCodeProductsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyValues Product attributes values, see <a href='/concepts/products.html#focus-on-the-products-values'>Product values</a> section for more details
swagger:model PatchProductsCodeParamsBodyValues
*/
type PatchProductsCodeParamsBodyValues struct {

	// attribute code
	AttributeCode []*PatchProductsCodeParamsBodyValuesAttributeCodeItems0 `json:"attributeCode"`
}

// Validate validates this patch products code params body values
func (o *PatchProductsCodeParamsBodyValues) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateAttributeCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchProductsCodeParamsBodyValues) validateAttributeCode(formats strfmt.Registry) error {

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
func (o *PatchProductsCodeParamsBodyValues) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyValues) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyValues
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyValuesAttributeCodeItems0 patch products code params body values attribute code items0
swagger:model PatchProductsCodeParamsBodyValuesAttributeCodeItems0
*/
type PatchProductsCodeParamsBodyValuesAttributeCodeItems0 struct {

	// Product value
	Data interface{} `json:"data,omitempty"`

	// linked data
	LinkedData *PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData `json:"linked_data,omitempty"`

	// Locale code of the product value
	Locale string `json:"locale,omitempty"`

	// Channel code of the product value
	Scope string `json:"scope,omitempty"`
}

// Validate validates this patch products code params body values attribute code items0
func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateLinkedData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0) validateLinkedData(formats strfmt.Registry) error {

	if swag.IsZero(o.LinkedData) { // not required
		return nil
	}

	if o.LinkedData != nil {
		if err := o.LinkedData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("linked_data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyValuesAttributeCodeItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData Object containing labels of attribute options (only available in Serenity and when query parameter "with_attribute_options" is set to "true"). See <a href='/concepts/products.html#the-linked_data-format'>the `linked_data` format</a> section for more details.
swagger:model PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData
*/
type PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData struct {

	// attribute
	Attribute string `json:"attribute,omitempty"`

	// code
	Code string `json:"code,omitempty"`

	// labels
	Labels interface{} `json:"labels,omitempty"`
}

// Validate validates this patch products code params body values attribute code items0 linked data
func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeParamsBodyValuesAttributeCodeItems0LinkedData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeUnauthorizedBody patch products code unauthorized body
swagger:model PatchProductsCodeUnauthorizedBody
*/
type PatchProductsCodeUnauthorizedBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch products code unauthorized body
func (o *PatchProductsCodeUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeUnprocessableEntityBody patch products code unprocessable entity body
swagger:model PatchProductsCodeUnprocessableEntityBody
*/
type PatchProductsCodeUnprocessableEntityBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch products code unprocessable entity body
func (o *PatchProductsCodeUnprocessableEntityBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeUnprocessableEntityBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeUnprocessableEntityBody) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeUnprocessableEntityBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*PatchProductsCodeUnsupportedMediaTypeBody patch products code unsupported media type body
swagger:model PatchProductsCodeUnsupportedMediaTypeBody
*/
type PatchProductsCodeUnsupportedMediaTypeBody struct {

	// HTTP status code
	Code int64 `json:"code,omitempty"`

	// Message explaining the error
	Message string `json:"message,omitempty"`
}

// Validate validates this patch products code unsupported media type body
func (o *PatchProductsCodeUnsupportedMediaTypeBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PatchProductsCodeUnsupportedMediaTypeBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PatchProductsCodeUnsupportedMediaTypeBody) UnmarshalBinary(b []byte) error {
	var res PatchProductsCodeUnsupportedMediaTypeBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
