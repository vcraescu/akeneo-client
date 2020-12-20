// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_attribute_option

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParams creates a new GetReferenceEntityAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized.
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParams() *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParamsWithTimeout creates a new GetReferenceEntityAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParamsWithTimeout(timeout time.Duration) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeParams{

		timeout: timeout,
	}
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParamsWithContext creates a new GetReferenceEntityAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParamsWithContext(ctx context.Context) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeParams{

		Context: ctx,
	}
}

// NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParamsWithHTTPClient creates a new GetReferenceEntityAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParamsWithHTTPClient(client *http.Client) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &GetReferenceEntityAttributesAttributeCodeOptionsCodeParams{
		HTTPClient: client,
	}
}

/*GetReferenceEntityAttributesAttributeCodeOptionsCodeParams contains all the parameters to send to the API endpoint
for the get reference entity attributes attribute code options code operation typically these are written to a http.Request
*/
type GetReferenceEntityAttributesAttributeCodeOptionsCodeParams struct {

	/*AttributeCode
	  Code of the attribute

	*/
	AttributeCode string
	/*Code
	  Code of the resource

	*/
	Code string
	/*ReferenceEntityCode
	  Code of the reference entity

	*/
	ReferenceEntityCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WithTimeout(timeout time.Duration) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WithContext(ctx context.Context) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WithHTTPClient(client *http.Client) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAttributeCode adds the attributeCode to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WithAttributeCode(attributeCode string) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	o.SetAttributeCode(attributeCode)
	return o
}

// SetAttributeCode adds the attributeCode to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) SetAttributeCode(attributeCode string) {
	o.AttributeCode = attributeCode
}

// WithCode adds the code to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WithCode(code string) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) SetCode(code string) {
	o.Code = code
}

// WithReferenceEntityCode adds the referenceEntityCode to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WithReferenceEntityCode(referenceEntityCode string) *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams {
	o.SetReferenceEntityCode(referenceEntityCode)
	return o
}

// SetReferenceEntityCode adds the referenceEntityCode to the get reference entity attributes attribute code options code params
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) SetReferenceEntityCode(referenceEntityCode string) {
	o.ReferenceEntityCode = referenceEntityCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param attribute_code
	if err := r.SetPathParam("attribute_code", o.AttributeCode); err != nil {
		return err
	}

	// path param code
	if err := r.SetPathParam("code", o.Code); err != nil {
		return err
	}

	// path param reference_entity_code
	if err := r.SetPathParam("reference_entity_code", o.ReferenceEntityCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
