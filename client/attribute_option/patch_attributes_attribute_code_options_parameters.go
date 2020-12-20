// Code generated by go-swagger; DO NOT EDIT.

package attribute_option

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

// NewPatchAttributesAttributeCodeOptionsParams creates a new PatchAttributesAttributeCodeOptionsParams object
// with the default values initialized.
func NewPatchAttributesAttributeCodeOptionsParams() *PatchAttributesAttributeCodeOptionsParams {
	var ()
	return &PatchAttributesAttributeCodeOptionsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchAttributesAttributeCodeOptionsParamsWithTimeout creates a new PatchAttributesAttributeCodeOptionsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchAttributesAttributeCodeOptionsParamsWithTimeout(timeout time.Duration) *PatchAttributesAttributeCodeOptionsParams {
	var ()
	return &PatchAttributesAttributeCodeOptionsParams{

		timeout: timeout,
	}
}

// NewPatchAttributesAttributeCodeOptionsParamsWithContext creates a new PatchAttributesAttributeCodeOptionsParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchAttributesAttributeCodeOptionsParamsWithContext(ctx context.Context) *PatchAttributesAttributeCodeOptionsParams {
	var ()
	return &PatchAttributesAttributeCodeOptionsParams{

		Context: ctx,
	}
}

// NewPatchAttributesAttributeCodeOptionsParamsWithHTTPClient creates a new PatchAttributesAttributeCodeOptionsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchAttributesAttributeCodeOptionsParamsWithHTTPClient(client *http.Client) *PatchAttributesAttributeCodeOptionsParams {
	var ()
	return &PatchAttributesAttributeCodeOptionsParams{
		HTTPClient: client,
	}
}

/*PatchAttributesAttributeCodeOptionsParams contains all the parameters to send to the API endpoint
for the patch attributes attribute code options operation typically these are written to a http.Request
*/
type PatchAttributesAttributeCodeOptionsParams struct {

	/*AttributeCode
	  Code of the attribute

	*/
	AttributeCode string
	/*Body*/
	Body PatchAttributesAttributeCodeOptionsBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) WithTimeout(timeout time.Duration) *PatchAttributesAttributeCodeOptionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) WithContext(ctx context.Context) *PatchAttributesAttributeCodeOptionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) WithHTTPClient(client *http.Client) *PatchAttributesAttributeCodeOptionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAttributeCode adds the attributeCode to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) WithAttributeCode(attributeCode string) *PatchAttributesAttributeCodeOptionsParams {
	o.SetAttributeCode(attributeCode)
	return o
}

// SetAttributeCode adds the attributeCode to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) SetAttributeCode(attributeCode string) {
	o.AttributeCode = attributeCode
}

// WithBody adds the body to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) WithBody(body PatchAttributesAttributeCodeOptionsBody) *PatchAttributesAttributeCodeOptionsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch attributes attribute code options params
func (o *PatchAttributesAttributeCodeOptionsParams) SetBody(body PatchAttributesAttributeCodeOptionsBody) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PatchAttributesAttributeCodeOptionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param attribute_code
	if err := r.SetPathParam("attribute_code", o.AttributeCode); err != nil {
		return err
	}

	if err := r.SetBodyParam(o.Body); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
