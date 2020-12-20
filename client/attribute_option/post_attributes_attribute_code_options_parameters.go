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

// NewPostAttributesAttributeCodeOptionsParams creates a new PostAttributesAttributeCodeOptionsParams object
// with the default values initialized.
func NewPostAttributesAttributeCodeOptionsParams() *PostAttributesAttributeCodeOptionsParams {
	var ()
	return &PostAttributesAttributeCodeOptionsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPostAttributesAttributeCodeOptionsParamsWithTimeout creates a new PostAttributesAttributeCodeOptionsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPostAttributesAttributeCodeOptionsParamsWithTimeout(timeout time.Duration) *PostAttributesAttributeCodeOptionsParams {
	var ()
	return &PostAttributesAttributeCodeOptionsParams{

		timeout: timeout,
	}
}

// NewPostAttributesAttributeCodeOptionsParamsWithContext creates a new PostAttributesAttributeCodeOptionsParams object
// with the default values initialized, and the ability to set a context for a request
func NewPostAttributesAttributeCodeOptionsParamsWithContext(ctx context.Context) *PostAttributesAttributeCodeOptionsParams {
	var ()
	return &PostAttributesAttributeCodeOptionsParams{

		Context: ctx,
	}
}

// NewPostAttributesAttributeCodeOptionsParamsWithHTTPClient creates a new PostAttributesAttributeCodeOptionsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPostAttributesAttributeCodeOptionsParamsWithHTTPClient(client *http.Client) *PostAttributesAttributeCodeOptionsParams {
	var ()
	return &PostAttributesAttributeCodeOptionsParams{
		HTTPClient: client,
	}
}

/*PostAttributesAttributeCodeOptionsParams contains all the parameters to send to the API endpoint
for the post attributes attribute code options operation typically these are written to a http.Request
*/
type PostAttributesAttributeCodeOptionsParams struct {

	/*AttributeCode
	  Code of the attribute

	*/
	AttributeCode string
	/*Body*/
	Body PostAttributesAttributeCodeOptionsBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) WithTimeout(timeout time.Duration) *PostAttributesAttributeCodeOptionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) WithContext(ctx context.Context) *PostAttributesAttributeCodeOptionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) WithHTTPClient(client *http.Client) *PostAttributesAttributeCodeOptionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAttributeCode adds the attributeCode to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) WithAttributeCode(attributeCode string) *PostAttributesAttributeCodeOptionsParams {
	o.SetAttributeCode(attributeCode)
	return o
}

// SetAttributeCode adds the attributeCode to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) SetAttributeCode(attributeCode string) {
	o.AttributeCode = attributeCode
}

// WithBody adds the body to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) WithBody(body PostAttributesAttributeCodeOptionsBody) *PostAttributesAttributeCodeOptionsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the post attributes attribute code options params
func (o *PostAttributesAttributeCodeOptionsParams) SetBody(body PostAttributesAttributeCodeOptionsBody) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PostAttributesAttributeCodeOptionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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