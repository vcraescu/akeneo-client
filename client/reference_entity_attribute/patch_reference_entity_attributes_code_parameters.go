// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_attribute

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

// NewPatchReferenceEntityAttributesCodeParams creates a new PatchReferenceEntityAttributesCodeParams object
// with the default values initialized.
func NewPatchReferenceEntityAttributesCodeParams() *PatchReferenceEntityAttributesCodeParams {
	var ()
	return &PatchReferenceEntityAttributesCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchReferenceEntityAttributesCodeParamsWithTimeout creates a new PatchReferenceEntityAttributesCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchReferenceEntityAttributesCodeParamsWithTimeout(timeout time.Duration) *PatchReferenceEntityAttributesCodeParams {
	var ()
	return &PatchReferenceEntityAttributesCodeParams{

		timeout: timeout,
	}
}

// NewPatchReferenceEntityAttributesCodeParamsWithContext creates a new PatchReferenceEntityAttributesCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchReferenceEntityAttributesCodeParamsWithContext(ctx context.Context) *PatchReferenceEntityAttributesCodeParams {
	var ()
	return &PatchReferenceEntityAttributesCodeParams{

		Context: ctx,
	}
}

// NewPatchReferenceEntityAttributesCodeParamsWithHTTPClient creates a new PatchReferenceEntityAttributesCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchReferenceEntityAttributesCodeParamsWithHTTPClient(client *http.Client) *PatchReferenceEntityAttributesCodeParams {
	var ()
	return &PatchReferenceEntityAttributesCodeParams{
		HTTPClient: client,
	}
}

/*PatchReferenceEntityAttributesCodeParams contains all the parameters to send to the API endpoint
for the patch reference entity attributes code operation typically these are written to a http.Request
*/
type PatchReferenceEntityAttributesCodeParams struct {

	/*Body*/
	Body PatchReferenceEntityAttributesCodeBody
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

// WithTimeout adds the timeout to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) WithTimeout(timeout time.Duration) *PatchReferenceEntityAttributesCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) WithContext(ctx context.Context) *PatchReferenceEntityAttributesCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) WithHTTPClient(client *http.Client) *PatchReferenceEntityAttributesCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) WithBody(body PatchReferenceEntityAttributesCodeBody) *PatchReferenceEntityAttributesCodeParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) SetBody(body PatchReferenceEntityAttributesCodeBody) {
	o.Body = body
}

// WithCode adds the code to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) WithCode(code string) *PatchReferenceEntityAttributesCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) SetCode(code string) {
	o.Code = code
}

// WithReferenceEntityCode adds the referenceEntityCode to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) WithReferenceEntityCode(referenceEntityCode string) *PatchReferenceEntityAttributesCodeParams {
	o.SetReferenceEntityCode(referenceEntityCode)
	return o
}

// SetReferenceEntityCode adds the referenceEntityCode to the patch reference entity attributes code params
func (o *PatchReferenceEntityAttributesCodeParams) SetReferenceEntityCode(referenceEntityCode string) {
	o.ReferenceEntityCode = referenceEntityCode
}

// WriteToRequest writes these params to a swagger request
func (o *PatchReferenceEntityAttributesCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if err := r.SetBodyParam(o.Body); err != nil {
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
