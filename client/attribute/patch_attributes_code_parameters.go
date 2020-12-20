// Code generated by go-swagger; DO NOT EDIT.

package attribute

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

// NewPatchAttributesCodeParams creates a new PatchAttributesCodeParams object
// with the default values initialized.
func NewPatchAttributesCodeParams() *PatchAttributesCodeParams {
	var ()
	return &PatchAttributesCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchAttributesCodeParamsWithTimeout creates a new PatchAttributesCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchAttributesCodeParamsWithTimeout(timeout time.Duration) *PatchAttributesCodeParams {
	var ()
	return &PatchAttributesCodeParams{

		timeout: timeout,
	}
}

// NewPatchAttributesCodeParamsWithContext creates a new PatchAttributesCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchAttributesCodeParamsWithContext(ctx context.Context) *PatchAttributesCodeParams {
	var ()
	return &PatchAttributesCodeParams{

		Context: ctx,
	}
}

// NewPatchAttributesCodeParamsWithHTTPClient creates a new PatchAttributesCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchAttributesCodeParamsWithHTTPClient(client *http.Client) *PatchAttributesCodeParams {
	var ()
	return &PatchAttributesCodeParams{
		HTTPClient: client,
	}
}

/*PatchAttributesCodeParams contains all the parameters to send to the API endpoint
for the patch attributes code operation typically these are written to a http.Request
*/
type PatchAttributesCodeParams struct {

	/*Body*/
	Body PatchAttributesCodeBody
	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch attributes code params
func (o *PatchAttributesCodeParams) WithTimeout(timeout time.Duration) *PatchAttributesCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch attributes code params
func (o *PatchAttributesCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch attributes code params
func (o *PatchAttributesCodeParams) WithContext(ctx context.Context) *PatchAttributesCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch attributes code params
func (o *PatchAttributesCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch attributes code params
func (o *PatchAttributesCodeParams) WithHTTPClient(client *http.Client) *PatchAttributesCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch attributes code params
func (o *PatchAttributesCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch attributes code params
func (o *PatchAttributesCodeParams) WithBody(body PatchAttributesCodeBody) *PatchAttributesCodeParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch attributes code params
func (o *PatchAttributesCodeParams) SetBody(body PatchAttributesCodeBody) {
	o.Body = body
}

// WithCode adds the code to the patch attributes code params
func (o *PatchAttributesCodeParams) WithCode(code string) *PatchAttributesCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the patch attributes code params
func (o *PatchAttributesCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *PatchAttributesCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
