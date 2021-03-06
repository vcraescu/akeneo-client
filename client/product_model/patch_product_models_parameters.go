// Code generated by go-swagger; DO NOT EDIT.

package product_model

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

// NewPatchProductModelsParams creates a new PatchProductModelsParams object
// with the default values initialized.
func NewPatchProductModelsParams() *PatchProductModelsParams {
	var ()
	return &PatchProductModelsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchProductModelsParamsWithTimeout creates a new PatchProductModelsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchProductModelsParamsWithTimeout(timeout time.Duration) *PatchProductModelsParams {
	var ()
	return &PatchProductModelsParams{

		timeout: timeout,
	}
}

// NewPatchProductModelsParamsWithContext creates a new PatchProductModelsParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchProductModelsParamsWithContext(ctx context.Context) *PatchProductModelsParams {
	var ()
	return &PatchProductModelsParams{

		Context: ctx,
	}
}

// NewPatchProductModelsParamsWithHTTPClient creates a new PatchProductModelsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchProductModelsParamsWithHTTPClient(client *http.Client) *PatchProductModelsParams {
	var ()
	return &PatchProductModelsParams{
		HTTPClient: client,
	}
}

/*PatchProductModelsParams contains all the parameters to send to the API endpoint
for the patch product models operation typically these are written to a http.Request
*/
type PatchProductModelsParams struct {

	/*Body*/
	Body PatchProductModelsBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch product models params
func (o *PatchProductModelsParams) WithTimeout(timeout time.Duration) *PatchProductModelsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch product models params
func (o *PatchProductModelsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch product models params
func (o *PatchProductModelsParams) WithContext(ctx context.Context) *PatchProductModelsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch product models params
func (o *PatchProductModelsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch product models params
func (o *PatchProductModelsParams) WithHTTPClient(client *http.Client) *PatchProductModelsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch product models params
func (o *PatchProductModelsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch product models params
func (o *PatchProductModelsParams) WithBody(body PatchProductModelsBody) *PatchProductModelsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch product models params
func (o *PatchProductModelsParams) SetBody(body PatchProductModelsBody) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PatchProductModelsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if err := r.SetBodyParam(o.Body); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
