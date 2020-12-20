// Code generated by go-swagger; DO NOT EDIT.

package measurement_family

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

// NewPatchMeasurementFamiliesParams creates a new PatchMeasurementFamiliesParams object
// with the default values initialized.
func NewPatchMeasurementFamiliesParams() *PatchMeasurementFamiliesParams {
	var ()
	return &PatchMeasurementFamiliesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchMeasurementFamiliesParamsWithTimeout creates a new PatchMeasurementFamiliesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchMeasurementFamiliesParamsWithTimeout(timeout time.Duration) *PatchMeasurementFamiliesParams {
	var ()
	return &PatchMeasurementFamiliesParams{

		timeout: timeout,
	}
}

// NewPatchMeasurementFamiliesParamsWithContext creates a new PatchMeasurementFamiliesParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchMeasurementFamiliesParamsWithContext(ctx context.Context) *PatchMeasurementFamiliesParams {
	var ()
	return &PatchMeasurementFamiliesParams{

		Context: ctx,
	}
}

// NewPatchMeasurementFamiliesParamsWithHTTPClient creates a new PatchMeasurementFamiliesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchMeasurementFamiliesParamsWithHTTPClient(client *http.Client) *PatchMeasurementFamiliesParams {
	var ()
	return &PatchMeasurementFamiliesParams{
		HTTPClient: client,
	}
}

/*PatchMeasurementFamiliesParams contains all the parameters to send to the API endpoint
for the patch measurement families operation typically these are written to a http.Request
*/
type PatchMeasurementFamiliesParams struct {

	/*Body*/
	Body []*PatchMeasurementFamiliesParamsBodyItems0

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) WithTimeout(timeout time.Duration) *PatchMeasurementFamiliesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) WithContext(ctx context.Context) *PatchMeasurementFamiliesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) WithHTTPClient(client *http.Client) *PatchMeasurementFamiliesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) WithBody(body []*PatchMeasurementFamiliesParamsBodyItems0) *PatchMeasurementFamiliesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch measurement families params
func (o *PatchMeasurementFamiliesParams) SetBody(body []*PatchMeasurementFamiliesParamsBodyItems0) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PatchMeasurementFamiliesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}