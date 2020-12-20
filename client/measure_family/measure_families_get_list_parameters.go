// Code generated by go-swagger; DO NOT EDIT.

package measure_family

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

// NewMeasureFamiliesGetListParams creates a new MeasureFamiliesGetListParams object
// with the default values initialized.
func NewMeasureFamiliesGetListParams() *MeasureFamiliesGetListParams {

	return &MeasureFamiliesGetListParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewMeasureFamiliesGetListParamsWithTimeout creates a new MeasureFamiliesGetListParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewMeasureFamiliesGetListParamsWithTimeout(timeout time.Duration) *MeasureFamiliesGetListParams {

	return &MeasureFamiliesGetListParams{

		timeout: timeout,
	}
}

// NewMeasureFamiliesGetListParamsWithContext creates a new MeasureFamiliesGetListParams object
// with the default values initialized, and the ability to set a context for a request
func NewMeasureFamiliesGetListParamsWithContext(ctx context.Context) *MeasureFamiliesGetListParams {

	return &MeasureFamiliesGetListParams{

		Context: ctx,
	}
}

// NewMeasureFamiliesGetListParamsWithHTTPClient creates a new MeasureFamiliesGetListParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewMeasureFamiliesGetListParamsWithHTTPClient(client *http.Client) *MeasureFamiliesGetListParams {

	return &MeasureFamiliesGetListParams{
		HTTPClient: client,
	}
}

/*MeasureFamiliesGetListParams contains all the parameters to send to the API endpoint
for the measure families get list operation typically these are written to a http.Request
*/
type MeasureFamiliesGetListParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the measure families get list params
func (o *MeasureFamiliesGetListParams) WithTimeout(timeout time.Duration) *MeasureFamiliesGetListParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the measure families get list params
func (o *MeasureFamiliesGetListParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the measure families get list params
func (o *MeasureFamiliesGetListParams) WithContext(ctx context.Context) *MeasureFamiliesGetListParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the measure families get list params
func (o *MeasureFamiliesGetListParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the measure families get list params
func (o *MeasureFamiliesGetListParams) WithHTTPClient(client *http.Client) *MeasureFamiliesGetListParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the measure families get list params
func (o *MeasureFamiliesGetListParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *MeasureFamiliesGetListParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
