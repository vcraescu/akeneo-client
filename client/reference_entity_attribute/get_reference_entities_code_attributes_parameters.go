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

// NewGetReferenceEntitiesCodeAttributesParams creates a new GetReferenceEntitiesCodeAttributesParams object
// with the default values initialized.
func NewGetReferenceEntitiesCodeAttributesParams() *GetReferenceEntitiesCodeAttributesParams {
	var ()
	return &GetReferenceEntitiesCodeAttributesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetReferenceEntitiesCodeAttributesParamsWithTimeout creates a new GetReferenceEntitiesCodeAttributesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetReferenceEntitiesCodeAttributesParamsWithTimeout(timeout time.Duration) *GetReferenceEntitiesCodeAttributesParams {
	var ()
	return &GetReferenceEntitiesCodeAttributesParams{

		timeout: timeout,
	}
}

// NewGetReferenceEntitiesCodeAttributesParamsWithContext creates a new GetReferenceEntitiesCodeAttributesParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetReferenceEntitiesCodeAttributesParamsWithContext(ctx context.Context) *GetReferenceEntitiesCodeAttributesParams {
	var ()
	return &GetReferenceEntitiesCodeAttributesParams{

		Context: ctx,
	}
}

// NewGetReferenceEntitiesCodeAttributesParamsWithHTTPClient creates a new GetReferenceEntitiesCodeAttributesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetReferenceEntitiesCodeAttributesParamsWithHTTPClient(client *http.Client) *GetReferenceEntitiesCodeAttributesParams {
	var ()
	return &GetReferenceEntitiesCodeAttributesParams{
		HTTPClient: client,
	}
}

/*GetReferenceEntitiesCodeAttributesParams contains all the parameters to send to the API endpoint
for the get reference entities code attributes operation typically these are written to a http.Request
*/
type GetReferenceEntitiesCodeAttributesParams struct {

	/*ReferenceEntityCode
	  Code of the reference entity

	*/
	ReferenceEntityCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) WithTimeout(timeout time.Duration) *GetReferenceEntitiesCodeAttributesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) WithContext(ctx context.Context) *GetReferenceEntitiesCodeAttributesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) WithHTTPClient(client *http.Client) *GetReferenceEntitiesCodeAttributesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithReferenceEntityCode adds the referenceEntityCode to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) WithReferenceEntityCode(referenceEntityCode string) *GetReferenceEntitiesCodeAttributesParams {
	o.SetReferenceEntityCode(referenceEntityCode)
	return o
}

// SetReferenceEntityCode adds the referenceEntityCode to the get reference entities code attributes params
func (o *GetReferenceEntitiesCodeAttributesParams) SetReferenceEntityCode(referenceEntityCode string) {
	o.ReferenceEntityCode = referenceEntityCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetReferenceEntitiesCodeAttributesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param reference_entity_code
	if err := r.SetPathParam("reference_entity_code", o.ReferenceEntityCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
