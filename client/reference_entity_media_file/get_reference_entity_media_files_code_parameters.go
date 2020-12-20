// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_media_file

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

// NewGetReferenceEntityMediaFilesCodeParams creates a new GetReferenceEntityMediaFilesCodeParams object
// with the default values initialized.
func NewGetReferenceEntityMediaFilesCodeParams() *GetReferenceEntityMediaFilesCodeParams {
	var ()
	return &GetReferenceEntityMediaFilesCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetReferenceEntityMediaFilesCodeParamsWithTimeout creates a new GetReferenceEntityMediaFilesCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetReferenceEntityMediaFilesCodeParamsWithTimeout(timeout time.Duration) *GetReferenceEntityMediaFilesCodeParams {
	var ()
	return &GetReferenceEntityMediaFilesCodeParams{

		timeout: timeout,
	}
}

// NewGetReferenceEntityMediaFilesCodeParamsWithContext creates a new GetReferenceEntityMediaFilesCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetReferenceEntityMediaFilesCodeParamsWithContext(ctx context.Context) *GetReferenceEntityMediaFilesCodeParams {
	var ()
	return &GetReferenceEntityMediaFilesCodeParams{

		Context: ctx,
	}
}

// NewGetReferenceEntityMediaFilesCodeParamsWithHTTPClient creates a new GetReferenceEntityMediaFilesCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetReferenceEntityMediaFilesCodeParamsWithHTTPClient(client *http.Client) *GetReferenceEntityMediaFilesCodeParams {
	var ()
	return &GetReferenceEntityMediaFilesCodeParams{
		HTTPClient: client,
	}
}

/*GetReferenceEntityMediaFilesCodeParams contains all the parameters to send to the API endpoint
for the get reference entity media files code operation typically these are written to a http.Request
*/
type GetReferenceEntityMediaFilesCodeParams struct {

	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) WithTimeout(timeout time.Duration) *GetReferenceEntityMediaFilesCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) WithContext(ctx context.Context) *GetReferenceEntityMediaFilesCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) WithHTTPClient(client *http.Client) *GetReferenceEntityMediaFilesCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) WithCode(code string) *GetReferenceEntityMediaFilesCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get reference entity media files code params
func (o *GetReferenceEntityMediaFilesCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *GetReferenceEntityMediaFilesCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param code
	if err := r.SetPathParam("code", o.Code); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
