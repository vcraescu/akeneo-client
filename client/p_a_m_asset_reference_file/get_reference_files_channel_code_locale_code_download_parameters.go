// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset_reference_file

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

// NewGetReferenceFilesChannelCodeLocaleCodeDownloadParams creates a new GetReferenceFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized.
func NewGetReferenceFilesChannelCodeLocaleCodeDownloadParams() *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetReferenceFilesChannelCodeLocaleCodeDownloadParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetReferenceFilesChannelCodeLocaleCodeDownloadParamsWithTimeout creates a new GetReferenceFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetReferenceFilesChannelCodeLocaleCodeDownloadParamsWithTimeout(timeout time.Duration) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetReferenceFilesChannelCodeLocaleCodeDownloadParams{

		timeout: timeout,
	}
}

// NewGetReferenceFilesChannelCodeLocaleCodeDownloadParamsWithContext creates a new GetReferenceFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetReferenceFilesChannelCodeLocaleCodeDownloadParamsWithContext(ctx context.Context) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetReferenceFilesChannelCodeLocaleCodeDownloadParams{

		Context: ctx,
	}
}

// NewGetReferenceFilesChannelCodeLocaleCodeDownloadParamsWithHTTPClient creates a new GetReferenceFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetReferenceFilesChannelCodeLocaleCodeDownloadParamsWithHTTPClient(client *http.Client) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetReferenceFilesChannelCodeLocaleCodeDownloadParams{
		HTTPClient: client,
	}
}

/*GetReferenceFilesChannelCodeLocaleCodeDownloadParams contains all the parameters to send to the API endpoint
for the get reference files channel code locale code download operation typically these are written to a http.Request
*/
type GetReferenceFilesChannelCodeLocaleCodeDownloadParams struct {

	/*AssetCode
	  Code of the asset

	*/
	AssetCode string
	/*LocaleCode
	  Code of the locale if the asset is localizable or equal to `no-locale` if the asset is not localizable

	*/
	LocaleCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) WithTimeout(timeout time.Duration) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) WithContext(ctx context.Context) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) WithHTTPClient(client *http.Client) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssetCode adds the assetCode to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) WithAssetCode(assetCode string) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	o.SetAssetCode(assetCode)
	return o
}

// SetAssetCode adds the assetCode to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) SetAssetCode(assetCode string) {
	o.AssetCode = assetCode
}

// WithLocaleCode adds the localeCode to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) WithLocaleCode(localeCode string) *GetReferenceFilesChannelCodeLocaleCodeDownloadParams {
	o.SetLocaleCode(localeCode)
	return o
}

// SetLocaleCode adds the localeCode to the get reference files channel code locale code download params
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) SetLocaleCode(localeCode string) {
	o.LocaleCode = localeCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetReferenceFilesChannelCodeLocaleCodeDownloadParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param asset_code
	if err := r.SetPathParam("asset_code", o.AssetCode); err != nil {
		return err
	}

	// path param locale_code
	if err := r.SetPathParam("locale_code", o.LocaleCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
