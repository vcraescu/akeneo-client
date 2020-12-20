// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset_variation_file

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

// NewGetVariationFilesChannelCodeLocaleCodeDownloadParams creates a new GetVariationFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized.
func NewGetVariationFilesChannelCodeLocaleCodeDownloadParams() *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeDownloadParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadParamsWithTimeout creates a new GetVariationFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetVariationFilesChannelCodeLocaleCodeDownloadParamsWithTimeout(timeout time.Duration) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeDownloadParams{

		timeout: timeout,
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadParamsWithContext creates a new GetVariationFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetVariationFilesChannelCodeLocaleCodeDownloadParamsWithContext(ctx context.Context) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeDownloadParams{

		Context: ctx,
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeDownloadParamsWithHTTPClient creates a new GetVariationFilesChannelCodeLocaleCodeDownloadParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetVariationFilesChannelCodeLocaleCodeDownloadParamsWithHTTPClient(client *http.Client) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeDownloadParams{
		HTTPClient: client,
	}
}

/*GetVariationFilesChannelCodeLocaleCodeDownloadParams contains all the parameters to send to the API endpoint
for the get variation files channel code locale code download operation typically these are written to a http.Request
*/
type GetVariationFilesChannelCodeLocaleCodeDownloadParams struct {

	/*AssetCode
	  Code of the asset

	*/
	AssetCode string
	/*ChannelCode
	  Code of the channel

	*/
	ChannelCode string
	/*LocaleCode
	  Code of the locale if the asset is localizable or equal to `no-locale` if the asset is not localizable

	*/
	LocaleCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WithTimeout(timeout time.Duration) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WithContext(ctx context.Context) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WithHTTPClient(client *http.Client) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssetCode adds the assetCode to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WithAssetCode(assetCode string) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	o.SetAssetCode(assetCode)
	return o
}

// SetAssetCode adds the assetCode to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) SetAssetCode(assetCode string) {
	o.AssetCode = assetCode
}

// WithChannelCode adds the channelCode to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WithChannelCode(channelCode string) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	o.SetChannelCode(channelCode)
	return o
}

// SetChannelCode adds the channelCode to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) SetChannelCode(channelCode string) {
	o.ChannelCode = channelCode
}

// WithLocaleCode adds the localeCode to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WithLocaleCode(localeCode string) *GetVariationFilesChannelCodeLocaleCodeDownloadParams {
	o.SetLocaleCode(localeCode)
	return o
}

// SetLocaleCode adds the localeCode to the get variation files channel code locale code download params
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) SetLocaleCode(localeCode string) {
	o.LocaleCode = localeCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetVariationFilesChannelCodeLocaleCodeDownloadParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param asset_code
	if err := r.SetPathParam("asset_code", o.AssetCode); err != nil {
		return err
	}

	// path param channel_code
	if err := r.SetPathParam("channel_code", o.ChannelCode); err != nil {
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