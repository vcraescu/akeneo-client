// Code generated by go-swagger; DO NOT EDIT.

package currency

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
	"github.com/go-openapi/swag"
)

// NewCurrenciesGetListParams creates a new CurrenciesGetListParams object
// with the default values initialized.
func NewCurrenciesGetListParams() *CurrenciesGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &CurrenciesGetListParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewCurrenciesGetListParamsWithTimeout creates a new CurrenciesGetListParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCurrenciesGetListParamsWithTimeout(timeout time.Duration) *CurrenciesGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &CurrenciesGetListParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		timeout: timeout,
	}
}

// NewCurrenciesGetListParamsWithContext creates a new CurrenciesGetListParams object
// with the default values initialized, and the ability to set a context for a request
func NewCurrenciesGetListParamsWithContext(ctx context.Context) *CurrenciesGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &CurrenciesGetListParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		Context: ctx,
	}
}

// NewCurrenciesGetListParamsWithHTTPClient creates a new CurrenciesGetListParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCurrenciesGetListParamsWithHTTPClient(client *http.Client) *CurrenciesGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &CurrenciesGetListParams{
		Limit:      &limitDefault,
		Page:       &pageDefault,
		WithCount:  &withCountDefault,
		HTTPClient: client,
	}
}

/*CurrenciesGetListParams contains all the parameters to send to the API endpoint
for the currencies get list operation typically these are written to a http.Request
*/
type CurrenciesGetListParams struct {

	/*Limit
	  Number of results by page, see <a href="/documentation/pagination.html">Pagination</a> section

	*/
	Limit *int64
	/*Page
	  Number of the page to retrieve when using the `page` pagination method type. <strong>Should never be set manually</strong>, see <a href="/documentation/pagination.html#pagination">Pagination</a> section

	*/
	Page *int64
	/*WithCount
	  Return the count of products in the response. Be carefull with that, on a big catalog, it can decrease performance in a significative way

	*/
	WithCount *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the currencies get list params
func (o *CurrenciesGetListParams) WithTimeout(timeout time.Duration) *CurrenciesGetListParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the currencies get list params
func (o *CurrenciesGetListParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the currencies get list params
func (o *CurrenciesGetListParams) WithContext(ctx context.Context) *CurrenciesGetListParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the currencies get list params
func (o *CurrenciesGetListParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the currencies get list params
func (o *CurrenciesGetListParams) WithHTTPClient(client *http.Client) *CurrenciesGetListParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the currencies get list params
func (o *CurrenciesGetListParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the currencies get list params
func (o *CurrenciesGetListParams) WithLimit(limit *int64) *CurrenciesGetListParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the currencies get list params
func (o *CurrenciesGetListParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithPage adds the page to the currencies get list params
func (o *CurrenciesGetListParams) WithPage(page *int64) *CurrenciesGetListParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the currencies get list params
func (o *CurrenciesGetListParams) SetPage(page *int64) {
	o.Page = page
}

// WithWithCount adds the withCount to the currencies get list params
func (o *CurrenciesGetListParams) WithWithCount(withCount *bool) *CurrenciesGetListParams {
	o.SetWithCount(withCount)
	return o
}

// SetWithCount adds the withCount to the currencies get list params
func (o *CurrenciesGetListParams) SetWithCount(withCount *bool) {
	o.WithCount = withCount
}

// WriteToRequest writes these params to a swagger request
func (o *CurrenciesGetListParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Limit != nil {

		// query param limit
		var qrLimit int64
		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {
			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}

	}

	if o.Page != nil {

		// query param page
		var qrPage int64
		if o.Page != nil {
			qrPage = *o.Page
		}
		qPage := swag.FormatInt64(qrPage)
		if qPage != "" {
			if err := r.SetQueryParam("page", qPage); err != nil {
				return err
			}
		}

	}

	if o.WithCount != nil {

		// query param with_count
		var qrWithCount bool
		if o.WithCount != nil {
			qrWithCount = *o.WithCount
		}
		qWithCount := swag.FormatBool(qrWithCount)
		if qWithCount != "" {
			if err := r.SetQueryParam("with_count", qWithCount); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}