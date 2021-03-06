// Code generated by go-swagger; DO NOT EDIT.

package product

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

// NewGetProductsParams creates a new GetProductsParams object
// with the default values initialized.
func NewGetProductsParams() *GetProductsParams {
	var (
		limitDefault                = int64(10)
		pageDefault                 = int64(1)
		paginationTypeDefault       = string("page")
		searchAfterDefault          = string("cursor to the first page")
		withAttributeOptionsDefault = bool(false)
		withCountDefault            = bool(false)
		withQualityScoresDefault    = bool(false)
	)
	return &GetProductsParams{
		Limit:                &limitDefault,
		Page:                 &pageDefault,
		PaginationType:       &paginationTypeDefault,
		SearchAfter:          &searchAfterDefault,
		WithAttributeOptions: &withAttributeOptionsDefault,
		WithCount:            &withCountDefault,
		WithQualityScores:    &withQualityScoresDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewGetProductsParamsWithTimeout creates a new GetProductsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetProductsParamsWithTimeout(timeout time.Duration) *GetProductsParams {
	var (
		limitDefault                = int64(10)
		pageDefault                 = int64(1)
		paginationTypeDefault       = string("page")
		searchAfterDefault          = string("cursor to the first page")
		withAttributeOptionsDefault = bool(false)
		withCountDefault            = bool(false)
		withQualityScoresDefault    = bool(false)
	)
	return &GetProductsParams{
		Limit:                &limitDefault,
		Page:                 &pageDefault,
		PaginationType:       &paginationTypeDefault,
		SearchAfter:          &searchAfterDefault,
		WithAttributeOptions: &withAttributeOptionsDefault,
		WithCount:            &withCountDefault,
		WithQualityScores:    &withQualityScoresDefault,

		timeout: timeout,
	}
}

// NewGetProductsParamsWithContext creates a new GetProductsParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetProductsParamsWithContext(ctx context.Context) *GetProductsParams {
	var (
		limitDefault                = int64(10)
		pageDefault                 = int64(1)
		paginationTypeDefault       = string("page")
		searchAfterDefault          = string("cursor to the first page")
		withAttributeOptionsDefault = bool(false)
		withCountDefault            = bool(false)
		withQualityScoresDefault    = bool(false)
	)
	return &GetProductsParams{
		Limit:                &limitDefault,
		Page:                 &pageDefault,
		PaginationType:       &paginationTypeDefault,
		SearchAfter:          &searchAfterDefault,
		WithAttributeOptions: &withAttributeOptionsDefault,
		WithCount:            &withCountDefault,
		WithQualityScores:    &withQualityScoresDefault,

		Context: ctx,
	}
}

// NewGetProductsParamsWithHTTPClient creates a new GetProductsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetProductsParamsWithHTTPClient(client *http.Client) *GetProductsParams {
	var (
		limitDefault                = int64(10)
		pageDefault                 = int64(1)
		paginationTypeDefault       = string("page")
		searchAfterDefault          = string("cursor to the first page")
		withAttributeOptionsDefault = bool(false)
		withCountDefault            = bool(false)
		withQualityScoresDefault    = bool(false)
	)
	return &GetProductsParams{
		Limit:                &limitDefault,
		Page:                 &pageDefault,
		PaginationType:       &paginationTypeDefault,
		SearchAfter:          &searchAfterDefault,
		WithAttributeOptions: &withAttributeOptionsDefault,
		WithCount:            &withCountDefault,
		WithQualityScores:    &withQualityScoresDefault,
		HTTPClient:           client,
	}
}

/*GetProductsParams contains all the parameters to send to the API endpoint
for the get products operation typically these are written to a http.Request
*/
type GetProductsParams struct {

	/*Attributes
	  Filter product values to only return those concerning the given attributes, for more details see the <a href="/documentation/filter.html#filter-product-values">Filter on product values</a> section

	*/
	Attributes *string
	/*Limit
	  Number of results by page, see <a href="/documentation/pagination.html">Pagination</a> section

	*/
	Limit *int64
	/*Locales
	  Filter product values to return localizable attributes for the given locales as well as the non localizable/non scopable attributes, for more details see the <a href="/documentation/filter.html#filter-product-values">Filter on product values</a> section

	*/
	Locales *string
	/*Page
	  Number of the page to retrieve when using the `page` pagination method type. <strong>Should never be set manually</strong>, see <a href="/documentation/pagination.html#pagination">Pagination</a> section

	*/
	Page *int64
	/*PaginationType
	  Pagination method type, see <a href="/documentation/pagination.html">Pagination</a> section

	*/
	PaginationType *string
	/*Scope
	  Filter product values to return scopable attributes for the given channel as well as the non localizable/non scopable attributes, for more details see the <a href="/documentation/filter.html#filter-product-values">Filter on product values</a> section

	*/
	Scope *string
	/*Search
	  Filter products, for more details see the <a href="/documentation/filter.html">Filters</a> section

	*/
	Search *string
	/*SearchAfter
	  Cursor when using the `search_after` pagination method type. <strong>Should never be set manually</strong>, see <a href="/documentation/pagination.html">Pagination</a> section

	*/
	SearchAfter *string
	/*WithAttributeOptions
	  Return labels of attribute options in the response. (Only available in the PIM Serenity version.)

	*/
	WithAttributeOptions *bool
	/*WithCount
	  Return the count of products in the response. Be carefull with that, on a big catalog, it can decrease performance in a significative way

	*/
	WithCount *bool
	/*WithQualityScores
	  Return product quality scores in the response. (Only available in the PIM Serenity version.)

	*/
	WithQualityScores *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get products params
func (o *GetProductsParams) WithTimeout(timeout time.Duration) *GetProductsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get products params
func (o *GetProductsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get products params
func (o *GetProductsParams) WithContext(ctx context.Context) *GetProductsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get products params
func (o *GetProductsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get products params
func (o *GetProductsParams) WithHTTPClient(client *http.Client) *GetProductsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get products params
func (o *GetProductsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAttributes adds the attributes to the get products params
func (o *GetProductsParams) WithAttributes(attributes *string) *GetProductsParams {
	o.SetAttributes(attributes)
	return o
}

// SetAttributes adds the attributes to the get products params
func (o *GetProductsParams) SetAttributes(attributes *string) {
	o.Attributes = attributes
}

// WithLimit adds the limit to the get products params
func (o *GetProductsParams) WithLimit(limit *int64) *GetProductsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get products params
func (o *GetProductsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithLocales adds the locales to the get products params
func (o *GetProductsParams) WithLocales(locales *string) *GetProductsParams {
	o.SetLocales(locales)
	return o
}

// SetLocales adds the locales to the get products params
func (o *GetProductsParams) SetLocales(locales *string) {
	o.Locales = locales
}

// WithPage adds the page to the get products params
func (o *GetProductsParams) WithPage(page *int64) *GetProductsParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the get products params
func (o *GetProductsParams) SetPage(page *int64) {
	o.Page = page
}

// WithPaginationType adds the paginationType to the get products params
func (o *GetProductsParams) WithPaginationType(paginationType *string) *GetProductsParams {
	o.SetPaginationType(paginationType)
	return o
}

// SetPaginationType adds the paginationType to the get products params
func (o *GetProductsParams) SetPaginationType(paginationType *string) {
	o.PaginationType = paginationType
}

// WithScope adds the scope to the get products params
func (o *GetProductsParams) WithScope(scope *string) *GetProductsParams {
	o.SetScope(scope)
	return o
}

// SetScope adds the scope to the get products params
func (o *GetProductsParams) SetScope(scope *string) {
	o.Scope = scope
}

// WithSearch adds the search to the get products params
func (o *GetProductsParams) WithSearch(search *string) *GetProductsParams {
	o.SetSearch(search)
	return o
}

// SetSearch adds the search to the get products params
func (o *GetProductsParams) SetSearch(search *string) {
	o.Search = search
}

// WithSearchAfter adds the searchAfter to the get products params
func (o *GetProductsParams) WithSearchAfter(searchAfter *string) *GetProductsParams {
	o.SetSearchAfter(searchAfter)
	return o
}

// SetSearchAfter adds the searchAfter to the get products params
func (o *GetProductsParams) SetSearchAfter(searchAfter *string) {
	o.SearchAfter = searchAfter
}

// WithWithAttributeOptions adds the withAttributeOptions to the get products params
func (o *GetProductsParams) WithWithAttributeOptions(withAttributeOptions *bool) *GetProductsParams {
	o.SetWithAttributeOptions(withAttributeOptions)
	return o
}

// SetWithAttributeOptions adds the withAttributeOptions to the get products params
func (o *GetProductsParams) SetWithAttributeOptions(withAttributeOptions *bool) {
	o.WithAttributeOptions = withAttributeOptions
}

// WithWithCount adds the withCount to the get products params
func (o *GetProductsParams) WithWithCount(withCount *bool) *GetProductsParams {
	o.SetWithCount(withCount)
	return o
}

// SetWithCount adds the withCount to the get products params
func (o *GetProductsParams) SetWithCount(withCount *bool) {
	o.WithCount = withCount
}

// WithWithQualityScores adds the withQualityScores to the get products params
func (o *GetProductsParams) WithWithQualityScores(withQualityScores *bool) *GetProductsParams {
	o.SetWithQualityScores(withQualityScores)
	return o
}

// SetWithQualityScores adds the withQualityScores to the get products params
func (o *GetProductsParams) SetWithQualityScores(withQualityScores *bool) {
	o.WithQualityScores = withQualityScores
}

// WriteToRequest writes these params to a swagger request
func (o *GetProductsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Attributes != nil {

		// query param attributes
		var qrAttributes string
		if o.Attributes != nil {
			qrAttributes = *o.Attributes
		}
		qAttributes := qrAttributes
		if qAttributes != "" {
			if err := r.SetQueryParam("attributes", qAttributes); err != nil {
				return err
			}
		}

	}

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

	if o.Locales != nil {

		// query param locales
		var qrLocales string
		if o.Locales != nil {
			qrLocales = *o.Locales
		}
		qLocales := qrLocales
		if qLocales != "" {
			if err := r.SetQueryParam("locales", qLocales); err != nil {
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

	if o.PaginationType != nil {

		// query param pagination_type
		var qrPaginationType string
		if o.PaginationType != nil {
			qrPaginationType = *o.PaginationType
		}
		qPaginationType := qrPaginationType
		if qPaginationType != "" {
			if err := r.SetQueryParam("pagination_type", qPaginationType); err != nil {
				return err
			}
		}

	}

	if o.Scope != nil {

		// query param scope
		var qrScope string
		if o.Scope != nil {
			qrScope = *o.Scope
		}
		qScope := qrScope
		if qScope != "" {
			if err := r.SetQueryParam("scope", qScope); err != nil {
				return err
			}
		}

	}

	if o.Search != nil {

		// query param search
		var qrSearch string
		if o.Search != nil {
			qrSearch = *o.Search
		}
		qSearch := qrSearch
		if qSearch != "" {
			if err := r.SetQueryParam("search", qSearch); err != nil {
				return err
			}
		}

	}

	if o.SearchAfter != nil {

		// query param search_after
		var qrSearchAfter string
		if o.SearchAfter != nil {
			qrSearchAfter = *o.SearchAfter
		}
		qSearchAfter := qrSearchAfter
		if qSearchAfter != "" {
			if err := r.SetQueryParam("search_after", qSearchAfter); err != nil {
				return err
			}
		}

	}

	if o.WithAttributeOptions != nil {

		// query param with_attribute_options
		var qrWithAttributeOptions bool
		if o.WithAttributeOptions != nil {
			qrWithAttributeOptions = *o.WithAttributeOptions
		}
		qWithAttributeOptions := swag.FormatBool(qrWithAttributeOptions)
		if qWithAttributeOptions != "" {
			if err := r.SetQueryParam("with_attribute_options", qWithAttributeOptions); err != nil {
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

	if o.WithQualityScores != nil {

		// query param with_quality_scores
		var qrWithQualityScores bool
		if o.WithQualityScores != nil {
			qrWithQualityScores = *o.WithQualityScores
		}
		qWithQualityScores := swag.FormatBool(qrWithQualityScores)
		if qWithQualityScores != "" {
			if err := r.SetQueryParam("with_quality_scores", qWithQualityScores); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
