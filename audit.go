package mafate

import (
	"context"
	"strconv"
)

// AuditService provides methods for the /v1/audit resource.
type AuditService struct {
	http *httpClient
}

// List returns audit log entries, optionally filtered.
// All filter fields are optional; zero values are omitted from the request.
func (s *AuditService) List(ctx context.Context, filters *AuditFilters) (*ListAuditResponse, error) {
	params := buildAuditParams(filters)
	var out ListAuditResponse
	if err := s.http.get(ctx, "/v1/audit", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyChain checks the integrity of the audit log chain.
func (s *AuditService) VerifyChain(ctx context.Context) (*AuditChainVerification, error) {
	var result AuditChainVerification
	err := s.http.get(ctx, "/v1/audit/verify", nil, &result)
	return &result, err
}

// buildAuditParams converts an AuditFilters value into URL query parameters.
// Nil or zero-value fields are not included.
func buildAuditParams(f *AuditFilters) map[string]string {
	if f == nil {
		return nil
	}
	params := make(map[string]string)
	if f.Action != "" {
		params["action"] = f.Action
	}
	if f.KeyID != "" {
		params["key_id"] = f.KeyID
	}
	if f.DateFrom != "" {
		params["date_from"] = f.DateFrom
	}
	if f.DateTo != "" {
		params["date_to"] = f.DateTo
	}
	if f.Limit > 0 {
		params["limit"] = strconv.Itoa(f.Limit)
	}
	if f.Offset > 0 {
		params["offset"] = strconv.Itoa(f.Offset)
	}
	if len(params) == 0 {
		return nil
	}
	return params
}
