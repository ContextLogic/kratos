// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod CompleteSelfServiceVerificationFlowWithLinkMethod complete self service verification flow with link method
//
// swagger:model completeSelfServiceVerificationFlowWithLinkMethod
type CompleteSelfServiceVerificationFlowWithLinkMethod struct {

	// Sending the anti-csrf token is only required for browser login flows.
	CsrfToken string `json:"csrf_token,omitempty"`

	// Email to Verify
	//
	// Needs to be set when initiating the flow. If the email is a registered
	// verification email, a verification link will be sent. If the email is not known,
	// a email with details on what happened will be sent instead.
	//
	// format: email
	// in: body
	Email string `json:"email,omitempty"`
}

// Validate validates this complete self service verification flow with link method
func (m *CompleteSelfServiceVerificationFlowWithLinkMethod) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this complete self service verification flow with link method based on context it is used
func (m *CompleteSelfServiceVerificationFlowWithLinkMethod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CompleteSelfServiceVerificationFlowWithLinkMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CompleteSelfServiceVerificationFlowWithLinkMethod) UnmarshalBinary(b []byte) error {
	var res CompleteSelfServiceVerificationFlowWithLinkMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
