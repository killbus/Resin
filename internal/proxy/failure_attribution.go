package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/Resinat/Resin/internal/routing"
)

type FailureAttribution string

const (
	FailureNode           FailureAttribution = "Node"
	FailureTargetIdentity FailureAttribution = "TargetIdentity"
	FailureTargetService  FailureAttribution = "TargetService"
	FailureClient         FailureAttribution = "Client"
	FailureLocalPolicy    FailureAttribution = "LocalPolicy"
	FailureUnknown        FailureAttribution = "Unknown"
)

// NodeTransportFailure is the only negative-health proof accepted by the
// reverse data plane. Producers must use it only for a failure connecting or
// handshaking to the selected Resin node itself, never for the target hop.
type NodeTransportFailure struct {
	Err error
}

func (e *NodeTransportFailure) Error() string {
	if e == nil || e.Err == nil {
		return "selected Resin node transport failed"
	}
	return e.Err.Error()
}

func (e *NodeTransportFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// OpaqueRoutedDialFailure means the composite routed outbound call returned
// before yielding a stream. Sing-box may have failed either while connecting
// to the selected node or while asking that node to connect to the target, so
// this marker is boundary context, not proof of node failure.
type OpaqueRoutedDialFailure struct {
	Err error
}

func (e *OpaqueRoutedDialFailure) Error() string {
	if e == nil || e.Err == nil {
		return "routed outbound dial failed"
	}
	return e.Err.Error()
}

func (e *OpaqueRoutedDialFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type FailureAssessment struct {
	Detail             upstreamErrorDetail
	Attribution        FailureAttribution
	NegativeNodeHealth bool
}

type FailureAttributor interface {
	Assess(err error, decision ReverseRequestDecision) FailureAssessment
}

type defaultFailureAttributor struct{}

func (defaultFailureAttributor) Assess(err error, _ ReverseRequestDecision) FailureAssessment {
	assessment := FailureAssessment{Detail: summarizeUpstreamError(err), Attribution: FailureUnknown}
	var nodeFailure *NodeTransportFailure
	if errors.As(err, &nodeFailure) {
		assessment.Attribution = FailureNode
		assessment.NegativeNodeHealth = true
		return assessment
	}
	if errors.Is(err, context.Canceled) {
		assessment.Attribution = FailureClient
		return assessment
	}
	var opaqueRoutedDial *OpaqueRoutedDialFailure
	if errors.As(err, &opaqueRoutedDial) {
		// The routed adapter boundary combines node connection with target
		// negotiation. Even an X.509 symptom here may belong to node-side TLS,
		// so retain Unknown unless a nested producer supplied explicit proof.
		return assessment
	}
	var certInvalid x509.CertificateInvalidError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &certInvalid) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &recordHeader) {
		assessment.Attribution = FailureTargetIdentity
		return assessment
	}
	// DNS, refusal, timeout, reset, target service errors, and generic
	// RoundTrip failures are deliberately Unknown without node-local proof.
	return assessment
}

type ReverseHealthFeedback interface {
	RecordFailure(route *routing.RouteResult, assessment FailureAssessment)
	RecordSuccess(route *routing.RouteResult)
}

type reverseHealthFeedback struct {
	health HealthRecorder
}

func (f reverseHealthFeedback) RecordFailure(route *routing.RouteResult, assessment FailureAssessment) {
	if route == nil || f.health == nil || !assessment.NegativeNodeHealth || assessment.Attribution != FailureNode {
		return
	}
	recordPassiveResultAsync(f.health, *route, false)
}

func (f reverseHealthFeedback) RecordSuccess(route *routing.RouteResult) {
	if route == nil || f.health == nil {
		return
	}
	recordPassiveResultAsync(f.health, *route, true)
}
