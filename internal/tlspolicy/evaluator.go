package tlspolicy

import "time"

type Evaluator struct {
	policy *PolicyService
	clock  func() time.Time
}

func NewEvaluator(policy *PolicyService, clock func() time.Time) *Evaluator {
	if clock == nil {
		clock = time.Now
	}
	return &Evaluator{policy: policy, clock: clock}
}

func (e *Evaluator) Resolve(platformID, target string) (ResolvedPolicy, error) {
	if e == nil || e.policy == nil {
		return ResolvedPolicy{}, ErrIntegrity
	}
	return e.policy.Resolve(platformID, target, e.clock())
}
