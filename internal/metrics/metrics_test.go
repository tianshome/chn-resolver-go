package metrics

import (
	"strings"
	"testing"

	"chn-resolver/internal/policy"
)

func TestWriteRendersCounters(t *testing.T) {
	m := New([]string{"202.96.209.133:53", "8.8.8.8:53"})
	m.QueriesUDP.Add(5)
	m.QueriesTCP.Add(2)
	m.AnswersNOERROR.Add(4)
	m.AnswersNXDomain.Add(1)
	m.AnswersSERVFAIL.Add(2)
	m.DroppedOverload.Add(3)
	m.RecordPolicy(policy.PolicyPreferChina)
	m.RecordPolicy(policy.PolicyPreferChina)
	m.RecordUpstreamResult(0, "answer")
	m.RecordUpstreamResult(1, "failure")
	m.RecordUpstreamFailure(1, "timeout")
	m.Inflight.Add(7)

	var sb strings.Builder
	m.Write(&sb)
	out := sb.String()

	for _, want := range []string{
		`chn_resolver_queries_total{transport="udp"} 5`,
		`chn_resolver_queries_total{transport="tcp"} 2`,
		`chn_resolver_answers_total{rcode="noerror"} 4`,
		`chn_resolver_answers_total{rcode="nxdomain"} 1`,
		`chn_resolver_answers_total{rcode="servfail"} 2`,
		`chn_resolver_outcomes_total{outcome="dropped_overload"} 3`,
		`chn_resolver_policy_total{policy="prefer_china_from_china_resolvers"} 2`,
		`chn_resolver_upstream_results_total{upstream="202.96.209.133:53",state="answer"} 1`,
		`chn_resolver_upstream_failures_total{upstream="8.8.8.8:53",category="timeout"} 1`,
		`chn_resolver_inflight 7`,
		`chn_resolver_uptime_seconds`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n%s", want, out)
		}
	}
}

func TestRecordOutOfRangeIsNoop(t *testing.T) {
	m := New(nil)
	m.RecordUpstreamResult(3, "answer")
	m.RecordUpstreamFailure(-1, "timeout")
	// no panic is the assertion
}
