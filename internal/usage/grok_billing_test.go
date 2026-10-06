package usage

import (
	"testing"
	"time"
)

// Captured shape of a live `_x.ai/billing` result a day after a weekly reset
// (values other than the period are proto3 zeros). creditUsagePercent and
// used are absent because proto3 JSON omits zero-valued scalars.
const grokFreshPeriodConfig = `"onDemandCap":{"val":0},"onDemandUsed":{"val":0},"prepaidBalance":{"val":0},` +
	`"isUnifiedBillingUser":true,` +
	`"billingPeriodStart":"2026-10-05T21:44:41.777818+00:00","billingPeriodEnd":"2026-10-12T21:44:41.777818+00:00",` +
	`"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-10-05T21:44:41.777818+00:00","end":"2026-10-12T21:44:41.777818+00:00"}`

func TestParseGrokBillingFreshPeriod(t *testing.T) {
	now := time.Date(2026, 10, 6, 2, 59, 0, 0, time.UTC)
	reset := time.Date(2026, 10, 12, 21, 44, 41, 777818000, time.UTC)
	week := 7 * 24 * time.Hour
	tests := []struct {
		name     string
		raw      string
		now      time.Time
		status   string
		known    bool
		pct      int
		util     float64
		hasError bool
	}{
		{
			name:   "fresh period with usage omitted reads as 0%",
			raw:    `{"subscription_tier":"SuperGrok Heavy","config":{` + grokFreshPeriodConfig + `}}`,
			now:    now,
			status: QuotaOK, known: true, pct: 0, util: 0,
		},
		{
			name:   "percent present is used as is",
			raw:    `{"config":{"creditUsagePercent":37.5,` + grokFreshPeriodConfig + `}}`,
			now:    now,
			status: QuotaOK, known: true, pct: 37, util: 0.375,
		},
		{
			name:   "used and limit present are used when percent is omitted",
			raw:    `{"config":{"monthlyLimit":{"val":1000},"used":{"val":250},` + grokFreshPeriodConfig + `}}`,
			now:    now,
			status: QuotaOK, known: true, pct: 25, util: 0.25,
		},
		{
			name:   "period missing stays degraded",
			raw:    `{"subscription_tier":"SuperGrok Heavy","config":{"onDemandCap":{"val":0},"isUnifiedBillingUser":true}}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "garbled period stays degraded",
			raw:    `{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"yesterday","end":"next week"}}}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "period that ends before it starts stays degraded",
			raw:    `{"config":{"currentPeriod":{"start":"2026-10-12T21:44:41Z","end":"2026-10-05T21:44:41Z"}}}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "period already over stays degraded",
			raw:    `{"config":{` + grokFreshPeriodConfig + `}}`,
			now:    reset.Add(time.Minute),
			status: QuotaDegraded,
		},
		{
			name:   "percent present but null is not read as zero",
			raw:    `{"config":{"creditUsagePercent":null,` + grokFreshPeriodConfig + `}}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "percent present but garbled is not read as zero",
			raw:    `{"config":{"creditUsagePercent":"12junk",` + grokFreshPeriodConfig + `}}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "used present without a limit is not read as zero",
			raw:    `{"config":{"used":{"val":250},` + grokFreshPeriodConfig + `}}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "no config object stays degraded",
			raw:    `{"subscription_tier":"SuperGrok Heavy"}`,
			now:    now,
			status: QuotaDegraded,
		},
		{
			name:   "invalid JSON is unavailable",
			raw:    `{"config":{` + grokFreshPeriodConfig,
			now:    now,
			status: QuotaUnavailable, hasError: true,
		},
		{
			name:   "empty response is unavailable",
			raw:    ``,
			now:    now,
			status: QuotaUnavailable, hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := parseGrokBilling([]byte(tt.raw), tt.now)
			if info.QuotaStatus != tt.status {
				t.Fatalf("status = %q (note %q), want %q", info.QuotaStatus, info.QuotaNote, tt.status)
			}
			if (info.Error != "") != tt.hasError {
				t.Fatalf("error = %q, want error: %v", info.Error, tt.hasError)
			}
			if got := info.NumericQuotaKnown(); got != tt.known {
				t.Fatalf("NumericQuotaKnown = %v, want %v: %+v", got, tt.known, info)
			}
			if !tt.known {
				return
			}
			w := info.PrimaryWindow
			if w.UsedPercent != tt.pct || w.Utilization != tt.util || w.Unmeasured {
				t.Fatalf("window = %+v, want %d%% (%v) measured", w, tt.pct, tt.util)
			}
			if !w.ResetsAt.Equal(reset) || w.WindowDuration != week {
				t.Fatalf("window reset/duration = %v/%v, want %v/%v", w.ResetsAt, w.WindowDuration, reset, week)
			}
		})
	}
}
