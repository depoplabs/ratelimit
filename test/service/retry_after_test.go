package ratelimit_test

import (
	"os"
	"testing"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"golang.org/x/net/context"

	"github.com/envoyproxy/ratelimit/src/config"
	"github.com/envoyproxy/ratelimit/test/common"
)

// The header is opt-in, matching the existing custom-header flag, so existing
// deployments see no change in response shape. Enable it for these tests.
func withRetryAfterEnabled(t *testing.T) {
	t.Helper()
	old, had := os.LookupEnv("RETRY_AFTER_HEADER_ENABLED")
	os.Setenv("RETRY_AFTER_HEADER_ENABLED", "true")
	t.Cleanup(func() {
		// restoring an empty string would break envconfig's bool parsing
		if had {
			os.Setenv("RETRY_AFTER_HEADER_ENABLED", old)
		} else {
			os.Unsetenv("RETRY_AFTER_HEADER_ENABLED")
		}
	})
}

func headerValue(t rateLimitServiceTestSuite, resp *pb.RateLimitResponse, name string) string {
	for _, h := range resp.ResponseHeadersToAdd {
		if h.Key == name {
			return h.Value
		}
	}
	return ""
}

// depop-routing sets `Retry-After: <period>` on a hard breach
// (ratelimiting.lua:114). Clients and SDKs use it to back off; without it they
// retry immediately and keep the bucket saturated.
func TestRetryAfterSetOnOverLimit(test *testing.T) {
	withRetryAfterEnabled(test)
	t := commonSetup(test)
	defer t.controller.Finish()
	service := t.setupBasicService()

	request := common.NewRateLimitRequest("test-domain", [][][2]string{{{"hello", "world"}}}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(10, pb.RateLimitResponse_RateLimit_MINUTE, t.statsManager.NewStats("key"), false, false, false, "", nil, false),
	}
	t.config.EXPECT().GetLimit(context.Background(), "test-domain", request.Descriptors[0]).Return(limits[0])
	t.cache.EXPECT().DoLimit(context.Background(), request, limits).Return(
		[]*pb.RateLimitResponse_DescriptorStatus{{Code: pb.RateLimitResponse_OVER_LIMIT, CurrentLimit: limits[0].Limit, LimitRemaining: 0}})

	response, err := service.ShouldRateLimit(context.Background(), request)
	t.assert.Nil(err)
	t.assert.Equal(pb.RateLimitResponse_OVER_LIMIT, response.OverallCode)
	// a MINUTE limit means retry after 60 seconds
	t.assert.Equal("60", headerValue(t, response, "retry-after"),
		"Retry-After must carry the limit period in seconds")
}

// An admitted request must not carry Retry-After — it would tell a healthy
// client to back off for no reason.
func TestNoRetryAfterWhenAdmitted(test *testing.T) {
	withRetryAfterEnabled(test)
	t := commonSetup(test)
	defer t.controller.Finish()
	service := t.setupBasicService()

	request := common.NewRateLimitRequest("test-domain", [][][2]string{{{"hello", "world"}}}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(10, pb.RateLimitResponse_RateLimit_MINUTE, t.statsManager.NewStats("key"), false, false, false, "", nil, false),
	}
	t.config.EXPECT().GetLimit(context.Background(), "test-domain", request.Descriptors[0]).Return(limits[0])
	t.cache.EXPECT().DoLimit(context.Background(), request, limits).Return(
		[]*pb.RateLimitResponse_DescriptorStatus{{Code: pb.RateLimitResponse_OK, CurrentLimit: limits[0].Limit, LimitRemaining: 5}})

	response, err := service.ShouldRateLimit(context.Background(), request)
	t.assert.Nil(err)
	t.assert.Equal("", headerValue(t, response, "retry-after"))
}

// The period must follow the breaching descriptor's own unit, not a default.
func TestRetryAfterUsesTheBreachingDescriptorsUnit(test *testing.T) {
	withRetryAfterEnabled(test)
	t := commonSetup(test)
	defer t.controller.Finish()
	service := t.setupBasicService()

	request := common.NewRateLimitRequest("test-domain", [][][2]string{{{"hello", "world"}}}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(10, pb.RateLimitResponse_RateLimit_HOUR, t.statsManager.NewStats("key"), false, false, false, "", nil, false),
	}
	t.config.EXPECT().GetLimit(context.Background(), "test-domain", request.Descriptors[0]).Return(limits[0])
	t.cache.EXPECT().DoLimit(context.Background(), request, limits).Return(
		[]*pb.RateLimitResponse_DescriptorStatus{{Code: pb.RateLimitResponse_OVER_LIMIT, CurrentLimit: limits[0].Limit, LimitRemaining: 0}})

	response, err := service.ShouldRateLimit(context.Background(), request)
	t.assert.Nil(err)
	t.assert.Equal("3600", headerValue(t, response, "retry-after"))
}
