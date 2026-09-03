package redis_decay_test

// Tests for the PLA-8129 runtime allowlist added to cache_impl.go: an
// operator SADDs a value to a Redis SET (allowlist:rl_ip / allowlist:rl_ua /
// allowlist:rl_subject) and it takes effect on the next request, no deploy.
// This mirrors ratelimiting.lua's ip_rate_limit_with_pooling /
// user_agent_rate_limit_with_pooling / auth_rate_limit_with_pooling
// (:204-253): the three allowlists are NOT symmetric — an allowlisted IP
// exempts all three buckets for the whole request, but an allowlisted
// user-agent or user-id exempts only its own bucket. client_id is never
// exempted by any allowlist.

import (
	"context"
	"testing"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang/mock/gomock"
	gostats "github.com/lyft/gostats"
	"github.com/stretchr/testify/assert"

	"github.com/envoyproxy/ratelimit/src/config"
	"github.com/envoyproxy/ratelimit/src/redis_decay"
	"github.com/envoyproxy/ratelimit/test/common"
	stats "github.com/envoyproxy/ratelimit/test/mocks/stats"
	mock_utils "github.com/envoyproxy/ratelimit/test/mocks/utils"
)

// An allowlisted IP exempts its own rl_ip descriptor.
func TestAllowlistedIPExemptsItsOwnBucket(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	rs.SAdd("allowlist:rl_ip", "10.0.0.1")

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{{{"rl_ip", "10.0.0.1"}}}, 1)
	limits := []*config.RateLimit{config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false)}

	// Limit is 1/min; a non-exempt caller would be OVER_LIMIT by the second
	// call. An allowlisted IP must stay OK indefinitely.
	for i := 0; i < 5; i++ {
		statuses := cache.DoLimit(context.Background(), request, limits)
		assert.Equal(pb.RateLimitResponse_OK, statuses[0].Code, "allowlisted IP request %d must be admitted", i+1)
	}
	for _, k := range rs.Keys() {
		assert.NotContains(k, "decay_", "an allowlisted request must never touch its decay counter, found key %q", k)
	}
}

// An allowlisted IP exempts rl_ua and rl_subject buckets too, even in a
// SEPARATE descriptor group within the same request — this is the
// cross-bucket rule that makes the IP allowlist different from the UA/subject
// ones, which only ever exempt their own bucket.
func TestAllowlistedIPExemptsOtherBucketsInSameRequest(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	rs.SAdd("allowlist:rl_ip", "10.0.0.1")

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{
		{{"rl_ip", "10.0.0.1"}},
		{{"rl_ua", "curl/8"}},
		{{"rl_subject", "u_alice"}},
	}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false),
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ua_value"), false, false, false, "", nil, false),
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_subject_value"), false, false, false, "", nil, false),
	}

	for i := 0; i < 3; i++ {
		statuses := cache.DoLimit(context.Background(), request, limits)
		assert.Equal(pb.RateLimitResponse_OK, statuses[0].Code, "rl_ip request %d", i+1)
		assert.Equal(pb.RateLimitResponse_OK, statuses[1].Code, "rl_ua request %d must be exempted by the IP allowlist", i+1)
		assert.Equal(pb.RateLimitResponse_OK, statuses[2].Code, "rl_subject request %d must be exempted by the IP allowlist", i+1)
	}
}

// An allowlisted user-agent exempts ONLY its own bucket — a co-occurring
// rl_ip descriptor in the same request must still be rate limited normally.
func TestAllowlistedUserAgentExemptsOnlyItsOwnBucket(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	rs.SAdd("allowlist:rl_ua", "DepopInternalBot/1.0")

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{
		{{"rl_ip", "10.0.0.9"}},
		{{"rl_ua", "DepopInternalBot/1.0"}},
	}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false),
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ua_value"), false, false, false, "", nil, false),
	}

	cache.DoLimit(context.Background(), request, limits)
	statuses := cache.DoLimit(context.Background(), request, limits)
	assert.Equal(pb.RateLimitResponse_OVER_LIMIT, statuses[0].Code, "the non-allowlisted rl_ip bucket must still enforce its limit")
	assert.Equal(pb.RateLimitResponse_OK, statuses[1].Code, "the allowlisted rl_ua bucket must stay exempt")
}

// An allowlisted subject exempts only its own bucket, same as user-agent.
func TestAllowlistedSubjectExemptsOnlyItsOwnBucket(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	rs.SAdd("allowlist:rl_subject", "86339")

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{
		{{"rl_ip", "10.0.0.9"}},
		{{"rl_subject", "86339"}},
	}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false),
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_subject_value"), false, false, false, "", nil, false),
	}

	cache.DoLimit(context.Background(), request, limits)
	statuses := cache.DoLimit(context.Background(), request, limits)
	assert.Equal(pb.RateLimitResponse_OVER_LIMIT, statuses[0].Code, "the non-allowlisted rl_ip bucket must still enforce its limit")
	assert.Equal(pb.RateLimitResponse_OK, statuses[1].Code, "the allowlisted rl_subject bucket must stay exempt")
}

// client_id is never exempted by any allowlist, even if an operator SADDs a
// value under allowlist:client_id by mistake — it is not in allowlistKeys.
func TestClientIDNeverExempted(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	rs.SAdd("allowlist:client_id", "some-client")
	rs.SAdd("allowlist:rl_ip", "10.0.0.1") // even a global IP allowlist must not reach client_id

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{
		{{"rl_ip", "10.0.0.1"}},
		{{"client_id", "some-client"}},
	}, 1)
	limits := []*config.RateLimit{
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false),
		config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("client_id_value"), false, false, false, "", nil, false),
	}

	cache.DoLimit(context.Background(), request, limits)
	statuses := cache.DoLimit(context.Background(), request, limits)
	assert.Equal(pb.RateLimitResponse_OK, statuses[0].Code, "rl_ip is allowlisted")
	assert.Equal(pb.RateLimitResponse_OVER_LIMIT, statuses[1].Code, "client_id must never be exempted by any allowlist")
}

// A value that is not in any allowlist is rate limited normally — the
// allowlist machinery must be a no-op for the common case.
func TestNonAllowlistedValueBehavesNormally(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	rs.SAdd("allowlist:rl_ip", "10.0.0.1") // a different IP is allowlisted

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{{{"rl_ip", "10.0.0.99"}}}, 1)
	limits := []*config.RateLimit{config.NewRateLimit(1, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false)}

	cache.DoLimit(context.Background(), request, limits)
	statuses := cache.DoLimit(context.Background(), request, limits)
	assert.Equal(pb.RateLimitResponse_OVER_LIMIT, statuses[0].Code, "a non-allowlisted IP must be rate limited")
}

// No allowlists configured at all: the membership check pipeline must not
// run, and behavior must be identical to the pre-allowlist implementation.
func TestNoAllowlistsConfiguredBehavesLikeBaseline(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	defer rs.Close()
	controller := gomock.NewController(t)
	defer controller.Finish()

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	cache := redis_decay.NewDecayRateLimitCacheImpl(mkClient(rs.Addr()), timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{{{"key", "value"}}}, 1)
	limits := []*config.RateLimit{config.NewRateLimit(10, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("key_value"), false, false, false, "", nil, false)}

	statuses := cache.DoLimit(context.Background(), request, limits)
	assert.Equal(pb.RateLimitResponse_OK, statuses[0].Code)
	assert.Equal(uint32(9), statuses[0].LimitRemaining)
}

// A Redis failure during the allowlist membership check must surface as
// redis.RedisError, exactly as a failure during the decay pipeline does —
// the service layer's failure-mode policy must not be bypassed just because
// the failure happened in the allowlist phase instead of the counter phase.
func TestRedisDownDuringAllowlistCheckSurfacesRedisError(t *testing.T) {
	assert := assert.New(t)
	rs := mustNewRedisServer()
	controller := gomock.NewController(t)
	defer controller.Finish()

	statsStore := gostats.NewStore(gostats.NewNullSink(), false)
	sm := stats.NewMockStatManager(statsStore)
	timeSource := mock_utils.NewMockTimeSource(controller)
	timeSource.EXPECT().UnixNow().Return(int64(1000)).AnyTimes()

	client := mkClient(rs.Addr())
	rs.Close()

	cache := redis_decay.NewDecayRateLimitCacheImpl(client, timeSource, "")
	request := common.NewRateLimitRequest("domain", [][][2]string{{{"rl_ip", "10.0.0.1"}}}, 1)
	limits := []*config.RateLimit{config.NewRateLimit(10, pb.RateLimitResponse_RateLimit_MINUTE, sm.NewStats("rl_ip_value"), false, false, false, "", nil, false)}

	defer func() {
		r := recover()
		assert.NotNil(r, "a Redis failure during the allowlist check must panic")
	}()
	cache.DoLimit(context.Background(), request, limits)
	assert.Fail("DoLimit returned normally despite Redis being down")
}
