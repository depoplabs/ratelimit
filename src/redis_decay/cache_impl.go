// Package redis_decay implements limiter.RateLimitCache with a continuously
// decaying counter (GCRA family) executed atomically in Redis via EVAL.
// Unlike the fixed-window backend there is no window timestamp in the cache
// key, so there is no boundary at which the budget resets and the classic
// 2x boundary-burst cannot occur (see issue #32).
package redis_decay

import (
	"io"
	"math"
	"strconv"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/envoyproxy/ratelimit/src/config"
	"github.com/envoyproxy/ratelimit/src/limiter"
	"github.com/envoyproxy/ratelimit/src/redis"
	"github.com/envoyproxy/ratelimit/src/server"
	"github.com/envoyproxy/ratelimit/src/settings"
	"github.com/envoyproxy/ratelimit/src/utils"
)

// Counts are stored and returned as integer milli-counts so the existing
// redis driver's uint64 result decoding can be reused unchanged.
const decayScript = `
local data = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local period = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local addend = tonumber(ARGV[4])
local count = addend
if data then
  local sep = string.find(data, ':')
  if sep then
    local prev_ts = tonumber(string.sub(data, 1, sep-1))
    local prev_count = tonumber(string.sub(data, sep+1))
    if prev_ts and prev_count then
      local passed = math.max(now - prev_ts, 0)
      local unused = passed / period * limit * 1000.0
      count = math.max(prev_count - unused, 0) + addend
    end
  end
end
redis.call('SET', KEYS[1], now .. ':' .. count, 'EX', math.ceil(period/1000))
return math.floor(count)
`

type decayRateLimitCacheImpl struct {
	client     redis.Client
	timeSource utils.TimeSource
	prefix     string
}

func NewDecayRateLimitCacheImpl(client redis.Client, timeSource utils.TimeSource, cacheKeyPrefix string) limiter.RateLimitCache {
	return &decayRateLimitCacheImpl{client: client, timeSource: timeSource, prefix: cacheKeyPrefix}
}

// NewFromSettings mirrors redis.NewRateLimiterCacheImplFromSettings's client
// construction (single pool; the per-second pool split is a fixed-window
// optimization that does not apply to a decaying counter).
func NewFromSettings(ctx context.Context, s settings.Settings, srv server.Server, timeSource utils.TimeSource) (limiter.RateLimitCache, io.Closer) {
	client := redis.NewClientImpl(ctx, srv.Scope().Scope("redis_decay_pool"), s.RedisTls, s.RedisAuth, s.RedisSocketType,
		s.RedisType, s.RedisUrl, s.RedisPoolSize,
		s.RedisPipelineWindow, s.RedisPipelineLimit, s.RedisTlsConfig, s.RedisHealthCheckActiveConnection, srv, s.RedisTimeout,
		s.RedisPoolOnEmptyBehavior, s.RedisSentinelAuth,
		s.RedisStartupInitialInterval, s.RedisStartupMaxInterval, s.RedisStartupMaxElapsedTime,
		s.RedisCloseConnectionOnReadOnlyError)
	return NewDecayRateLimitCacheImpl(client, timeSource, s.CacheKeyPrefix), client
}

// allowlistKeys names the descriptor-entry keys PLA-8129 lets an operator
// exempt at runtime, one Redis SET per key: SADD allowlist:<name> <value>
// takes effect on the very next request — no deploy, no EnvoyFilter apply.
// This replaces the compiled-in Lua tables (IP_ALLOWLIST / USER_ID_ALLOWLIST)
// that were the PLA-8129 gap: a config change was still a deploy.
var allowlistKeys = map[string]bool{"rl_ip": true, "rl_ua": true, "rl_subject": true}

func (this *decayRateLimitCacheImpl) DoLimit(
	ctx context.Context,
	request *pb.RateLimitRequest,
	limits []*config.RateLimit,
) []*pb.RateLimitResponse_DescriptorStatus {
	statuses := make([]*pb.RateLimitResponse_DescriptorStatus, len(request.Descriptors))
	results := make([]uint64, len(request.Descriptors))
	allowlisted := make([]bool, len(request.Descriptors))

	nowMs := this.timeSource.UnixNow() * 1000
	hitsAddends := utils.GetHitsAddends(request)

	// Phase 1: one round trip checking every allowlist-eligible VALUE seen
	// anywhere in the request against its own live Redis SET. Runs before any
	// decay counter is touched, so an allowlisted caller never increments a
	// bucket it will be exempted from.
	//
	// The three allowlists are NOT symmetric — matching ratelimiting.lua
	// exactly (ip_rate_limit_with_pooling / user_agent_rate_limit_with_pooling
	// / auth_rate_limit_with_pooling, :204-253):
	//   - an allowlisted IP exempts ip, ua AND subject together
	//   - an allowlisted user-agent or user-id exempts only its own bucket
	//   - client_id is never exempted by any allowlist
	// A per-descriptor-only check (allowlist this descriptor iff its own key
	// is allowlisted) reproduces the second and third rules but silently
	// drops the first — the cross-bucket IP exemption is a request-level
	// correlation, not a per-descriptor one. So this collects each key's
	// VALUE from wherever it appears in the request first, then applies the
	// exemption rule per descriptor type afterward.
	values := map[string]string{}
	for i, descriptor := range request.Descriptors {
		if limits[i] == nil {
			continue
		}
		for _, entry := range descriptor.Entries {
			if allowlistKeys[entry.Key] {
				values[entry.Key] = entry.Value
			}
		}
	}
	membership := map[string]*uint64{}
	var checkPipeline redis.Pipeline
	for key, value := range values {
		var res uint64
		membership[key] = &res
		if checkPipeline == nil {
			checkPipeline = redis.Pipeline{}
		}
		checkPipeline = this.client.PipeAppend(checkPipeline, &res, "SISMEMBER",
			this.prefix+"allowlist:"+key, value)
	}
	if checkPipeline != nil {
		if err := this.client.PipeDo(ctx, checkPipeline); err != nil {
			// Same policy as a decay-pipeline failure: surface it rather than
			// silently treating everyone as allowlisted or as not allowlisted.
			panic(redis.RedisError(err.Error()))
		}
	}
	ipAllowed := membership["rl_ip"] != nil && *membership["rl_ip"] == 1
	for i, descriptor := range request.Descriptors {
		if limits[i] == nil {
			continue
		}
		for _, entry := range descriptor.Entries {
			switch entry.Key {
			case "rl_ip":
				allowlisted[i] = ipAllowed
			case "rl_ua":
				allowlisted[i] = ipAllowed || (membership["rl_ua"] != nil && *membership["rl_ua"] == 1)
			case "rl_subject":
				allowlisted[i] = ipAllowed || (membership["rl_subject"] != nil && *membership["rl_subject"] == 1)
			}
		}
	}

	var pipeline redis.Pipeline

	for i, descriptor := range request.Descriptors {
		statuses[i] = &pb.RateLimitResponse_DescriptorStatus{Code: pb.RateLimitResponse_OK, LimitRemaining: math.MaxUint32}
		if limits[i] == nil || allowlisted[i] {
			continue
		}
		// Key without a window timestamp — the decaying value itself carries time.
		key := this.prefix + "decay_" + request.Domain
		for _, entry := range descriptor.Entries {
			key += "_" + entry.Key + "_" + entry.Value
		}
		periodMs := utils.UnitToDivider(limits[i].Limit.Unit) * 1000
		if pipeline == nil {
			pipeline = redis.Pipeline{}
		}
		pipeline = this.client.PipeAppendWithRoutingKey(pipeline, key, &results[i], "EVAL", decayScript, 1, key,
			strconv.FormatInt(nowMs, 10), strconv.FormatInt(periodMs, 10),
			strconv.FormatInt(int64(limits[i].Limit.RequestsPerUnit), 10),
			strconv.FormatUint(hitsAddends[i].Value*1000, 10))
	}

	if pipeline != nil {
		if err := this.client.PipeDo(ctx, pipeline); err != nil {
			// Surface the failure exactly as the fixed-window backend does: the
			// service layer recovers it, increments the RedisError stat, and the
			// caller's configured failure-mode policy decides whether to admit.
			// Returning OK here would hide the outage and override that policy.
			panic(redis.RedisError(err.Error()))
		}
	}

	for i := range request.Descriptors {
		if limits[i] == nil || allowlisted[i] {
			continue
		}
		limit := uint64(limits[i].Limit.RequestsPerUnit)
		countMilli := results[i]
		count := countMilli / 1000
		remaining := int64(limit) - int64(count)
		if remaining < 0 {
			remaining = 0
		}
		statuses[i].CurrentLimit = limits[i].Limit
		statuses[i].LimitRemaining = uint32(remaining)
		statuses[i].DurationUntilReset = &durationpb.Duration{Seconds: utils.UnitToDivider(limits[i].Limit.Unit)}
		if countMilli > limit*1000 {
			statuses[i].Code = pb.RateLimitResponse_OVER_LIMIT
			limits[i].Stats.OverLimit.Add(1)
		} else {
			limits[i].Stats.WithinLimit.Add(1)
		}
		limits[i].Stats.TotalHits.Add(1)
	}
	return statuses
}

func (this *decayRateLimitCacheImpl) Flush() {}
