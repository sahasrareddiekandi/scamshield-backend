package com.scamshield.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class RateLimiterService {

    private static final Logger logger = LoggerFactory.getLogger(RateLimiterService.class);

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${scamshield.ratelimit.requests-per-minute:60}")
    private int maxRequestsPerMinute;

    private final ConcurrentHashMap<String, InMemoryCounter> inMemoryLimits = new ConcurrentHashMap<>();

    private static class InMemoryCounter {
        long windowStartEpochSecond;
        int count;

        InMemoryCounter(long windowStartEpochSecond, int count) {
            this.windowStartEpochSecond = windowStartEpochSecond;
            this.count = count;
        }
    }

    public RateLimiterService(@Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean tryAcquire(String clientKey) {
        String key = "ratelimit:" + clientKey;

        if (redisTemplate != null) {
            try {
                Long currentCount = redisTemplate.opsForValue().increment(key);
                if (currentCount != null && currentCount == 1) {
                    redisTemplate.expire(key, 60, TimeUnit.SECONDS);
                }
                return currentCount != null && currentCount <= maxRequestsPerMinute;
            } catch (Exception ex) {
                logger.debug("Redis rate-limiting failed for {}: {}. Falling back to in-memory limit.", key, ex.getMessage());
            }
        }

        // Memory fallback
        long currentMinute = Instant.now().getEpochSecond() / 60;
        InMemoryCounter counter = inMemoryLimits.compute(clientKey, (k, existing) -> {
            if (existing == null || existing.windowStartEpochSecond != currentMinute) {
                return new InMemoryCounter(currentMinute, 1);
            }
            existing.count++;
            return existing;
        });

        return counter.count <= maxRequestsPerMinute;
    }
}
