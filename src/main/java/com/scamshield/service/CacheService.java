package com.scamshield.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class CacheService {

    private static final Logger logger = LoggerFactory.getLogger(CacheService.class);

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    // In-memory fallback cache in case Redis is down or unavailable
    private final ConcurrentHashMap<String, InMemoryCacheEntry> memoryCache = new ConcurrentHashMap<>();

    private static class InMemoryCacheEntry {
        final Object value;
        final Instant expiresAt;

        InMemoryCacheEntry(Object value, long ttlSeconds) {
            this.value = value;
            this.expiresAt = ttlSeconds > 0 ? Instant.now().plusSeconds(ttlSeconds) : Instant.MAX;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    public CacheService(@Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                        ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        if (redisTemplate != null) {
            logger.info("CacheService initialized with Redis support.");
        } else {
            logger.info("CacheService initialized with High-Performance In-Memory Cache (Redis unavailable).");
        }
    }

    public <T> T get(String key, Class<T> targetClass) {
        if (redisTemplate != null) {
            try {
                Object cached = redisTemplate.opsForValue().get(key);
                if (cached != null) {
                    return objectMapper.convertValue(cached, targetClass);
                }
            } catch (Exception ex) {
                logger.debug("Redis read failed for key '{}': {}. Falling back to memory cache.", key, ex.getMessage());
            }
        }

        // Memory cache fallback
        InMemoryCacheEntry entry = memoryCache.get(key);
        if (entry != null) {
            if (entry.isExpired()) {
                memoryCache.remove(key);
                return null;
            }
            try {
                return objectMapper.convertValue(entry.value, targetClass);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    public void set(String key, Object value, long ttlSeconds) {
        if (redisTemplate != null) {
            try {
                redisTemplate.opsForValue().set(key, value, ttlSeconds, TimeUnit.SECONDS);
                return;
            } catch (Exception ex) {
                logger.debug("Redis write failed for key '{}': {}. Storing in memory cache.", key, ex.getMessage());
            }
        }

        // Memory cache fallback
        memoryCache.put(key, new InMemoryCacheEntry(value, ttlSeconds));
    }

    public void evict(String key) {
        if (redisTemplate != null) {
            try {
                redisTemplate.delete(key);
            } catch (Exception ignored) {}
        }
        memoryCache.remove(key);
    }
}
