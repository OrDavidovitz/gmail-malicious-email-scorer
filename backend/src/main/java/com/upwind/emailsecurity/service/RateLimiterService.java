package com.upwind.emailsecurity.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimiterService {

    private static final int MAX_REQUESTS_PER_WINDOW = 30;
    private static final long WINDOW_SECONDS = 60;

    private final Map<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();

    public boolean isAllowed(String key) {
        RateLimitBucket bucket = buckets.computeIfAbsent(key, ignored -> new RateLimitBucket());

        synchronized (bucket) {
            long now = Instant.now().getEpochSecond();

            if (now - bucket.windowStartEpochSecond >= WINDOW_SECONDS) {
                bucket.windowStartEpochSecond = now;
                bucket.requestCount = 0;
            }

            if (bucket.requestCount >= MAX_REQUESTS_PER_WINDOW) {
                return false;
            }

            bucket.requestCount++;
            return true;
        }
    }

    private static class RateLimitBucket {
        private long windowStartEpochSecond = Instant.now().getEpochSecond();
        private int requestCount = 0;
    }
}