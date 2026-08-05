package com.firewolf.cloud.signin.account;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AttemptLimiter {

    private final ConcurrentHashMap<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

    public void check(String key, int limit, Duration window, String message) {
        Deque<Instant> events = attempts.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (events) {
            removeExpired(events, window);
            if (events.size() >= limit) {
                throw DomainException.tooManyRequests(message);
            }
        }
    }

    public void record(String key, Duration window) {
        Deque<Instant> events = attempts.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (events) {
            removeExpired(events, window);
            events.addLast(Instant.now());
        }
    }

    public void reset(String key) {
        attempts.remove(key);
    }

    private void removeExpired(Deque<Instant> events, Duration window) {
        Instant threshold = Instant.now().minus(window);
        while (!events.isEmpty() && events.peekFirst().isBefore(threshold)) {
            events.removeFirst();
        }
    }
}
