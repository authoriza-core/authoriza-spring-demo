package com.example.oidc_client.util;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Component
public class TokenTimeFormatter {

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    public String formatInstant(Instant instant) {
        if (instant == null) {
            return "—";
        }

        return DATE_TIME_FORMATTER.format(instant);
    }

    public String formatRemainingTime(Instant expiresAt) {
        if (expiresAt == null) {
            return "неизвестно";
        }

        Instant now = Instant.now();

        if (!expiresAt.isAfter(now)) {
            return "истёк";
        }

        Duration duration = Duration.between(now, expiresAt);

        long days = duration.toDays();
        long hours = duration.toHoursPart();
        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();

        if (days > 0) {
            return days + " д. " + hours + " ч. " + minutes + " мин.";
        }

        if (hours > 0) {
            return hours + " ч. " + minutes + " мин.";
        }

        if (minutes > 0) {
            return minutes + " мин. " + seconds + " сек.";
        }

        return seconds + " сек.";
    }

    public boolean isExpired(Instant expiresAt) {
        return expiresAt != null && !expiresAt.isAfter(Instant.now());
    }

    public boolean isExpiringSoon(Instant expiresAt, Duration threshold) {
        if (expiresAt == null || threshold == null) {
            return false;
        }

        Instant limit = Instant.now().plus(threshold);

        return expiresAt.isAfter(Instant.now()) && expiresAt.isBefore(limit);
    }

    public long secondsUntilExpiration(Instant expiresAt) {
        if (expiresAt == null) {
            return -1;
        }

        return Duration.between(Instant.now(), expiresAt).toSeconds();
    }
}