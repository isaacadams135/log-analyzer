package com.github.isaacadams135.loganalyzer;

import java.time.Instant;

/** One parsed log line. ip is null when the message has no IPv4 address. */
public record LogEntry(Instant time, String host, String message, String ip) {
}
