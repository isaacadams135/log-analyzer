package com.github.isaacadams135.loganalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class LogAnalyzerTest {

    private static final String FAILED = "Failed password for root from %s port 22 ssh2";
    private static final String ACCEPTED = "Accepted password for root from %s port 22 ssh2";

    @Test
    void detectsBruteForceFromSameIp() {
        List<LogEntry> entries = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            entries.add(failure(10, i, "203.0.113.50"));
        }
        entries.add(failure(11, 0, "198.51.100.7"));
        entries.add(failure(11, 1, "198.51.100.7"));

        LogAnalyzer analyzer = new LogAnalyzer(entries, 10, 5);
        List<LogAnalyzer.BruteForce> brute = analyzer.bruteForce();

        assertEquals(1, brute.size());
        assertEquals("203.0.113.50", brute.get(0).ip());
        assertEquals(6, brute.get(0).count());
        assertEquals(entryTime(10, 0), brute.get(0).first());
        assertEquals(entryTime(10, 5), brute.get(0).last());
    }

    @Test
    void detectsLoginAfterFailureRun() {
        List<LogEntry> entries = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            entries.add(failure(10, i, "203.0.113.50"));
        }
        entries.add(accepted(10, 6, "203.0.113.50"));
        entries.add(accepted(11, 0, "192.168.1.20")); // clean IP, never fails

        LogAnalyzer analyzer = new LogAnalyzer(entries, 10, 5);
        List<LogAnalyzer.SuspiciousLogin> suspicious = analyzer.suspiciousLogins();

        assertEquals(1, suspicious.size());
        assertEquals("203.0.113.50", suspicious.get(0).ip());
        assertEquals("root", suspicious.get(0).user());
        assertEquals(entryTime(10, 6), suspicious.get(0).time());
    }

    @Test
    void ordersTopOffendingIpsByFailureCount() {
        List<LogEntry> entries = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            entries.add(failure(8, i, "203.0.113.50"));
        }
        for (int i = 0; i < 3; i++) {
            entries.add(failure(11, i, "198.51.100.7"));
        }
        entries.add(failure(13, 0, "192.0.2.66"));
        entries.add(accepted(14, 0, "203.0.113.50"));

        List<LogAnalyzer.TopIp> top = new LogAnalyzer(entries, 10, 5).topIps(2);

        assertEquals(2, top.size());
        assertEquals("203.0.113.50", top.get(0).ip());
        assertEquals(7, top.get(0).failures());
        assertEquals("198.51.100.7", top.get(1).ip());
        assertEquals(3, top.get(1).failures());
    }

    @Test
    void exactlyThresholdFailuresStillTrigger() {
        List<LogEntry> entries = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            entries.add(failure(10, i, "203.0.113.50"));
        }
        for (int i = 0; i < 4; i++) {
            entries.add(failure(12, i, "198.51.100.7")); // one short of the threshold
        }

        List<LogAnalyzer.BruteForce> brute = new LogAnalyzer(entries, 10, 5).bruteForce();

        assertEquals(1, brute.size());
        assertEquals("203.0.113.50", brute.get(0).ip());
        assertEquals(5, brute.get(0).count());
    }

    private static Instant entryTime(int hour, int minute) {
        return LocalDateTime.of(2026, 10, 12, hour, minute, 0)
                .atZone(ZoneId.systemDefault()).toInstant();
    }

    private static LogEntry failure(int hour, int minute, String ip) {
        return new LogEntry(entryTime(hour, minute), "web01", String.format(FAILED, ip), ip);
    }

    private static LogEntry accepted(int hour, int minute, String ip) {
        return new LogEntry(entryTime(hour, minute), "web01", String.format(ACCEPTED, ip), ip);
    }
}
