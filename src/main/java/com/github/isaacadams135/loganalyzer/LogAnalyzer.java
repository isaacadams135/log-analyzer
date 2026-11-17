package com.github.isaacadams135.loganalyzer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Holds the parsed entries and works out what is suspicious: brute-force
 * episodes (enough failures from one IP inside the sliding window) and
 * logins that came right after such an episode (credential stuffing).
 */
public final class LogAnalyzer {

    public record BruteForce(String ip, int count, Instant first, Instant last) {
    }

    public record SuspiciousLogin(String ip, String user, Instant time) {
    }

    public record TopIp(String ip, int failures) {
    }

    public record Totals(int failures, int invalidUsers, int successes, int sudoFailures, int other) {
    }

    private final List<LogEntry> entries;
    private final Map<String, List<Instant>> failuresByIp;
    private final Duration window;
    private final int threshold;

    public LogAnalyzer(List<LogEntry> entries, int windowMinutes, int threshold) {
        if (windowMinutes < 1) {
            throw new IllegalArgumentException("window must be at least 1 minute");
        }
        if (threshold < 1) {
            throw new IllegalArgumentException("threshold must be at least 1");
        }
        this.entries = entries.stream().sorted(Comparator.comparing(LogEntry::time)).toList();
        this.window = Duration.ofMinutes(windowMinutes);
        this.threshold = threshold;
        this.failuresByIp = indexFailures(this.entries);
    }

    public Totals totals() {
        int failures = 0;
        int invalidUsers = 0;
        int successes = 0;
        int sudoFailures = 0;
        int other = 0;
        for (LogEntry entry : entries) {
            switch (LogParser.classify(entry)) {
                case FAILURE -> failures++;
                case INVALID_USER -> invalidUsers++;
                case SUCCESS -> successes++;
                case SUDO_FAILURE -> sudoFailures++;
                case OTHER -> other++;
            }
        }
        return new Totals(failures, invalidUsers, successes, sudoFailures, other);
    }

    public List<BruteForce> bruteForce() {
        List<BruteForce> found = new ArrayList<>();
        for (Map.Entry<String, List<Instant>> e : failuresByIp.entrySet()) {
            findEpisodes(e.getKey(), e.getValue()).forEach(found::add);
        }
        found.sort(Comparator.comparing(BruteForce::first));
        return found;
    }

    public List<SuspiciousLogin> suspiciousLogins() {
        List<SuspiciousLogin> found = new ArrayList<>();
        for (LogEntry entry : entries) {
            if (entry.ip() == null || LogParser.classify(entry) != LogParser.EventType.SUCCESS) {
                continue;
            }
            if (recentFailures(entry.ip(), entry.time()) >= threshold) {
                found.add(new SuspiciousLogin(entry.ip(), LogParser.successUser(entry), entry.time()));
            }
        }
        return found;
    }

    public List<TopIp> topIps(int n) {
        Map<String, Integer> counts = new TreeMap<>();
        for (LogEntry entry : entries) {
            if (entry.ip() != null && isFailure(entry)) {
                counts.merge(entry.ip(), 1, Integer::sum);
            }
        }
        List<TopIp> top = new ArrayList<>();
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            top.add(new TopIp(e.getKey(), e.getValue()));
        }
        top.sort(Comparator.comparingInt(TopIp::failures).reversed().thenComparing(TopIp::ip));
        return top.size() > n ? List.copyOf(top.subList(0, n)) : top;
    }

    /**
     * Walks the failures of one IP with a sliding window and merges every
     * overlapping run of threshold-or-more failures into one episode.
     */
    private List<BruteForce> findEpisodes(String ip, List<Instant> times) {
        List<BruteForce> episodes = new ArrayList<>();
        int left = 0;
        int episodeStart = -1;
        int episodeEnd = -1;
        for (int right = 0; right < times.size(); right++) {
            while (times.get(right).minus(window).isAfter(times.get(left))) {
                left++;
            }
            if (right - left + 1 < threshold) {
                continue;
            }
            if (episodeStart >= 0 && left <= episodeEnd) {
                episodeEnd = right;
            } else {
                if (episodeStart >= 0) {
                    episodes.add(toEpisode(ip, times, episodeStart, episodeEnd));
                }
                episodeStart = left;
                episodeEnd = right;
            }
        }
        if (episodeStart >= 0) {
            episodes.add(toEpisode(ip, times, episodeStart, episodeEnd));
        }
        return episodes;
    }

    private static BruteForce toEpisode(String ip, List<Instant> times, int start, int end) {
        return new BruteForce(ip, end - start + 1, times.get(start), times.get(end));
    }

    /** Failures from this IP in (time - window, time]. */
    private int recentFailures(String ip, Instant time) {
        List<Instant> times = failuresByIp.get(ip);
        if (times == null) {
            return 0;
        }
        Instant cutoff = time.minus(window);
        int count = 0;
        for (Instant t : times) {
            if (t.isAfter(cutoff) && !t.isAfter(time)) {
                count++;
            }
        }
        return count;
    }

    private static Map<String, List<Instant>> indexFailures(List<LogEntry> entries) {
        Map<String, List<Instant>> byIp = new HashMap<>();
        for (LogEntry entry : entries) {
            if (entry.ip() != null && isFailure(entry)) {
                byIp.computeIfAbsent(entry.ip(), key -> new ArrayList<>()).add(entry.time());
            }
        }
        return byIp;
    }

    private static boolean isFailure(LogEntry entry) {
        LogParser.EventType type = LogParser.classify(entry);
        return type == LogParser.EventType.FAILURE || type == LogParser.EventType.SUDO_FAILURE;
    }
}
