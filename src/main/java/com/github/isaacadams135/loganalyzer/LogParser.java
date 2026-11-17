package com.github.isaacadams135.loganalyzer;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Month;
import java.time.ZoneId;
import java.time.Year;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Turns a single log line into a LogEntry and classifies the event type.
 * Understands syslog ("Oct 12 10:22:33 host ...") and ISO ("2026-10-12T10:22:33 host ...")
 * prefixes; anything else comes back empty and is counted as skipped.
 */
public final class LogParser {

    public enum EventType { FAILURE, INVALID_USER, SUCCESS, SUDO_FAILURE, OTHER }

    private static final Pattern SYSLOG_LINE = Pattern.compile(
            "^([A-Z][a-z]{2})\\s+(\\d{1,2})\\s+(\\d{2}):(\\d{2}):(\\d{2})\\s+(\\S+)\\s+(.+)$");
    private static final Pattern ISO_LINE = Pattern.compile(
            "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})\\s+(\\S+)\\s+(.+)$");
    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b");
    private static final Pattern SUCCESS_USER =
            Pattern.compile("Accepted\\s+(?:password|publickey)\\s+for\\s+(\\S+)\\s+from");

    private LogParser() {
    }

    public static Optional<LogEntry> parse(String line) {
        Matcher iso = ISO_LINE.matcher(line);
        if (iso.matches()) {
            LocalDateTime time = LocalDateTime.of(
                    Integer.parseInt(iso.group(1)),
                    Integer.parseInt(iso.group(2)),
                    Integer.parseInt(iso.group(3)),
                    Integer.parseInt(iso.group(4)),
                    Integer.parseInt(iso.group(5)),
                    Integer.parseInt(iso.group(6)));
            String message = iso.group(8);
            return Optional.of(new LogEntry(toInstant(time), iso.group(7), message, extractIp(message)));
        }

        Matcher syslog = SYSLOG_LINE.matcher(line);
        if (syslog.matches()) {
            try {
                // syslog lines carry no year; assume the current one
                Month month = parseMonth(syslog.group(1));
                LocalDate date = LocalDate.of(Year.now().getValue(), month, Integer.parseInt(syslog.group(2)));
                LocalTime time = LocalTime.of(
                        Integer.parseInt(syslog.group(3)),
                        Integer.parseInt(syslog.group(4)),
                        Integer.parseInt(syslog.group(5)));
                String message = syslog.group(7);
                return Optional.of(new LogEntry(toInstant(LocalDateTime.of(date, time)), syslog.group(6), message, extractIp(message)));
            } catch (RuntimeException e) {
                return Optional.empty(); // matches the syslog shape but not a real date
            }
        }

        return Optional.empty();
    }

    public static EventType classify(LogEntry entry) {
        String msg = entry.message().toLowerCase(Locale.ROOT);
        if (msg.contains("invalid user")) {
            return EventType.INVALID_USER;
        }
        if (msg.contains("accepted password") || msg.contains("accepted publickey")) {
            return EventType.SUCCESS;
        }
        // check sudo before the generic auth-failure pattern, pam_unix lines mention both
        if (msg.contains("failed sudo for") || (msg.contains("sudo") && msg.contains("authentication failure"))) {
            return EventType.SUDO_FAILURE;
        }
        if (msg.contains("failed password") || msg.contains("authentication failure")) {
            return EventType.FAILURE;
        }
        return EventType.OTHER;
    }

    /** The username from a successful login message, or "" if there is none. */
    public static String successUser(LogEntry entry) {
        Matcher m = SUCCESS_USER.matcher(entry.message());
        return m.find() ? m.group(1) : "";
    }

    private static Month parseMonth(String abbreviation) {
        for (Month month : Month.values()) {
            if (month.name().regionMatches(true, 0, abbreviation, 0, 3)) {
                return month;
            }
        }
        throw new IllegalArgumentException("bad month: " + abbreviation);
    }

    private static String extractIp(String message) {
        Matcher m = IPV4.matcher(message);
        while (m.find()) {
            String candidate = m.group(1);
            if (isRealIp(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean isRealIp(String ip) {
        for (String octet : ip.split("\\.")) {
            if (Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    private static Instant toInstant(LocalDateTime time) {
        // no zone in the log lines, so treat them as local time
        return time.atZone(ZoneId.systemDefault()).toInstant();
    }
}
