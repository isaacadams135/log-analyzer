package com.github.isaacadams135.loganalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDateTime;
import java.time.Year;
import java.time.ZoneId;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class LogParserTest {

    @Test
    void parsesSyslogStyleLine() {
        Optional<LogEntry> parsed = LogParser.parse(
                "Oct 12 10:22:33 web01 sshd[1234]: Failed password for root from 203.0.113.50 port 50012 ssh2");

        assertTrue(parsed.isPresent());
        LogEntry entry = parsed.get();
        assertEquals("web01", entry.host());
        assertEquals("203.0.113.50", entry.ip());
        assertTrue(entry.message().contains("Failed password for root"));
        var expected = LocalDateTime.of(Year.now().getValue(), 10, 12, 10, 22, 33)
                .atZone(ZoneId.systemDefault()).toInstant();
        assertEquals(expected, entry.time());
        assertEquals(LogParser.EventType.FAILURE, LogParser.classify(entry));
    }

    @Test
    void parsesIsoStyleLine() {
        Optional<LogEntry> parsed = LogParser.parse(
                "2026-10-12T10:22:33 web01 sshd[1234]: Accepted password for root from 203.0.113.50 port 50012 ssh2");

        assertTrue(parsed.isPresent());
        LogEntry entry = parsed.get();
        assertEquals("web01", entry.host());
        assertEquals("203.0.113.50", entry.ip());
        var expected = LocalDateTime.of(2026, 10, 12, 10, 22, 33)
                .atZone(ZoneId.systemDefault()).toInstant();
        assertEquals(expected, entry.time());
        assertEquals(LogParser.EventType.SUCCESS, LogParser.classify(entry));
        assertEquals("root", LogParser.successUser(entry));
    }

    @Test
    void unparseableLineGivesEmpty() {
        assertTrue(LogParser.parse("Disconnected from user root 203.0.113.50").isEmpty());
        assertTrue(LogParser.parse("").isEmpty());
        assertTrue(LogParser.parse("Oct 99 10:22:33 web01 sshd[1]: Failed password for root").isEmpty());
    }

    @Test
    void classifiesSudoFailureAndHasNoIp() {
        LogEntry sudo = LogParser.parse(
                "Oct 12 09:15:40 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=isaac uid=1000 euid=0 tty=/dev/pts/0 ruser=isaac rhost=  user=isaac")
                .orElseThrow();

        assertEquals(LogParser.EventType.SUDO_FAILURE, LogParser.classify(sudo));
        assertNull(sudo.ip());

        LogEntry failedSudo = LogParser.parse(
                "Oct 12 09:20:15 web01 sudo:     bob : FAILED sudo for /usr/bin/id from pts/2 ; AUTHENTICATION FAILURE")
                .orElseThrow();
        assertEquals(LogParser.EventType.SUDO_FAILURE, LogParser.classify(failedSudo));

        LogEntry invalid = LogParser.parse(
                "Oct 12 09:58:11 web01 sshd[2101]: Invalid user test from 192.0.2.66 port 44120")
                .orElseThrow();
        assertEquals(LogParser.EventType.INVALID_USER, LogParser.classify(invalid));
        assertEquals("192.0.2.66", invalid.ip());
    }
}
