package com.github.isaacadams135.loganalyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class Main {

    private static final String USAGE = """
        usage: log-analyzer [options] <logfile...>

        options:
          -w <minutes>   sliding time window in minutes (default: 10)
          -n <count>     failures from one IP needed to flag brute force (default: 5)
          -h, --help     show this help
        """;

    private Main() {
    }

    public static void main(String[] args) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println(USAGE);
            System.exit(2);
            return;
        }

        if (opts.help()) {
            System.out.println(USAGE);
            return;
        }

        List<LogEntry> entries = new ArrayList<>();
        int skipped = 0;
        for (Path file : opts.files()) {
            if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
                System.err.println("error: cannot read " + file);
                System.exit(1);
                return;
            }
            try (BufferedReader reader = Files.newBufferedReader(file)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    Optional<LogEntry> parsed = LogParser.parse(line);
                    if (parsed.isPresent()) {
                        entries.add(parsed.get());
                    } else {
                        skipped++;
                    }
                }
            } catch (IOException e) {
                System.err.println("error: could not read " + file + ": " + e.getMessage());
                System.exit(1);
                return;
            }
        }

        LogAnalyzer analyzer = new LogAnalyzer(entries, opts.windowMinutes(), opts.threshold());
        printReport(opts.files(), entries.size(), skipped, analyzer);
    }

    private static void printReport(List<Path> files, int parsed, int skipped, LogAnalyzer analyzer) {
        LogAnalyzer.Totals totals = analyzer.totals();

        System.out.printf("files   %s%n", String.join(", ", files.stream().map(Path::toString).toList()));
        System.out.printf("lines   %d parsed, %d skipped%n", parsed, skipped);
        System.out.printf("events  %d failures, %d invalid-user, %d successes, %d sudo failures, %d other%n",
                totals.failures(), totals.invalidUsers(), totals.successes(), totals.sudoFailures(), totals.other());

        System.out.println();
        System.out.println("brute force");
        List<LogAnalyzer.BruteForce> brute = analyzer.bruteForce();
        if (brute.isEmpty()) {
            System.out.println("  none");
        } else {
            for (LogAnalyzer.BruteForce b : brute) {
                System.out.printf("  %-15s %2d failures  %s -> %s%n",
                        b.ip(), b.count(), format(b.first()), format(b.last()));
            }
        }

        System.out.println();
        System.out.println("suspicious logins");
        List<LogAnalyzer.SuspiciousLogin> suspicious = analyzer.suspiciousLogins();
        if (suspicious.isEmpty()) {
            System.out.println("  none");
        } else {
            for (LogAnalyzer.SuspiciousLogin s : suspicious) {
                System.out.printf("  %-15s user %-10s %s%n", s.ip(), s.user(), format(s.time()));
            }
        }

        System.out.println();
        System.out.println("top offending ips");
        List<LogAnalyzer.TopIp> top = analyzer.topIps(5);
        if (top.isEmpty()) {
            System.out.println("  none");
        } else {
            System.out.printf("  %-15s %s%n", "ip", "failures");
            for (LogAnalyzer.TopIp t : top) {
                System.out.printf("  %-15s %d%n", t.ip(), t.failures());
            }
        }
    }

    private static String format(Instant time) {
        return LocalDateTime.ofInstant(time, ZoneId.systemDefault()).toString();
    }

    record Options(int windowMinutes, int threshold, List<Path> files, boolean help) {

        static Options parse(String[] args) {
            int windowMinutes = 10;
            int threshold = 5;
            boolean help = false;
            List<Path> files = new ArrayList<>();

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> help = true;
                    case "-w" -> windowMinutes = Integer.parseInt(nextValue(args, ++i, arg));
                    case "-n" -> threshold = Integer.parseInt(nextValue(args, ++i, arg));
                    default -> {
                        if (arg.startsWith("-")) {
                            throw new IllegalArgumentException("unknown option: " + arg);
                        }
                        files.add(Path.of(arg));
                    }
                }
            }

            if (help) {
                return new Options(0, 0, List.of(), true);
            }
            if (files.isEmpty()) {
                throw new IllegalArgumentException("missing log file");
            }
            if (windowMinutes < 1) {
                throw new IllegalArgumentException("window must be at least 1 minute");
            }
            if (threshold < 1) {
                throw new IllegalArgumentException("threshold must be at least 1");
            }
            return new Options(windowMinutes, threshold, List.copyOf(files), false);
        }

        private static String nextValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException(option + " needs a value");
            }
            return args[index];
        }
    }
}
