/*
 * BetterDiagnosticsDIGI — Diagnostic tool for every tech issue in day-to-day computing.
 * AI-helper style: categories, steps, resolution outcomes. Single-file build.
 */

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

// ─── BDIGI Config (final constants; randomized ranges) ─────────────────────

final class BDIGIConfig {
    static final int BDIGI_MAX_STEPS_PER_SESSION = 87;
    static final int BDIGI_MAX_SESSIONS_PER_CATEGORY = 4127;
    static final int BDIGI_CATEGORY_COUNT = 8;
    static final int BDIGI_MAX_BATCH_OPEN = 19;
    static final int BDIGI_OUTCOME_NONE = 0;
    static final int BDIGI_OUTCOME_RESOLVED = 1;
    static final int BDIGI_OUTCOME_ESCALATED = 2;
    static final int BDIGI_OUTCOME_DEFERRED = 3;
    static final int BDIGI_OUTCOME_CAP = 4;
    static final int BDIGI_VERSION = 2;
    static final long BDIGI_DOMAIN_SALT = 0x7f2e9a1b4c8d0e3aL;
    static final int BDIGI_DEFAULT_CATEGORY = 1;
    static final int BDIGI_SESSION_ID_BYTES = 32;
    static final int BDIGI_STEP_HASH_BYTES = 32;
    static final String BDIGI_NAMESPACE = "BetterDiagnosticsDIGI.v2";
    static final String BDIGI_TRIAGE_KEEPER = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb";
    static final String BDIGI_ZERO = "0x0000000000000000000000000000000000000000";
    static final int BDIGI_SUGGESTED_STEPS_INITIAL = 12;
    static final int BDIGI_MAX_HINT_LENGTH = 512;
    static final long BDIGI_SESSION_TIMEOUT_MS = 86400_000L;
    static final int BDIGI_RESOLUTION_HASH_BYTES = 32;

    private BDIGIConfig() {}
}

// ─── BDIGI Exceptions (unique names) ───────────────────────────────────────

final class BDIGINotTriageKeeperException extends RuntimeException {
    BDIGINotTriageKeeperException() { super("BDIGI: triage keeper only"); }
}
final class BDIGISessionNotFoundException extends RuntimeException {
    BDIGISessionNotFoundException() { super("BDIGI: session not found"); }
}
final class BDIGISessionAlreadyResolvedException extends RuntimeException {
    BDIGISessionAlreadyResolvedException() { super("BDIGI: session already resolved"); }
}
final class BDIGICategoryCapReachedException extends RuntimeException {
    BDIGICategoryCapReachedException() { super("BDIGI: category cap reached"); }
}
final class BDIGIStepIndexOutOfRangeException extends RuntimeException {
    BDIGIStepIndexOutOfRangeException() { super("BDIGI: step index out of range"); }
}
final class BDIGIZeroHashException extends RuntimeException {
    BDIGIZeroHashException() { super("BDIGI: zero hash"); }
}
final class BDIGIOutcomeOutOfRangeException extends RuntimeException {
    BDIGIOutcomeOutOfRangeException() { super("BDIGI: outcome out of range"); }
}
final class BDIGIBatchTooLargeException extends RuntimeException {
    BDIGIBatchTooLargeException() { super("BDIGI: batch too large"); }
}
final class BDIGIInvalidCategoryException extends RuntimeException {
    BDIGIInvalidCategoryException() { super("BDIGI: invalid category"); }
}
final class BDIGIRegistryPausedException extends RuntimeException {
    BDIGIRegistryPausedException() { super("BDIGI: registry paused"); }
}
final class BDIGIReentrantException extends RuntimeException {
    BDIGIReentrantException() { super("BDIGI: reentrant"); }
}

// ─── BDIGI Event payloads ───────────────────────────────────────────────────

final class BDIGISessionOpenedEvent {
    final byte[] sessionId;
    final String reporterHex;
    final int category;
    final long atMs;

    BDIGISessionOpenedEvent(byte[] sessionId, String reporterHex, int category, long atMs) {
        this.sessionId = sessionId != null ? sessionId.clone() : new byte[0];
        this.reporterHex = reporterHex != null ? reporterHex : BDIGIConfig.BDIGI_ZERO;
        this.category = category;
        this.atMs = atMs;
    }
}

final class BDIGIStepRecordedEvent {
    final byte[] sessionId;
    final int stepIndex;
    final byte[] stepHash;
    final long atMs;

    BDIGIStepRecordedEvent(byte[] sessionId, int stepIndex, byte[] stepHash, long atMs) {
        this.sessionId = sessionId != null ? sessionId.clone() : new byte[0];
        this.stepIndex = stepIndex;
        this.stepHash = stepHash != null ? stepHash.clone() : new byte[0];
        this.atMs = atMs;
    }
}

final class BDIGIResolutionAttestedEvent {
    final byte[] sessionId;
    final byte[] resolutionHash;
    final int outcome;
    final long atMs;

    BDIGIResolutionAttestedEvent(byte[] sessionId, byte[] resolutionHash, int outcome, long atMs) {
        this.sessionId = sessionId != null ? sessionId.clone() : new byte[0];
        this.resolutionHash = resolutionHash != null ? resolutionHash.clone() : new byte[0];
        this.outcome = outcome;
        this.atMs = atMs;
    }
}

final class BDIGICategoryThresholdUpdatedEvent {
    final int category;
    final long previousCap;
    final long newCap;
    final long atMs;

    BDIGICategoryThresholdUpdatedEvent(int category, long previousCap, long newCap, long atMs) {
        this.category = category;
        this.previousCap = previousCap;
        this.newCap = newCap;
        this.atMs = atMs;
    }
}

// ─── BDIGI Enums ───────────────────────────────────────────────────────────

enum BDIGICategory {
    NETWORK(1, "Network & connectivity"),
    DISK(2, "Storage & disk"),
    OS(3, "Operating system"),
    BROWSER(4, "Browser & web"),
    DRIVER(5, "Drivers & peripherals"),
    POWER(6, "Power & battery"),
    DISPLAY(7, "Display & graphics"),
    AUDIO(8, "Audio & sound");

    private final int code;
    private final String label;
    BDIGICategory(int code, String label) {
        this.code = code;
        this.label = label;
    }
    public int getCode() { return code; }
    public String getLabel() { return label; }
    public static BDIGICategory fromCode(int c) {
        for (BDIGICategory cat : values()) if (cat.code == c) return cat;
        return NETWORK;
    }
}

enum BDIGIOutcome {
    NONE(0),
    RESOLVED(1),
    ESCALATED(2),
    DEFERRED(3);

    private final int code;
    BDIGIOutcome(int code) { this.code = code; }
    public int getCode() { return code; }
    public static BDIGIOutcome fromCode(int c) {
        for (BDIGIOutcome o : values()) if (o.code == c) return o;
        return NONE;
    }
}

// ─── BDIGI State DTOs ───────────────────────────────────────────────────────

final class BDIGIDiagnosticSession {
    private final byte[] sessionId;
    private final String reporterHex;
    private final int category;
    private final long openedAtMs;
    private final boolean resolved;
    private final byte[] resolutionHash;
