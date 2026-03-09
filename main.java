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
    private final int outcome;
    private final int stepCount;
    private final List<byte[]> steps;

    BDIGIDiagnosticSession(byte[] sessionId, String reporterHex, int category, long openedAtMs,
                           boolean resolved, byte[] resolutionHash, int outcome, int stepCount, List<byte[]> steps) {
        this.sessionId = sessionId != null ? sessionId.clone() : new byte[0];
        this.reporterHex = reporterHex != null ? reporterHex : BDIGIConfig.BDIGI_ZERO;
        this.category = Math.max(1, Math.min(BDIGIConfig.BDIGI_CATEGORY_COUNT, category));
        this.openedAtMs = openedAtMs;
        this.resolved = resolved;
        this.resolutionHash = resolutionHash != null ? resolutionHash.clone() : new byte[0];
        this.outcome = outcome;
        this.stepCount = stepCount;
        this.steps = steps != null ? new ArrayList<>(steps) : new ArrayList<>();
    }

    public byte[] getSessionId() { return sessionId.clone(); }
    public String getReporterHex() { return reporterHex; }
    public int getCategory() { return category; }
    public long getOpenedAtMs() { return openedAtMs; }
    public boolean isResolved() { return resolved; }
    public byte[] getResolutionHash() { return resolutionHash.clone(); }
    public int getOutcome() { return outcome; }
    public int getStepCount() { return stepCount; }
    public List<byte[]> getSteps() { return new ArrayList<>(steps); }
}

// ─── BDIGI AI hint provider (suggested steps per category) ───────────────────

final class BDIGIHintProvider {
    private static final Map<Integer, List<String>> HINTS = new HashMap<>();

    static {
        HINTS.put(1, Arrays.asList(
            "Check physical cable/Wi‑Fi connection.",
            "Run network troubleshooter (Windows: Settings > Network).",
            "Flush DNS: ipconfig /flushdns (Windows) or sudo dscacheutil -flushcache (macOS).",
            "Restart router and modem.",
            "Verify IP configuration (DHCP vs static).",
            "Disable and re-enable the network adapter.",
            "Check firewall/antivirus for blocked traffic.",
            "Ping gateway and 8.8.8.8 to isolate path.",
            "Try another DNS (e.g. 1.1.1.1 or 8.8.4.4).",
            "Review proxy/VPN settings.",
            "Check for driver updates for the NIC.",
            "Confirm no MAC filtering or captive portal."
        ));
        HINTS.put(2, Arrays.asList(
            "Check free space (disk cleanup / Storage Sense).",
            "Run CHKDSK (Windows) or fsck (Linux/macOS).",
            "Verify drive health (SMART status).",
            "Defragment if HDD (not needed for SSD).",
            "Check for large temp/cache folders.",
            "Ensure drive is properly connected (SATA/USB).",
            "Review OneDrive/Dropbox sync and local cache.",
            "Check disk permissions.",
            "Disable hibernation to free space (powercfg -h off).",
            "Move user folders to another volume if needed.",
            "Check for runaway logs or dump files.",
            "Consider replacing drive if SMART errors."
        ));
        HINTS.put(3, Arrays.asList(
            "Restart the computer.",
            "Install pending Windows/macOS/Linux updates.",
            "Boot into Safe Mode to isolate driver/software.",
            "Check Task Manager for high CPU/memory usage.",
            "Run sfc /scannow (Windows) or diskutil verifyVolume (macOS).",
            "Review startup programs and disable unnecessary ones.",
            "Check Event Viewer / Console for errors.",
            "Restore to a previous restore point if available.",
            "Reset Windows (Keep my files) or reinstall as last resort.",
            "Verify system file integrity (DISM on Windows).",
            "Check for conflicting security software.",
            "Ensure BIOS/UEFI and drivers are up to date."
        ));
        HINTS.put(4, Arrays.asList(
            "Clear cache and cookies.",
            "Disable extensions one by one to find conflict.",
            "Try incognito/private window.",
            "Update browser to latest version.",
            "Reset browser settings to default.",
            "Check proxy and DNS settings in browser.",
            "Disable hardware acceleration.",
            "Try another browser to isolate issue.",
            "Remove and re-add profile.",
            "Check for conflicting VPN or firewall.",
            "Ensure JavaScript and cookies are allowed for the site.",
            "Review site permissions (camera, mic, location)."
        ));
        HINTS.put(5, Arrays.asList(
            "Update device driver from manufacturer or Windows Update.",
            "Uninstall device and scan for hardware changes.",
            "Roll back driver if issue started after update.",
            "Check Device Manager for yellow exclamation marks.",
            "Ensure USB/Thunderbolt controller drivers are current.",
            "Try another port or cable.",
            "Install manufacturer-specific utility (e.g. Logitech, Dell).",
            "Check for firmware update for the device.",
            "Disable USB selective suspend in power options.",
            "Verify device works on another machine.",
            "Remove duplicate or ghost devices in Device Manager.",
            "Check Group Policy for driver installation restrictions."
        ));
        HINTS.put(6, Arrays.asList(
            "Calibrate battery (full discharge then full charge).",
            "Check power plan (Balanced/High performance).",
            "Reduce screen brightness and close heavy apps.",
            "Disable unused USB devices and wake-on-LAN if not needed.",
            "Review Task Manager for background apps using CPU.",
            "Replace battery if health is low (manufacturer tool).",
            "Check power adapter and cable; try another if possible.",
            "Update BIOS for power management fixes.",
            "Disable fast startup (can cause wake/sleep issues).",
            "Check outlet and surge protector.",
            "Verify hibernation and sleep settings.",
            "Run power report: powercfg /batteryreport (Windows)."
        ));
        HINTS.put(7, Arrays.asList(
            "Check cable connections (HDMI/DisplayPort).",
            "Update graphics driver from GPU vendor (NVIDIA/AMD/Intel).",
            "Set correct resolution and refresh rate in display settings.",
            "Try another monitor or TV to isolate.",
            "Disable multiple display and re-enable.",
            "Roll back graphics driver if issue after update.",
            "Check for overheating (clean fans, repaste).",
            "Run display troubleshooter (Windows).",
            "Disable hardware acceleration in apps if artifacts.",
            "Verify monitor OSD settings (input source).",
            "Try different cable (e.g. HDMI 2.0 for 4K).",
            "Reset monitor to factory defaults."
        ));
        HINTS.put(8, Arrays.asList(
            "Check physical volume and mute buttons.",
            "Set correct output device (speakers/headphones).",
            "Run audio troubleshooter (Windows).",
            "Update or reinstall audio driver.",
            "Disable audio enhancements (Windows Sound properties).",
            "Verify default format (e.g. 24-bit 48000 Hz).",
            "Check app-specific volume (mixer).",
            "Unplug and replug USB/3.5mm device.",
            "Reset sound settings to default.",
            "Check for conflicting audio software.",
            "Verify HDMI/DisplayPort audio if using monitor speakers.",
            "Test with another device to isolate hardware."
        ));
    }

    static List<String> getHintsForCategory(int category) {
        List<String> list = HINTS.get(category);
        return list != null ? new ArrayList<>(list) : Collections.emptyList();
    }

    static String getFirstHint(int category) {
        List<String> list = HINTS.get(category);
        return (list != null && !list.isEmpty()) ? list.get(0) : "No hints for this category.";
    }
}

// ─── BDIGI Hash helper ──────────────────────────────────────────────────────

final class BDIGIHash {
    static byte[] sha256(byte[] input) {
        if (input == null) return new byte[0];
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    static byte[] sessionIdFrom(String reporterHex, int category, long nonce) {
        String payload = BDIGIConfig.BDIGI_NAMESPACE + ":" + reporterHex + ":" + category + ":" + nonce;
        return sha256(payload.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] stepHashFrom(byte[] sessionId, int stepIndex, String stepDescription) {
        String payload = new String(sessionId, StandardCharsets.ISO_8859_1) + ":" + stepIndex + ":" + (stepDescription != null ? stepDescription : "");
        return sha256(payload.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] resolutionHashFrom(byte[] sessionId, String resolutionSummary) {
        String payload = new String(sessionId, StandardCharsets.ISO_8859_1) + ":" + (resolutionSummary != null ? resolutionSummary : "");
        return sha256(payload.getBytes(StandardCharsets.UTF_8));
    }
}

// ─── BDIGI Engine (core logic) ──────────────────────────────────────────────

final class BDIGIEngine {
    private final Map<String, BDIGIDiagnosticSession> sessionsByKey = new ConcurrentHashMap<>();
    private final Map<String, List<byte[]>> stepsBySession = new ConcurrentHashMap<>();
    private final List<Object> eventLog = new CopyOnWriteArrayList<>();
    private final AtomicLong sessionCounter = new AtomicLong(0L);
    private final int[] categoryCounts = new int[BDIGIConfig.BDIGI_CATEGORY_COUNT + 1];
    private final long[] categoryCaps;
    private volatile boolean paused;
    private final String triageKeeperHex;
    private int reentrancyGuard;

    BDIGIEngine() {
        triageKeeperHex = BDIGIConfig.BDIGI_TRIAGE_KEEPER;
        categoryCaps = new long[BDIGIConfig.BDIGI_CATEGORY_COUNT + 1];
        for (int i = 1; i <= BDIGIConfig.BDIGI_CATEGORY_COUNT; i++) {
            categoryCaps[i] = BDIGIConfig.BDIGI_MAX_SESSIONS_PER_CATEGORY;
        }
    }

    private String sessionKey(byte[] sessionId) {
        return Base64.getEncoder().encodeToString(sessionId != null ? sessionId : new byte[0]);
    }

    public byte[] openSession(String reporterHex, int category) {
        if (paused) throw new BDIGIRegistryPausedException();
        if (reporterHex == null) reporterHex = BDIGIConfig.BDIGI_ZERO;
        if (category < 1 || category > BDIGIConfig.BDIGI_CATEGORY_COUNT) throw new BDIGIInvalidCategoryException();
        if (categoryCounts[category] >= categoryCaps[category]) throw new BDIGICategoryCapReachedException();
        if (reentrancyGuard != 0) throw new BDIGIReentrantException();
        reentrancyGuard = 1;
        try {
            long nonce = sessionCounter.incrementAndGet();
            byte[] sessionId = BDIGIHash.sessionIdFrom(reporterHex, category, nonce);
            String key = sessionKey(sessionId);
            if (sessionsByKey.containsKey(key)) throw new BDIGICategoryCapReachedException();
            long atMs = System.currentTimeMillis();
            BDIGIDiagnosticSession session = new BDIGIDiagnosticSession(
                sessionId, reporterHex, category, atMs,
                false, new byte[0], BDIGIConfig.BDIGI_OUTCOME_NONE, 0, new ArrayList<>());
            sessionsByKey.put(key, session);
            stepsBySession.put(key, new ArrayList<>());
            categoryCounts[category]++;
            eventLog.add(new BDIGISessionOpenedEvent(sessionId, reporterHex, category, atMs));
            return sessionId;
        } finally {
            reentrancyGuard = 0;
        }
    }

    public void recordStep(byte[] sessionId, int stepIndex, byte[] stepHash) {
        if (sessionId == null || stepHash == null || stepHash.length == 0) throw new BDIGIZeroHashException();
        if (stepIndex < 0 || stepIndex >= BDIGIConfig.BDIGI_MAX_STEPS_PER_SESSION) throw new BDIGIStepIndexOutOfRangeException();
        String key = sessionKey(sessionId);
        BDIGIDiagnosticSession session = sessionsByKey.get(key);
        if (session == null) throw new BDIGISessionNotFoundException();
        if (session.isResolved()) throw new BDIGISessionAlreadyResolvedException();
        List<byte[]> steps = stepsBySession.get(key);
        if (steps == null) steps = new ArrayList<>();
        while (steps.size() <= stepIndex) steps.add(new byte[0]);
        steps.set(stepIndex, stepHash.clone());
        stepsBySession.put(key, steps);
        eventLog.add(new BDIGIStepRecordedEvent(sessionId, stepIndex, stepHash, System.currentTimeMillis()));
    }

    public void attestResolution(byte[] sessionId, byte[] resolutionHash, int outcome, String triageKeeperCaller) {
        if (sessionId == null || resolutionHash == null || resolutionHash.length == 0) throw new BDIGIZeroHashException();
        if (outcome < 0 || outcome >= BDIGIConfig.BDIGI_OUTCOME_CAP) throw new BDIGIOutcomeOutOfRangeException();
        if (!triageKeeperHex.equalsIgnoreCase(triageKeeperCaller)) throw new BDIGINotTriageKeeperException();
        String key = sessionKey(sessionId);
        BDIGIDiagnosticSession session = sessionsByKey.get(key);
        if (session == null) throw new BDIGISessionNotFoundException();
        if (session.isResolved()) throw new BDIGISessionAlreadyResolvedException();
        List<byte[]> steps = stepsBySession.get(key);
        BDIGIDiagnosticSession updated = new BDIGIDiagnosticSession(
            session.getSessionId(), session.getReporterHex(), session.getCategory(), session.getOpenedAtMs(),
            true, resolutionHash, outcome, steps != null ? steps.size() : 0, steps != null ? steps : Collections.emptyList());
        sessionsByKey.put(key, updated);
        eventLog.add(new BDIGIResolutionAttestedEvent(sessionId, resolutionHash, outcome, System.currentTimeMillis()));
    }

    public void setCategoryCap(int category, long newCap) {
        if (category < 1 || category > BDIGIConfig.BDIGI_CATEGORY_COUNT) throw new BDIGIInvalidCategoryException();
        long prev = categoryCaps[category];
        categoryCaps[category] = Math.max(0, newCap);
        eventLog.add(new BDIGICategoryThresholdUpdatedEvent(category, prev, categoryCaps[category], System.currentTimeMillis()));
    }

    public void setPaused(boolean p) {
        paused = p;
    }

    public BDIGIDiagnosticSession getSession(byte[] sessionId) {
        String key = sessionKey(sessionId);
        return sessionsByKey.get(key);
    }

    public List<byte[]> getSteps(byte[] sessionId) {
        String key = sessionKey(sessionId);
        List<byte[]> steps = stepsBySession.get(key);
        return steps != null ? new ArrayList<>(steps) : Collections.emptyList();
    }

    public List<byte[]> listSessionIds() {
        return sessionsByKey.values().stream()
            .map(BDIGIDiagnosticSession::getSessionId)
            .collect(Collectors.toList());
    }

    public int getCategoryCount(int category) {
        if (category < 1 || category > BDIGIConfig.BDIGI_CATEGORY_COUNT) return 0;
        return categoryCounts[category];
    }

    public long getCategoryCap(int category) {
        if (category < 1 || category > BDIGIConfig.BDIGI_CATEGORY_COUNT) return 0;
        return categoryCaps[category];
    }

    public List<Object> getEventLog() {
        return new ArrayList<>(eventLog);
    }

    public List<byte[]> batchOpenSessions(String reporterHex, int[] categories) {
        if (categories == null || categories.length > BDIGIConfig.BDIGI_MAX_BATCH_OPEN) throw new BDIGIBatchTooLargeException();
        List<byte[]> out = new ArrayList<>();
        for (int cat : categories) {
            if (cat >= 1 && cat <= BDIGIConfig.BDIGI_CATEGORY_COUNT) {
                try {
                    byte[] sid = openSession(reporterHex, cat);
                    out.add(sid);
                } catch (BDIGICategoryCapReachedException e) {
                    // skip this category
                }
            }
        }
        return out;
    }
}

// ─── BDIGI Report builder ───────────────────────────────────────────────────

final class BDIGIReportBuilder {
    private final List<String> sections = new ArrayList<>();
    private final long createdAtMs = System.currentTimeMillis();

    BDIGIReportBuilder addSection(String title, String content) {
        if (title != null && content != null) {
            sections.add("## " + title + "\n" + content);
        }
        return this;
    }

    BDIGIReportBuilder addSessionSummary(BDIGIDiagnosticSession session) {
        if (session == null) return this;
        String catLabel = BDIGICategory.fromCode(session.getCategory()).getLabel();
        sections.add("## Session\nCategory: " + catLabel + ", Steps: " + session.getStepCount() + ", Resolved: " + session.isResolved());
        return this;
    }

    BDIGIReportBuilder addHints(int category) {
        List<String> hints = BDIGIHintProvider.getHintsForCategory(category);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hints.size(); i++) {
            sb.append((i + 1)).append(". ").append(hints.get(i)).append("\n");
        }
        sections.add("## Suggested steps\n" + sb.toString());
        return this;
    }

    String build() {
        StringBuilder out = new StringBuilder();
        out.append("# BetterDiagnosticsDIGI Report\n");
        out.append("Generated: ").append(new Date(createdAtMs)).append("\n\n");
        for (String s : sections) {
            out.append(s).append("\n\n");
        }
        return out.toString();
    }
}

// ─── BDIGI Validator ───────────────────────────────────────────────────────

final class BDIGIValidator {
    static boolean isValidCategory(int category) {
        return category >= 1 && category <= BDIGIConfig.BDIGI_CATEGORY_COUNT;
    }

    static boolean isValidOutcome(int outcome) {
        return outcome >= 0 && outcome < BDIGIConfig.BDIGI_OUTCOME_CAP;
    }

    static boolean isValidStepIndex(int stepIndex) {
        return stepIndex >= 0 && stepIndex < BDIGIConfig.BDIGI_MAX_STEPS_PER_SESSION;
    }

    static boolean isValidSessionId(byte[] sessionId) {
        return sessionId != null && sessionId.length == BDIGIConfig.BDIGI_SESSION_ID_BYTES;
    }

    static boolean isValidHash(byte[] hash) {
        return hash != null && hash.length >= BDIGIConfig.BDIGI_STEP_HASH_BYTES;
    }
}

// ─── BDIGI Extended hints (additional steps per category) ───────────────────

final class BDIGIExtendedHints {
    private static final Map<Integer, List<String>> EXTRA = new HashMap<>();

    static {
        EXTRA.put(1, Arrays.asList(
            "Verify no IP conflict with another device.",
            "Check router admin page for blocked clients.",
            "Test with Ethernet if on Wi‑Fi to rule out wireless issues.",
            "Review recent router firmware updates.",
            "Confirm ISP outage status.",
            "Try tethering to phone to test if PC stack is fine.",
            "Inspect network adapter power management (allow off = no).",
            "Check for duplicate IPv4 addresses.",
            "Validate subnet mask and default gateway.",
            "Run netsh winsock reset (Windows)."
        ));
        EXTRA.put(2, Arrays.asList(
            "Check Recycle Bin size and empty if needed.",
            "Use TreeSize or WinDirStat to find large folders.",
            "Verify SSD trim is enabled (Windows: fsutil behavior query DisableDeleteNotify).",
            "Check for Windows.old and remove via Disk Cleanup.",
            "Review cloud sync selective sync settings.",
            "Ensure no runaway download or temp folder.",
            "Check virtual memory / page file size.",
            "Consider moving user profile to another drive if system drive full.",
            "Verify external drive is not in read-only or failing.",
            "Run Storage Sense (Windows 10/11) to auto-clean."
        ));
        EXTRA.put(3, Arrays.asList(
            "Check Windows Update history for failed updates.",
            "Review reliability monitor (perfmon /rel).",
            "Temporarily disable antivirus to test.",
            "Check for corrupt user profile (new local user test).",
            "Verify system time and time zone.",
            "Run memory diagnostic (mdsched).",
            "Check for pending reboot (registry or wmic).",
            "Review application crash dumps in %LocalAppData%\\CrashDumps.",
            "Ensure no conflicting .NET versions.",
            "Check Windows activation status."
        ));
        EXTRA.put(4, Arrays.asList(
            "Test with a different user profile in the same browser.",
            "Check for browser updates in background.",
            "Verify no corporate proxy or SSL inspection breaking sites.",
            "Clear site data for the specific domain.",
            "Try disabling tracking protection for the site.",
            "Check if issue is only on one site or all sites.",
            "Review browser flags (chrome://flags) for experimental features.",
            "Ensure WebRTC or geolocation is not blocked if needed.",
            "Test with browser in no-sandbox mode for debugging.",
            "Check certificate errors (valid cert, correct date)."
        ));
        EXTRA.put(5, Arrays.asList(
            "Check Windows Update optional updates for drivers.",
            "Use manufacturer-provided driver (not generic).",
            "Verify device appears in BIOS/UEFI.",
            "Try USB 2.0 port if device is USB 3 and flaky.",
            "Check for power delivery (USB-C) if applicable.",
            "Review Windows compatibility for the device.",
            "Uninstall all instances of the device and reboot.",
            "Check for firmware update for the peripheral.",
            "Verify no conflict with another driver (e.g. two mouse drivers).",
            "Test on another OS (e.g. Linux live USB) to isolate."
        ));
        EXTRA.put(6, Arrays.asList(
            "Check powercfg /devicequery wake_armed for wake sources.",
            "Review high power usage in Battery report.",
            "Disable unnecessary startup programs.",
            "Set GPU to power-saving when on battery.",
            "Check for BIOS power management settings.",
            "Verify charger wattage meets laptop requirement.",
            "Test with battery removed (AC only) if possible.",
            "Calibrate battery if percentage is wrong.",
            "Check for thermal throttling (high temp = lower performance).",
            "Review OEM power manager (Dell Command, Lenovo Vantage, etc.)."
        ));
        EXTRA.put(7, Arrays.asList(
            "Check GPU temperature under load.",
            "Verify monitor supports the resolution/refresh requested.",
            "Try lowering resolution or refresh rate.",
            "Disable G-Sync/FreeSync to test for sync issues.",
            "Check for GPU driver timeout (TDR) in registry.",
            "Verify no loose connection at both ends.",
            "Try another video output on the GPU.",
            "Test with integrated graphics if available.",
            "Review HDR and color format settings.",
            "Check for firmware update for the monitor."
        ));
        EXTRA.put(8, Arrays.asList(
            "Set communications device to do nothing (Windows).",
            "Disable exclusive mode in Sound properties.",
            "Check for sample rate mismatch (e.g. 44.1 vs 48 kHz).",
            "Verify default device is correct in Sound settings.",
            "Test with built-in speakers vs external.",
            "Review spatial sound and enhancements.",
            "Check for duplicate playback devices.",
            "Ensure no app is holding exclusive access.",
            "Try WASAPI shared vs exclusive in supported apps.",
            "Verify no hardware mute or physical switch."
        ));
    }

    static List<String> getExtendedHints(int category) {
        List<String> list = EXTRA.get(category);
        return list != null ? new ArrayList<>(list) : Collections.emptyList();
    }
}

// ─── BDIGI Session timeout checker ──────────────────────────────────────────

final class BDIGISessionTimeoutChecker {
    private final BDIGIEngine engine;
    private final long timeoutMs;

    BDIGISessionTimeoutChecker(BDIGIEngine engine, long timeoutMs) {
        this.engine = engine;
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : BDIGIConfig.BDIGI_SESSION_TIMEOUT_MS;
    }

    List<byte[]> findStaleSessions() {
        long now = System.currentTimeMillis();
        List<byte[]> stale = new ArrayList<>();
        for (byte[] sid : engine.listSessionIds()) {
            BDIGIDiagnosticSession s = engine.getSession(sid);
            if (s != null && !s.isResolved() && (now - s.getOpenedAtMs() > timeoutMs)) {
                stale.add(sid);
            }
        }
        return stale;
    }
}

// ─── BDIGI Hex and encoding helpers ────────────────────────────────────────

final class BDIGIHex {
    static String toHex(byte[] bytes) {
        if (bytes == null) return "0x";
        StringBuilder sb = new StringBuilder("0x");
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    static byte[] fromHex(String hex) {
        if (hex == null) return new byte[0];
        String s = hex.startsWith("0x") ? hex.substring(2) : hex;
        if (s.length() % 2 != 0) s = "0" + s;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}

// ─── BDIGI Stats aggregator ───────────────────────────────────────────────

final class BDIGIStatsAggregator {
    private final BDIGIEngine engine;

    BDIGIStatsAggregator(BDIGIEngine engine) {
        this.engine = engine;
    }

    int totalSessions() {
        return engine.listSessionIds().size();
    }

    int resolvedCount() {
        int n = 0;
        for (byte[] sid : engine.listSessionIds()) {
            BDIGIDiagnosticSession s = engine.getSession(sid);
            if (s != null && s.isResolved()) n++;
        }
        return n;
    }

    Map<Integer, Integer> sessionsByCategory() {
        Map<Integer, Integer> m = new HashMap<>();
        for (int c = 1; c <= BDIGIConfig.BDIGI_CATEGORY_COUNT; c++) {
            m.put(c, engine.getCategoryCount(c));
        }
        return m;
    }

    String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Total sessions: ").append(totalSessions()).append("\n");
        sb.append("Resolved: ").append(resolvedCount()).append("\n");
        sb.append("By category:\n");
        for (Map.Entry<Integer, Integer> e : sessionsByCategory().entrySet()) {
            sb.append("  ").append(BDIGICategory.fromCode(e.getKey()).getLabel()).append(": ").append(e.getValue()).append("\n");
        }
        return sb.toString();
    }
}

// ─── BDIGI Step templates (predefined step descriptions for AI helper) ───────

final class BDIGIStepTemplates {
    private static final Map<Integer, List<String>> TEMPLATES = new HashMap<>();

    static {
        List<String> net = new ArrayList<>();
        for (int i = 0; i < 24; i++) {
            net.add("Network step " + (i + 1) + ": " + (i % 3 == 0 ? "Verify connectivity" : i % 3 == 1 ? "Check configuration" : "Test path"));
        }
        TEMPLATES.put(1, net);
        List<String> disk = new ArrayList<>();
        for (int i = 0; i < 24; i++) {
            disk.add("Disk step " + (i + 1) + ": " + (i % 2 == 0 ? "Check space or health" : "Run tool or cleanup"));
        }
        TEMPLATES.put(2, disk);
        List<String> os = new ArrayList<>();
        for (int i = 0; i < 28; i++) {
            os.add("OS step " + (i + 1) + ": " + (i % 4 == 0 ? "Update" : i % 4 == 1 ? "Restart" : i % 4 == 2 ? "Scan" : "Reset"));
        }
        TEMPLATES.put(3, os);
        List<String> browser = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            browser.add("Browser step " + (i + 1) + ": Clear cache, extension, or setting");
        }
        TEMPLATES.put(4, browser);
        List<String> driver = new ArrayList<>();
        for (int i = 0; i < 22; i++) {
            driver.add("Driver step " + (i + 1) + ": Update, rollback, or reinstall device");
        }
        TEMPLATES.put(5, driver);
        List<String> power = new ArrayList<>();
        for (int i = 0; i < 18; i++) {
            power.add("Power step " + (i + 1) + ": Calibrate, plan, or hardware check");
        }
        TEMPLATES.put(6, power);
        List<String> display = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            display.add("Display step " + (i + 1) + ": Cable, driver, or resolution");
        }
        TEMPLATES.put(7, display);
        List<String> audio = new ArrayList<>();
        for (int i = 0; i < 18; i++) {
            audio.add("Audio step " + (i + 1) + ": Output device or driver");
        }
        TEMPLATES.put(8, audio);
    }

    static List<String> getTemplates(int category) {
        List<String> list = TEMPLATES.get(category);
        return list != null ? new ArrayList<>(list) : Collections.emptyList();
    }

    static String getTemplate(int category, int index) {
        List<String> list = TEMPLATES.get(category);
        if (list == null || index < 0 || index >= list.size()) return "";
        return list.get(index);
    }
}

// ─── BDIGI Export (text report to string) ───────────────────────────────────

final class BDIGIExport {
    static String exportSessionToText(BDIGIDiagnosticSession session, BDIGIEngine engine) {
        if (session == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("Session ID: ").append(Base64.getEncoder().encodeToString(session.getSessionId())).append("\n");
        sb.append("Reporter: ").append(session.getReporterHex()).append("\n");
        sb.append("Category: ").append(session.getCategory()).append(" (").append(BDIGICategory.fromCode(session.getCategory()).getLabel()).append(")\n");
        sb.append("Opened: ").append(new Date(session.getOpenedAtMs())).append("\n");
        sb.append("Resolved: ").append(session.isResolved()).append("\n");
        sb.append("Outcome: ").append(BDIGIOutcome.fromCode(session.getOutcome())).append("\n");
        sb.append("Step count: ").append(session.getStepCount()).append("\n");
        if (engine != null) {
            List<byte[]> steps = engine.getSteps(session.getSessionId());
            for (int i = 0; i < steps.size(); i++) {
                sb.append("  Step ").append(i).append(": ").append(BDIGIHex.toHex(steps.get(i))).append("\n");
            }
        }
        return sb.toString();
    }

    static String exportAllSessionsSummary(BDIGIEngine engine) {
        BDIGIStatsAggregator agg = new BDIGIStatsAggregator(engine);
        return agg.summary();
    }
}

// ─── BDIGI Outcome statistics ───────────────────────────────────────────────

final class BDIGIOutcomeStats {
    private final BDIGIEngine engine;

    BDIGIOutcomeStats(BDIGIEngine engine) {
        this.engine = engine;
    }

    Map<Integer, Integer> countByOutcome() {
        Map<Integer, Integer> m = new HashMap<>();
        for (int o = 0; o < BDIGIConfig.BDIGI_OUTCOME_CAP; o++) m.put(o, 0);
        for (byte[] sid : engine.listSessionIds()) {
            BDIGIDiagnosticSession s = engine.getSession(sid);
            if (s != null && s.isResolved()) {
                int o = s.getOutcome();
                m.put(o, m.getOrDefault(o, 0) + 1);
            }
        }
        return m;
    }

    String outcomeSummary() {
        Map<Integer, Integer> m = countByOutcome();
        StringBuilder sb = new StringBuilder();
        sb.append("Resolved: ").append(m.getOrDefault(BDIGIConfig.BDIGI_OUTCOME_RESOLVED, 0)).append("\n");
        sb.append("Escalated: ").append(m.getOrDefault(BDIGIConfig.BDIGI_OUTCOME_ESCALATED, 0)).append("\n");
        sb.append("Deferred: ").append(m.getOrDefault(BDIGIConfig.BDIGI_OUTCOME_DEFERRED, 0)).append("\n");
        return sb.toString();
    }
}

// ─── BDIGI Diagnostic flow (AI-helper flow scripts per category) ───────────

final class BDIGIDiagnosticFlow {
    static List<String> getFlowForNetwork() {
        return Arrays.asList(
            "Start: User reports connectivity issue.",
            "Step 1: Confirm scope (one device vs all, one site vs all).",
            "Step 2: Check physical link (cable/Wi‑Fi icon).",
            "Step 3: Run ping to gateway.",
            "Step 4: Run ping to 8.8.8.8.",
            "Step 5: If gateway fails, check router and NIC.",
            "Step 6: If 8.8.8.8 fails, check DNS or WAN.",
            "Step 7: Flush DNS cache.",
            "Step 8: Try different DNS server.",
            "Step 9: Disable VPN/proxy temporarily.",
            "Step 10: Check firewall rules.",
            "Step 11: Restart network stack (netsh winsock reset).",
            "Step 12: Escalate to ISP or network admin if WAN issue."
        );
    }

    static List<String> getFlowForDisk() {
        return Arrays.asList(
            "Start: User reports disk full or errors.",
            "Step 1: Check free space (all volumes).",
            "Step 2: Run Disk Cleanup or Storage Sense.",
            "Step 3: Identify largest folders (TreeSize/WinDirStat).",
            "Step 4: Remove temp, cache, or old installers.",
            "Step 5: Empty Recycle Bin and clear downloads.",
            "Step 6: Check cloud sync local cache size.",
            "Step 7: Run CHKDSK if errors reported.",
            "Step 8: Check SMART status if available.",
            "Step 9: Consider moving user data to another drive.",
            "Step 10: Disable hibernation to free space if needed.",
            "Step 11: Remove Windows.old if present after upgrade.",
            "Step 12: Escalate to backup/replace if hardware failure."
        );
    }

    static List<String> getFlowForOS() {
        return Arrays.asList(
            "Start: User reports OS slowness, crash, or error.",
            "Step 1: Restart the computer.",
            "Step 2: Check Task Manager for high CPU/memory.",
            "Step 3: Review startup programs and disable unnecessary.",
            "Step 4: Install pending Windows/macOS updates.",
            "Step 5: Run sfc /scannow (Windows) or diskutil verifyVolume (macOS).",
            "Step 6: Check Event Viewer or Console for errors.",
            "Step 7: Boot Safe Mode to isolate driver/software.",
            "Step 8: Restore to previous restore point if available.",
            "Step 9: Run memory diagnostic.",
            "Step 10: Disable antivirus temporarily to test.",
            "Step 11: Create new user profile to test corruption.",
            "Step 12: Consider reset (keep files) or reinstall as last resort."
        );
    }

    static List<String> getFlowForBrowser() {
        return Arrays.asList(
            "Start: User reports browser not loading or error.",
            "Step 1: Try incognito/private window.",
            "Step 2: Clear cache and cookies for the site.",
            "Step 3: Disable extensions one by one.",
            "Step 4: Update browser to latest version.",
            "Step 5: Check proxy and DNS in browser settings.",
            "Step 6: Try another browser to isolate.",
            "Step 7: Disable hardware acceleration.",
            "Step 8: Reset browser settings to default.",
            "Step 9: Check VPN or corporate proxy.",
            "Step 10: Verify certificate and date/time.",
            "Step 11: Test on another network.",
            "Step 12: Reinstall browser if profile corrupt."
        );
    }

    static List<String> getFlowForDriver() {
        return Arrays.asList(
            "Start: User reports device not working.",
            "Step 1: Check Device Manager for warnings.",
            "Step 2: Uninstall device and scan for hardware changes.",
            "Step 3: Install driver from Windows Update.",
            "Step 4: Install driver from manufacturer site.",
            "Step 5: Roll back driver if issue after update.",
            "Step 6: Try another USB/port or cable.",
            "Step 7: Update chipset/USB controller drivers.",
            "Step 8: Disable USB selective suspend.",
            "Step 9: Check firmware update for device.",
            "Step 10: Test on another computer.",
            "Step 11: Remove duplicate entries in Device Manager.",
            "Step 12: Escalate to hardware replacement if failed."
        );
    }

    static List<String> getFlowForPower() {
        return Arrays.asList(
            "Start: User reports battery or power issue.",
            "Step 1: Check power plan and brightness.",
            "Step 2: Review Task Manager for background usage.",
            "Step 3: Run powercfg /batteryreport.",
            "Step 4: Calibrate battery (full cycle).",
            "Step 5: Update BIOS for power management.",
            "Step 6: Disable wake-on-LAN and USB wake.",
            "Step 7: Check charger and cable.",
            "Step 8: Verify adapter wattage meets spec.",
            "Step 9: Disable fast startup if sleep issues.",
            "Step 10: Check thermal throttling.",
            "Step 11: Replace battery if health very low.",
            "Step 12: Escalate to OEM if hardware fault."
        );
    }

    static List<String> getFlowForDisplay() {
        return Arrays.asList(
            "Start: User reports display or graphics issue.",
            "Step 1: Check cable and connections.",
            "Step 2: Set correct resolution and refresh rate.",
            "Step 3: Update graphics driver from vendor.",
            "Step 4: Roll back driver if issue after update.",
            "Step 5: Try another monitor or TV.",
            "Step 6: Disable multi-monitor and re-enable.",
            "Step 7: Run display troubleshooter.",
            "Step 8: Disable hardware acceleration in app.",
            "Step 9: Check GPU temperature.",
