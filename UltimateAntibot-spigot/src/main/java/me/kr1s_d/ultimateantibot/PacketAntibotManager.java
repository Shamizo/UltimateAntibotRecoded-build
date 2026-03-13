package me.kr1s_d.ultimateantibot;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

import org.bukkit.plugin.java.JavaPlugin;

import io.papermc.paper.threadedregions.scheduler.AsyncScheduler;
import io.papermc.paper.threadedregions.scheduler.ScheduledTask;
import me.kr1s_d.ultimateantibot.common.utils.BoundedRingBuffer;
import me.kr1s_d.ultimateantibot.utils.BotFingerprintAnalyzer;

public class PacketAntibotManager {

    private final JavaPlugin plugin;
    private final ConnectionController controller;

    private final Map<String, Long> ipConnectionHistory = new ConcurrentHashMap<>();
    private final Map<String, Long> handshakeTimestamps = new ConcurrentHashMap<>();
    private final Map<String, VerificationData> pendingVerification = new ConcurrentHashMap<>();
    private final Map<String, List<String>> recentUsernamesBySubnet = new ConcurrentHashMap<>();

    private final BoundedRingBuffer recentHandshakes = new BoundedRingBuffer(1000);
    private final AtomicBoolean aggressiveMode = new AtomicBoolean(false);
    private volatile long lastAggressiveCheck = 0L;
    private final BotFingerprintAnalyzer fingerprintAnalyzer = new BotFingerprintAnalyzer();

    private static final long BASE_CONNECTION_THROTTLE_MS = 2000L;
    private static final long BASE_SLOW_BOT_THRESHOLD_MS = 3000L;
    private static final int GLOBAL_RATE_THRESHOLD_PER_5S = 500;

    private static final long CLEANUP_TIMER_TICKS = 20L * 10;
    private static final long KEEPALIVE_SEND_TICKS = 40L;
    private static final long VERIFICATION_SWEEP_TICKS = 600L;

    // Folia 调度器
    private final AsyncScheduler asyncScheduler;

    public PacketAntibotManager(JavaPlugin plugin, ConnectionController controller) {
        this.plugin = plugin;
        this.controller = controller;
        this.asyncScheduler = plugin.getServer().getAsyncScheduler();

        // F
        asyncScheduler.runAtFixedRate(plugin, task -> cleanupAndEvaluate(),
                CLEANUP_TIMER_TICKS * 50, CLEANUP_TIMER_TICKS * 50, TimeUnit.MILLISECONDS);

        asyncScheduler.runAtFixedRate(plugin, task -> sendKeepalivesToPending(),
                20 * 50, KEEPALIVE_SEND_TICKS * 50, TimeUnit.MILLISECONDS);

        asyncScheduler.runAtFixedRate(plugin, task -> finalVerificationSweep(),
                VERIFICATION_SWEEP_TICKS * 50, VERIFICATION_SWEEP_TICKS * 50, TimeUnit.MILLISECONDS);
    }

    private void cleanupAndEvaluate() {
        long now = System.currentTimeMillis();
        ipConnectionHistory.entrySet().removeIf(e -> now - e.getValue() > 30_000L);
        handshakeTimestamps.entrySet().removeIf(e -> now - e.getValue() > 30_000L);
        pendingVerification.entrySet().removeIf(e -> now - e.getValue().createdAt > 60_000L);
        recentUsernamesBySubnet.entrySet().removeIf(e -> e.getValue().isEmpty());

        recentHandshakes.removeOlderThan(now - 5_000L);
        
        if (now - lastAggressiveCheck > 1000L) {
            boolean shouldAggressive = recentHandshakes.size() > GLOBAL_RATE_THRESHOLD_PER_5S;
            if (shouldAggressive != aggressiveMode.get()) {
                aggressiveMode.set(shouldAggressive);
                plugin.getLogger().log(Level.INFO, "PacketAntibotManager: aggressiveMode={0} (recentHandshakes={1})", new Object[]{shouldAggressive, recentHandshakes.size()});
            }
            lastAggressiveCheck = now;
        }
        
        fingerprintAnalyzer.cleanupSubnetData(now - 30_000L);
    }

    public void notifyPacketSeen(String connId) {
        long now = System.currentTimeMillis();
        recentHandshakes.add(now);
    }

    public void notifyHandshake(String connId, InetSocketAddress address) {
        String ip = address == null ? "unknown" : address.getAddress().getHostAddress();
        long now = System.currentTimeMillis();
        handleHandshake(connId, ip, now);
    }

    public void notifyLoginStart(String connId, String username) {
        long now = System.currentTimeMillis();
        handleLoginStart(connId, username, now);
    }

    public void notifyClientSettings(String connId) {
        handleSettings(connId);
    }

    public void notifyPluginMessage(String connId, String channel) {
        handlePluginMessage(connId, channel);
    }

    public void notifyClientKeepAlive(String connId) {
        handleKeepAlive(connId);
    }

    private void handleHandshake(String connId, String ip, long now) {
        long throttle = aggressiveMode.get() ? 800L : BASE_CONNECTION_THROTTLE_MS;
        Long last = ipConnectionHistory.get(ip);
        if (last != null && now - last < throttle) {
                pendingVerification.putIfAbsent(connId, new VerificationData());
                
                // 👇 替换为 Folia 异步延迟
                asyncScheduler.runDelayed(plugin, task -> {
                    try { Thread.sleep(250); } catch (InterruptedException ignored) {}
                    Long h = handshakeTimestamps.get(connId);
                    VerificationData d = pendingVerification.get(connId);
                    boolean handshakePassed = d != null && d.handshakePassed;
                    if ((h == null || !handshakePassed) && !aggressiveMode.get()) {
                        plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection after delayed throttle check conn={0} ip={1}", new Object[]{connId, ip});
                        try { controller.closeConnection(connId); } catch (Throwable ignored) {}
                        pendingVerification.remove(connId);
                    }
                }, 250, TimeUnit.MILLISECONDS);
                
                return;
            }
        ipConnectionHistory.put(ip, now);
        handshakeTimestamps.put(connId, now);
        VerificationData data = new VerificationData();
        
        double subnetScore = fingerprintAnalyzer.analyzeSubnetBurst(ip, now);
        if (subnetScore > 0.85) {
            data.botScores.subnetBurstScore = subnetScore;
        }
        
        pendingVerification.put(connId, data);
    }

    private void handleLoginStart(String connId, String username, long now) {
        Long handshake = handshakeTimestamps.get(connId);
        if (handshake == null) {
            // 👇 替换为 Folia 异步延迟
            asyncScheduler.runDelayed(plugin, task -> {
                try { Thread.sleep(250); } catch (InterruptedException ignored) {}
                Long h = handshakeTimestamps.get(connId);
                if (h == null && !aggressiveMode.get()) {
                    plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (missing-handshake after delay) conn={0}", new Object[]{connId});
                    try { controller.closeConnection(connId); } catch (Throwable ignored) {}
                }
            }, 250, TimeUnit.MILLISECONDS);
            
            return;
        }
        long delta = now - handshake;
        
        VerificationData data = pendingVerification.computeIfAbsent(connId, k -> new VerificationData());
        double timingScore = fingerprintAnalyzer.analyzeHandshakeToLoginTiming(delta);
        if (timingScore > 0.9 && !aggressiveMode.get()) {
            plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (bot-timing-fingerprint) conn={0} delta={1}ms score={2}", new Object[]{connId, delta, timingScore});
            try { controller.closeConnection(connId); } catch (Throwable ignored) {}
            pendingVerification.remove(connId);
            return;
        }
        data.botScores.handshakeTimingScore = timingScore;
        data.handshakeTime = handshake;
        data.loginTime = now;
        
        long slowThreshold = aggressiveMode.get() ? BASE_SLOW_BOT_THRESHOLD_MS * 2 : BASE_SLOW_BOT_THRESHOLD_MS;
        if (delta > slowThreshold) {
            if (!aggressiveMode.get()) {
                plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (slow-handshake) conn={0} delta={1}", new Object[]{connId, delta});
                try { controller.closeConnection(connId); } catch (Throwable ignored) {}
            } else {
                data.markedSlow = true;
            }
            return;
        }

        String name = username;
        if (name == null || !name.matches("[a-zA-Z0-9_]{3,16}")) {
            plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (invalid-username) conn={0} name={1}", new Object[]{connId, name});
            try { controller.closeConnection(connId); } catch (Throwable ignored) {}
            return;
        }
        
        data.username = name;
        InetSocketAddress addr = controller.getAddress(connId);
        if (addr != null) {
            String ip = addr.getAddress().getHostAddress();
            String subnet = extractSubnet(ip);
            if (subnet != null) {
                List<String> subnetUsernames = recentUsernamesBySubnet.computeIfAbsent(subnet, k -> new ArrayList<>());
                synchronized (subnetUsernames) {
                    subnetUsernames.add(name);
                    if (subnetUsernames.size() > 20) {
                        subnetUsernames.remove(0);
                    }
                    
                    if (subnetUsernames.size() >= 5) {
                        double usernameScore = fingerprintAnalyzer.analyzeUsernamePattern(name, subnetUsernames);
                        data.botScores.usernamePatternScore = usernameScore;
                        if (usernameScore > 0.9 && !aggressiveMode.get()) {
                            plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (bot-username-pattern) conn={0} name={1} score={2}", new Object[]{connId, name, usernameScore});
                            try { controller.closeConnection(connId); } catch (Throwable ignored) {}
                            pendingVerification.remove(connId);
                            return;
                        }
                    }
                }
            }
        }

        data.handshakePassed = true;
        data.lastActivity = now;
    }

    private void handleSettings(String connId) {
        VerificationData data = pendingVerification.get(connId);
        if (data != null) {
            long now = System.currentTimeMillis();
            data.hasSentSettings = true;
            data.lastActivity = now;
            data.settingsTime = now;
            if (data.loginTime > 0) {
                long delta = now - data.loginTime;
                double timingScore = fingerprintAnalyzer.analyzeLoginToSettingsTiming(delta);
                data.botScores.loginTimingScore = timingScore;
            }
        }
    }

    private void handlePluginMessage(String connId, String channel) {
        VerificationData data = pendingVerification.get(connId);
        if (data == null) return;
        if (channel.equalsIgnoreCase("minecraft:brand") || channel.equalsIgnoreCase("MC|Brand")) {
            data.hasSentPluginMessage = true;
            data.lastActivity = System.currentTimeMillis();
        }
    }

    private void handleKeepAlive(String connId) {
        VerificationData data = pendingVerification.get(connId);
        if (data == null) return;
        long now = System.currentTimeMillis();
        long sentAt = data.lastKeepAliveSentAt;
        if (sentAt > 0) {
            long interval = now - sentAt;
            synchronized (data.keepAliveSamples) {
                if (data.keepAliveSamples.size() >= 5) data.keepAliveSamples.remove(0);
                data.keepAliveSamples.add(interval);
            }
            data.lastActivity = now;
        }
    }

    public void notifyDisconnect(String connId) {
        if (connId == null) return;
        handshakeTimestamps.remove(connId);
        pendingVerification.remove(connId);
    }

    private void sendKeepalivesToPending() {
        if (pendingVerification.isEmpty()) return;
        int sends = 0;
        for (Map.Entry<String, VerificationData> e : pendingVerification.entrySet()) {
            if (sends >= 1000) break;
            String connId = e.getKey();
            VerificationData data = e.getValue();
            if (data.verified) continue;
            if (!data.handshakePassed) continue;
            if (System.currentTimeMillis() - data.lastKeepAliveSentAt < 1000L) continue;
            if (controller.getAddress(connId) == null) continue;
            try {
                if (!controller.hasPlayer(connId)) continue;
            } catch (Throwable ignored) {
                continue;
            }
            long id = ThreadLocalRandom.current().nextLong();
            try {
                boolean ok = controller.sendKeepAlive(connId, id);
                if (!ok) continue;
            } catch (Throwable ignored) {}
            data.lastKeepAliveSentAt = System.currentTimeMillis();
            sends++;
        }
    }

    private void finalVerificationSweep() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, VerificationData> e : pendingVerification.entrySet()) {
            String connId = e.getKey();
            VerificationData data = e.getValue();
            if (data.verified) { pendingVerification.remove(connId); continue; }

            List<Long> samples;
            synchronized (data.keepAliveSamples) { samples = new ArrayList<>(data.keepAliveSamples); }
            if (samples.size() >= 3) {
                double variance = calculateVarianceFast(samples);
                
                double keepaliveScore = fingerprintAnalyzer.analyzeKeepaliveResponseTimes(samples);
                data.botScores.keepaliveScore = keepaliveScore;
                
                InetSocketAddress addr1 = controller.getAddress(connId);
                boolean isLocal = addr1 != null && addr1.getAddress().isLoopbackAddress();
                
                double finalScore = fingerprintAnalyzer.calculateWeightedScore(
                    data.botScores.brandScore,
                    data.botScores.handshakeTimingScore,
                    data.botScores.loginTimingScore,
                    keepaliveScore,
                    data.botScores.subnetBurstScore,
                    data.botScores.usernamePatternScore,
                    data.hasSentSettings,
                    data.hasSentPluginMessage
                );
                
                if (!isLocal && finalScore > 0.75 && !aggressiveMode.get()) {
                    plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (bot-fingerprint-score) conn={0} score={1} keepalive={2} timing={3}", 
                        new Object[]{connId, finalScore, keepaliveScore, data.botScores.handshakeTimingScore});
                    try { controller.closeConnection(connId); } catch (Throwable ignored) {}
                    pendingVerification.remove(connId);
                    continue;
                }
                
                if (!isLocal && variance < 0.5D && !aggressiveMode.get() && !data.hasSentSettings && !data.hasSentPluginMessage) {
                    plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (keepalive-variance+no-settings) conn={0} variance={1}", new Object[]{connId, variance});
                    try { controller.closeConnection(connId); } catch (Throwable ignored) {}
                    pendingVerification.remove(connId);
                    continue;
                }
                
                if (data.hasSentSettings && (data.hasSentPluginMessage || samples.size() >= 3)) {
                    data.verified = true;
                    pendingVerification.remove(connId);
                    continue;
                }
            }

            long ageMs = now - data.createdAt;
            if (ageMs >= VERIFICATION_SWEEP_TICKS * 50L) {
                boolean lowSamples = samples.size() < 3;
                boolean shouldClose = !data.hasSentSettings && !data.hasSentPluginMessage && lowSamples && !aggressiveMode.get();
                boolean handshakePassed = data.handshakePassed;
                boolean hasPlayer = controller.hasPlayer(connId);

                if (shouldClose && !handshakePassed && !hasPlayer) {
                    plugin.getLogger().log(Level.INFO, "PacketAntibotManager: closing connection (verification-timeout-missing-settings) conn={0} ageMs={1}", new Object[]{connId, ageMs});
                    try { controller.closeConnection(connId); } catch (Throwable ignored) {}
                    pendingVerification.remove(connId);
                } else {
                    data.verified = true;
                    pendingVerification.remove(connId);
                }
            }
        }
    }

    private double calculateVarianceFast(List<Long> samples) {
        if (samples.isEmpty()) return Double.MAX_VALUE;
        if (samples.size() == 1) return 0.0;
        
        double mean = 0.0;
        double m2 = 0.0;
        int count = 0;
        
        for (Long value : samples) {
            count++;
            double delta = value - mean;
            mean += delta / count;
            double delta2 = value - mean;
            m2 += delta * delta2;
        }
        
        return count < 2 ? 0.0 : m2 / count;
    }
    
    private String extractSubnet(String ip) {
        if (ip == null || ip.isEmpty()) return null;
        int lastDot = ip.lastIndexOf('.');
        if (lastDot == -1) return null;
        return ip.substring(0, lastDot) + ".0";
    }

    private static class VerificationData {
        final long createdAt = System.currentTimeMillis();
        volatile boolean handshakePassed = false;
        volatile boolean hasSentSettings = false;
        volatile boolean hasSentPluginMessage = false;
        volatile boolean verified = false;
        volatile boolean markedSlow = false;
        volatile long lastActivity = System.currentTimeMillis();
        volatile long lastKeepAliveSentAt = 0L;
        final List<Long> keepAliveSamples = new ArrayList<>();
        
        volatile long handshakeTime = 0L;
        volatile long loginTime = 0L;
        volatile long settingsTime = 0L;
        volatile String username = null;
        
        final BotScores botScores = new BotScores();
    }
    
    private static class BotScores {
        volatile double brandScore = 0.0;
        volatile double handshakeTimingScore = 0.0;
        volatile double loginTimingScore = 0.0;
        volatile double keepaliveScore = 0.0;
        volatile double subnetBurstScore = 0.0;
        volatile double usernamePatternScore = 0.0;
    }
}
