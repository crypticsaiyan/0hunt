import * as dotenv from "dotenv";
dotenv.config();

import { getThreatIntelFeed, getGithubPoCs, getMitigations, getCommunityIntel, getCVSSScore, getSoftwareContext, getPatchIntel, getCanonicalProductName, pushToSlack, pushDailyDigest, DailyStats } from "./ohitaClient";
import { triageThreatFeed, generateSecurityBriefing } from "./agent";
import { hasSeenCVE, markCVESeen } from "./state";

// Exploit Probability Index: base severity + PoC availability + community signal
function computeEPI(baseScore: number, pocCount: number, hasRedditActivity: boolean): number {
    const pocBonus = pocCount === 0 ? 0 : pocCount === 1 ? 1.5 : 2.5;
    const communityBonus = hasRedditActivity ? 0.5 : 0;
    return Math.min(10, baseScore + pocBonus + communityBonus);
}

function getSeverity(epi: number): "CRITICAL" | "HIGH" | "MEDIUM" {
    if (epi >= 8.5) return "CRITICAL";
    if (epi >= 6.5) return "HIGH";
    return "MEDIUM";
}

async function mainLoop(): Promise<boolean> {
    const cycleStart = new Date().toISOString();
    console.log(`\n${"=".repeat(50)}`);
    console.log(`[${cycleStart}] 0hunt — Starting Cycle`);
    console.log(`${"=".repeat(50)}`);

    // Step 1: Ingest & Triage
    console.log("[1/4] Ingesting threat intel (HackerNews + Twitter)...");
    const feed = await getThreatIntelFeed();

    if (!feed.trim()) {
        console.log("[-] Feed empty. No data from sources. Sleeping.");
        return false;
    }

    console.log("[1/4] Triaging with AI...");
    const triage = await triageThreatFeed(feed);

    if (!triage.hasThreat || !triage.cveId || !triage.affectedSoftware) {
        console.log("[-] No significant zero-day detected. Feed clear.");
        return false;
    }

    const { cveId, baseScore = 7, threatType = "Unknown" } = triage;
    let { affectedSoftware } = triage;
    console.log(`[!] Potential zero-day detected: ${cveId} in ${affectedSoftware} (base score: ${baseScore})`);

    // Deduplication — skip if already alerted
    if (hasSeenCVE(cveId)) {
        console.log(`[-] ${cveId} already processed. Skipping duplicate alert.`);
        return false;
    }

    // Step 2: Deep-Dive Intelligence (all parallel)
    console.log("[2/4] Hunting for PoCs, mitigations, community intel, patch info, and CVSS...");
    const [pocs, mitigations, communityIntel, cvssSnippet, softwareContext, patchIntel, canonicalName] = await Promise.all([
        getGithubPoCs(cveId),
        getMitigations(affectedSoftware),
        getCommunityIntel(cveId, affectedSoftware),
        getCVSSScore(cveId),
        getSoftwareContext(affectedSoftware),
        getPatchIntel(cveId, affectedSoftware),
        getCanonicalProductName(cveId)
    ]);

    // Use NVD canonical product name if available — more accurate than LLM extraction
    if (canonicalName) {
        console.log(`   → Canonical product: ${canonicalName} (was: ${affectedSoftware})`);
        affectedSoftware = canonicalName;
    }

    console.log(`   → ${pocs.length} PoC repo(s) found on GitHub`);
    console.log(`   → Community intel: ${communityIntel ? "yes" : "none"}`);
    console.log(`   → CVSS (NVD): ${cvssSnippet ? "found" : "not found"}`);
    console.log(`   → Wikipedia context: ${softwareContext ? "found" : "none"}`);
    console.log(`   → Patch intel (Tavily): ${patchIntel ? "found" : "none"}`);

    // Step 3: Compute EPI Score
    const epiScore = computeEPI(baseScore, pocs.length, !!communityIntel);
    const severity  = getSeverity(epiScore);
    console.log(`[3/4] EPI Score: ${epiScore.toFixed(1)}/10 → ${severity}`);

    if (epiScore < 4) {
        console.log(`[-] EPI too low (${epiScore.toFixed(1)}). Not worth alerting.`);
        markCVESeen(cveId);
        return false;
    }

    // Step 4: Synthesize & Deliver
    console.log("[4/4] Generating security briefing...");
    const briefing = await generateSecurityBriefing(
        feed, pocs, mitigations, communityIntel, cvssSnippet,
        cveId, affectedSoftware, epiScore, severity
    );

    console.log("[4/4] Pushing to Slack...");
    await pushToSlack({
        cveId,
        software: affectedSoftware,
        epiScore,
        severity,
        threatType,
        pocs,
        mitigations,
        briefing,
        redditIntel: communityIntel,
        cvssSnippet,
        softwareContext,
        patchIntel,
        detectedAt: cycleStart
    });

    markCVESeen(cveId);
    console.log(`[✓] Cycle complete. ${cveId} logged to dedup state.`);
    return true;
}

async function start() {
    console.log("🛡️  0hunt starting...");
    console.log("    Polling interval : 30 minutes");
    console.log("    Intel sources    : HackerNews, GitHub, StackExchange, Wikipedia, Tavily, NVD");
    console.log("    Delivery         : Slack");

    const stats: DailyStats = { cyclesRun: 0, threatsFound: 0, cvesSeen: [] };

    const runCycle = async () => {
        stats.cyclesRun++;
        try {
            const found = await mainLoop();
            if (found) {
                stats.threatsFound++;
                // Pick up the last logged CVE from state file
                const state = JSON.parse(require("fs").readFileSync("cve-state.json", "utf-8"));
                const latest = Object.keys(state.seenCVEs).pop();
                if (latest && !stats.cvesSeen.includes(latest)) stats.cvesSeen.push(latest);
            }
        } catch (e: any) {
            console.error("Loop error (engine continues):", e.message);
        }
    };

    // Initial run
    await runCycle();

    const INTERVAL_MS = 30 * 60 * 1000;
    setInterval(runCycle, INTERVAL_MS);

    // Daily digest every 24 hours
    setInterval(async () => {
        await pushDailyDigest(stats);
    }, 24 * 60 * 60 * 1000);
}

start().catch(e => {
    console.error("Fatal engine error:", e);
    process.exit(1);
});
