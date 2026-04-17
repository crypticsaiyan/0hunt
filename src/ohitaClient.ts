import * as dotenv from "dotenv";
dotenv.config();
import fetch from "node-fetch";

const BASE_URL = "https://api.ohita.tech/v1";

function getHeaders() {
    return {
        "Authorization": `Bearer ${process.env.OHITA_KEY}`,
        "Content-Type": "application/json"
    };
}

export async function getThreatIntelFeed(): Promise<string> {
    const base = ["CVE-2026-", "zero-day", "RCE exploit", "auth bypass vulnerability"];
    const custom = (process.env.WATCH_KEYWORDS || "")
        .split(",").map(k => k.trim()).filter(Boolean);
    const keywords = [...new Set([...base, ...custom])];
    let combinedFeed = "";

    // HackerNews
    const hnResults = await Promise.allSettled(
        keywords.map(q =>
            fetch(`${BASE_URL}/hackernews/search?q=${encodeURIComponent(q)}`, { headers: getHeaders() })
                .then(r => r.json())
        )
    );
    hnResults.forEach((res, idx) => {
        if (res.status === "fulfilled") {
            const hits = (res.value as any)?.data?.hits || [];
            if (hits.length > 0) {
                combinedFeed += `\n[HackerNews - ${keywords[idx]}]\n`;
                hits.slice(0, 3).forEach((hit: any) => {
                    combinedFeed += `- ${hit.title} (${hit.url})\n`;
                });
            }
        }
    });

    // Twitter/X
    const twResults = await Promise.allSettled(
        keywords.map(q =>
            fetch(`${BASE_URL}/twitter/search?q=${encodeURIComponent(q)}`, { headers: getHeaders() })
                .then(r => r.json())
        )
    );
    twResults.forEach((res, idx) => {
        if (res.status === "fulfilled") {
            const data = res.value as any;
            if (data?.ok && data?.data) {
                combinedFeed += `\n[Twitter - ${keywords[idx]}]\n`;
                (data.data.tweets || []).slice(0, 3).forEach((t: any) => {
                    combinedFeed += `- ${t.text}\n`;
                });
            }
        }
    });

    return combinedFeed;
}

export async function getGithubPoCs(cveId: string): Promise<string[]> {
    const queries = [`${cveId} PoC`, `${cveId} exploit`];
    const pocs: string[] = [];

    for (const q of queries) {
        try {
            const res = await fetch(`${BASE_URL}/github/search/repos?q=${encodeURIComponent(q)}&sort=updated`, { headers: getHeaders() });
            const data: any = await res.json();
            // Ohita returns 'repos' not 'items'
            (data?.data?.repos || data?.data?.items || []).slice(0, 2).forEach((repo: any) => {
                const url = repo.url || repo.html_url;
                if (url) pocs.push(`<${url}|${repo.full_name}> ⭐${repo.stars ?? repo.stargazers_count ?? 0}`);
            });
        } catch (e: any) {
            console.error(`GitHub PoC error for ${q}:`, e.message);
        }
    }
    return [...new Set(pocs)];
}

export async function getMitigations(software: string): Promise<string> {
    try {
        const query = `${software} vulnerability mitigation workaround`;
        const res = await fetch(`${BASE_URL}/stackexchange/search?q=${encodeURIComponent(query)}&site=security.stackexchange.com`, { headers: getHeaders() });
        const data: any = await res.json();
        let mitigations = "";
        (data?.data?.items || []).slice(0, 3).forEach((item: any) => {
            mitigations += `• <${item.link}|${item.title}>\n`;
        });
        return mitigations;
    } catch (e: any) {
        console.error(`Mitigations error for ${software}:`, e.message);
        return "";
    }
}

export async function getCommunityIntel(cveId: string, software: string): Promise<string> {
    let intel = "";

    // 1. HackerNews — search for the specific CVE ID
    try {
        const res = await fetch(
            `${BASE_URL}/hackernews/search?q=${encodeURIComponent(cveId)}`,
            { headers: getHeaders() }
        );
        const data: any = await res.json();
        const hits = data?.data?.hits || [];
        hits.slice(0, 3).forEach((hit: any) => {
            if (hit.title) intel += `• <${hit.url || hit.story_url || "#"}|${hit.title}> (HN)\n`;
        });
    } catch (e: any) {
        console.error(`HN community intel error:`, e.message);
    }

    // 2. Dev.to — only show articles that explicitly mention the CVE or software
    try {
        const res = await fetch(
            `${BASE_URL}/devto/articles?tag=security&per_page=20`,
            { headers: getHeaders() }
        );
        const data: any = await res.json();
        const articles = data?.data?.articles || [];
        const lcCve = cveId.toLowerCase();
        const lcSoftware = software.toLowerCase().split(" ")[0]; // first word only

        articles
            .filter((a: any) =>
                a.title?.toLowerCase().includes(lcCve) ||
                a.title?.toLowerCase().includes(lcSoftware) ||
                a.description?.toLowerCase().includes(lcCve)
            )
            .slice(0, 2)
            .forEach((a: any) => {
                intel += `• <${a.url}|${a.title}> (Dev.to)\n`;
            });
    } catch (e: any) {
        console.error(`Dev.to intel error:`, e.message);
    }

    return intel;
}

export async function getCanonicalProductName(cveId: string): Promise<string> {
    try {
        const res = await fetch(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`
        );
        const data: any = await res.json();
        const cve = data?.vulnerabilities?.[0]?.cve;
        if (!cve) return "";

        // Try CPE configuration first: cpe:2.3:a:google:chrome:* → "Google Chrome"
        const cpeMatch = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || "";
        if (cpeMatch) {
            const parts = cpeMatch.split(":");
            if (parts.length >= 5) {
                const vendor = parts[3].replace(/_/g, " ");
                const product = parts[4].replace(/_/g, " ");
                // Avoid redundant "google google chrome" — skip vendor if it's a substring of product
                const name = product.toLowerCase().includes(vendor.toLowerCase())
                    ? product
                    : `${vendor} ${product}`;
                return name.replace(/\b\w/g, (c: string) => c.toUpperCase());
            }
        }

        // Fallback: extract from description "in <Product> prior to X.X"
        const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
        const match = desc.match(/in ([A-Z][^.]+?) (?:prior to|before|\d)/);
        if (match) return match[1].trim();

        return "";
    } catch (e: any) {
        console.error(`NVD canonical name error:`, e.message);
        return "";
    }
}

export async function getSoftwareContext(software: string): Promise<string> {
    try {
        const res = await fetch(
            `${BASE_URL}/wikipedia/summary?title=${encodeURIComponent(software)}`,
            { headers: getHeaders() }
        );
        const data: any = await res.json();
        const extract = data?.data?.extract || "";
        // First 2-3 sentences, capped at 300 chars
        const sentences = extract.split(". ").slice(0, 3).join(". ");
        return (sentences.length > 300 ? sentences.slice(0, 300) + "…" : sentences);
    } catch (e: any) {
        console.error(`Wikipedia context error:`, e.message);
        return "";
    }
}

export async function getPatchIntel(cveId: string, software: string): Promise<string> {
    try {
        const res = await fetch(
            `${BASE_URL}/search/search?query=${encodeURIComponent(`${cveId} ${software} official patch fix update`)}`,
            { headers: getHeaders() }
        );
        const data: any = await res.json();
        const answer = data?.data?.answer || "";
        const results = data?.data?.results || [];

        let intel = answer ? `_${answer}_\n` : "";
        results.slice(0, 2).forEach((r: any) => {
            if (r.title && r.url) intel += `• <${r.url}|${r.title}>\n`;
        });
        return intel;
    } catch (e: any) {
        console.error(`Patch intel error:`, e.message);
        return "";
    }
}

export async function getCVSSScore(cveId: string): Promise<string> {
    try {
        // NVD REST API — free, no key needed, authoritative CVSS data
        const res = await fetch(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`
        );
        const data: any = await res.json();
        const cve = data?.vulnerabilities?.[0]?.cve;
        if (!cve) return "";

        const description = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
        const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData
            || cve.metrics?.cvssMetricV30?.[0]?.cvssData
            || cve.metrics?.cvssMetricV2?.[0]?.cvssData;

        if (cvss) {
            return `CVSS ${cvss.version}: *${cvss.baseScore} ${cvss.baseSeverity}* — ${description}`;
        }
        return description.slice(0, 300);
    } catch (e: any) {
        console.error(`NVD CVSS error:`, e.message);
        return "";
    }
}

export interface AlertPayload {
    cveId: string;
    software: string;
    epiScore: number;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    threatType: string;
    pocs: string[];
    mitigations: string;
    briefing: string;
    redditIntel: string;
    cvssSnippet: string;
    softwareContext: string;
    patchIntel: string;
    detectedAt: string;
}

export interface DailyStats {
    cyclesRun: number;
    threatsFound: number;
    cvesSeen: string[];
}

export async function pushDailyDigest(stats: DailyStats): Promise<void> {
    const cvesLine = stats.cvesSeen.length > 0
        ? `• CVEs logged: ${stats.cvesSeen.join(", ")}`
        : `• CVEs logged: none`;

    const text = [
        `🛡️ *0hunt — Daily Report*`,
        `• Cycles completed: ${stats.cyclesRun}`,
        `• Threats detected: ${stats.threatsFound}`,
        cvesLine,
        `• Sources: HackerNews, GitHub, StackExchange, Wikipedia, Tavily, NVD`,
        `_Running continuously — next cycle in 30 min_`
    ].join("\n");

    try {
        const channelId = process.env.SLACK_CHANNEL_ID || "";
        const res = await fetch(`${BASE_URL}/slack/messages`, {
            method: "POST",
            headers: getHeaders(),
            body: JSON.stringify({ channel: channelId, text })
        });
        const data: any = await res.json();
        if (data.ok) console.log("✅ Daily digest sent.");
    } catch (e: any) {
        console.error("Daily digest error:", e.message);
    }
}

export async function pushToSlack(payload: AlertPayload): Promise<void> {
    const severityEmoji = { CRITICAL: "🚨", HIGH: "⚠️", MEDIUM: "🔵" }[payload.severity];
    const channelPing  = payload.severity === "CRITICAL" ? "<!channel> " : "";

    const pocSection = payload.pocs.length > 0
        ? `*💀 PoC Exploit Code Found (${payload.pocs.length}):*\n${payload.pocs.map(p => `  • ${p}`).join("\n")}`
        : `*✅ No Public PoC Found Yet* — window to patch before exploitation`;

    const redditSection = payload.redditIntel
        ? `*📣 Community Intel (HN + Dev.to):*\n${payload.redditIntel}`
        : "";

    const mitigationSection = payload.mitigations
        ? `*🛡️ Stack Exchange Mitigations:*\n${payload.mitigations}`
        : "";

    const cvssSection = payload.cvssSnippet
        ? `*📋 NVD Official Data:*\n_${payload.cvssSnippet}_`
        : "";

    const contextSection = payload.softwareContext
        ? `*🌐 Impact Scope:*\n_${payload.softwareContext}_`
        : "";

    const patchSection = payload.patchIntel
        ? `*🔧 Patch Intel (Tavily):*\n${payload.patchIntel}`
        : "";

    const sections = [
        `${channelPing}${severityEmoji} *ZERO-DAY ALERT — EPI Score: ${payload.epiScore.toFixed(1)}/10 (${payload.severity})*`,
        `*CVE:* \`${payload.cveId}\`  |  *Affected:* ${payload.software}  |  *Type:* ${payload.threatType}`,
        contextSection || null,
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
        `*🧠 Executive Summary:*\n${payload.briefing}`,
        pocSection,
        patchSection || null,
        redditSection || null,
        mitigationSection || null,
        cvssSection || null,
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
        `_Detected at ${payload.detectedAt} by 0hunt_`
    ].filter(Boolean) as string[];

    const slackMessage = sections.join("\n\n");

    try {
        const channelId = process.env.SLACK_CHANNEL_ID || "";
        const res = await fetch(`${BASE_URL}/slack/messages`, {
            method: "POST",
            headers: getHeaders(),
            body: JSON.stringify({ channel: channelId, text: slackMessage })
        });
        const data: any = await res.json();
        if (!data.ok) {
            console.error("Slack push failed:", JSON.stringify(data));
        } else {
            console.log("✅ Slack alert sent successfully.");
        }
    } catch (e: any) {
        console.error("Slack push error:", e.message);
    }
}
