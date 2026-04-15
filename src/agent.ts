import * as dotenv from "dotenv";
dotenv.config();

import OpenAI from "openai";

const openai = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY || "",
    maxRetries: 0
});

const FALLBACK_MODELS = [
    "liquid/lfm-2.5-1.2b-instruct:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "google/gemma-4-31b-it:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "minimax/minimax-m2.5:free"
];

export interface TriageResult {
    hasThreat: boolean;
    cveId?: string;
    affectedSoftware?: string;
    baseScore?: number;   // 1-10: LLM's severity assessment before PoC adjustment
    threatType?: string;  // RCE | AuthBypass | DoS | InfoLeak | PrivEsc | Other
}

async function callLLMWithFallback(messages: any[]): Promise<string> {
    let lastError = "";
    for (const model of FALLBACK_MODELS) {
        try {
            console.log(`      ...trying model: ${model}`);
            const response = await openai.chat.completions.create({ model, messages });
            return response.choices[0].message.content || "{}";
        } catch (e: any) {
            lastError = e.message;
        }
    }
    throw new Error(`All fallback models failed. Last error: ${lastError}`);
}

export async function triageThreatFeed(feedData: string): Promise<TriageResult> {
    if (!feedData.trim()) return { hasThreat: false };

    try {
        const raw = await callLLMWithFallback([
            {
                role: "system",
                content: `You are a senior security triage analyst. Analyze this raw feed for genuine, high-priority zero-day threats.

If a real threat exists, respond with ONLY this JSON (no extra text):
{"hasThreat": true, "cveId": "CVE-XXXX-XXXXX", "affectedSoftware": "Product Name", "baseScore": <1-10>, "threatType": "RCE"}

Rules:
- affectedSoftware: the PRODUCT name (e.g. "Google Chrome", "Apache HTTP Server", "Windows") — NOT the vulnerability component (not "CSS", "HTTP", "memory")
- threatType: ONE value only from: RCE, AuthBypass, DoS, InfoLeak, PrivEsc, Other
- baseScore:
  9-10: unauthenticated RCE, widespread software, actively exploited
  7-8:  auth bypass, privilege escalation, serious impact
  5-6:  requires auth, limited scope, or theoretical
  1-4:  edge case, theoretical, minimal real-world impact

If no genuine threat, respond with ONLY: {"hasThreat": false}`
            },
            { role: "user", content: `Raw Feed:\n${feedData}` }
        ]);

        const jsonMatch = raw.match(/\{[\s\S]*\}/);
        const result = JSON.parse(jsonMatch ? jsonMatch[0] : "{}");
        return {
            hasThreat: !!result.hasThreat,
            cveId: result.cveId,
            affectedSoftware: result.affectedSoftware,
            baseScore: result.baseScore,
            threatType: result.threatType
        };
    } catch (e: any) {
        console.error("Error in LLM triage:", e.message);
        return { hasThreat: false };
    }
}

export async function generateSecurityBriefing(
    feedData: string,
    pocs: string[],
    mitigations: string,
    redditIntel: string,
    cvssSnippet: string,
    cveId: string,
    software: string,
    epiScore: number,
    severity: string
): Promise<string> {
    try {
        const raw = await callLLMWithFallback([
            {
                role: "system",
                content: `You are a security analyst writing an emergency briefing. Be concise and actionable.
Format as clean Slack mrkdwn (use *bold*, \`code\`, bullet points with •).
Structure:
1. One-paragraph executive summary (2-3 sentences max)
2. "• Mitigation Steps:" — 3-5 concrete, specific actions a sysadmin can take RIGHT NOW
Do NOT repeat the CVE ID, software name, EPI score, or PoC links — those are already in the header.
Keep total length under 400 words.`
            },
            {
                role: "user",
                content: `CVE: ${cveId} | Product: ${software} | Severity: ${severity} | EPI: ${epiScore}/10
NVD Official Description: ${cvssSnippet || "Not available"}
PoCs on GitHub: ${pocs.length > 0 ? "YES — exploit code is public" : "None found"}
Community activity: ${redditIntel ? "Active discussion" : "None"}
Stack Exchange mitigations: ${mitigations || "None found"}`
            }
        ]);
        return raw || "Intelligence gathered but briefing generation failed.";
    } catch (e: any) {
        console.error("Error generating briefing:", e.message);
        return "Critical Error: Could not generate security briefing.";
    }
}
