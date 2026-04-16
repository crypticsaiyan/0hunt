import * as dotenv from "dotenv";
dotenv.config();

import OpenAI from "openai";

const openai = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY || "",
    maxRetries: 0
});

async function run() {
    try {
        const response = await openai.chat.completions.create({
            model: "google/gemma-3-27b-it:free",
            messages: [
                {
                    role: "system",
                    content: `You are a triage analyst. Analyze this feed. Is there a genuine, high-priority zero-day threat emerging? If yes, extract the CVE ID and the affected software into a strict JSON format exactly like {"hasThreat": true, "cveId": "CVE-X", "affectedSoftware": "Software Name"}. If no, return {"hasThreat": false}. Output ONLY valid JSON.`
                },
                {
                    role: "user",
                    content: `Raw Feed Data:\n[HackerNews - CVE-2026-]\n- Critical CVE-2026-1122 auth bypass in FooBar`
                }
            ]
        });
        console.log("SUCCESS:", response.choices[0].message.content);
    } catch (e: any) {
        console.log("ERROR STATUS:", e.status);
        console.log("ERROR MESSAGE:", e.message);
        console.log("ERROR RAW:", e.error);
    }
}
run();
