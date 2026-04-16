import * as fs from "fs";
import * as path from "path";

const STATE_FILE = path.join(process.cwd(), "cve-state.json");

interface CVEState {
    seenCVEs: Record<string, string>;
}

function load(): CVEState {
    try {
        if (fs.existsSync(STATE_FILE)) {
            return JSON.parse(fs.readFileSync(STATE_FILE, "utf-8"));
        }
    } catch {}
    return { seenCVEs: {} };
}

function save(state: CVEState): void {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

export function hasSeenCVE(cveId: string): boolean {
    return !!load().seenCVEs[cveId];
}

export function markCVESeen(cveId: string): void {
    const state = load();
    state.seenCVEs[cveId] = new Date().toISOString();
    save(state);
}
