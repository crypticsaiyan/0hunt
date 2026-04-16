import * as dotenv from "dotenv"; dotenv.config();
import OpenAI from "openai";

const openai = new OpenAI({ baseURL: "https://openrouter.ai/api/v1", apiKey: process.env.OPENROUTER_API_KEY || "", maxRetries: 0 });

const models = [
  "google/gemma-4-31b-it:free",
  "minimax/minimax-m2.5:free",
  "qwen/qwen3-next-80b-a3b-instruct:free",
  "liquid/lfm-2.5-1.2b-instruct:free",
  "openai/gpt-oss-120b:free",
  "z-ai/glm-4.5-air:free",
  "qwen/qwen3-coder:free",
  "google/gemma-3-12b-it:free"
];

async function scan() {
  for (const m of models) {
    try {
      const res = await openai.chat.completions.create({
        model: m,
        messages: [{role:"user", content:"hello"}],
      });
      console.log("SUCCESS:", m, "->", res.choices[0].message.content?.slice(0, 10));
      return;
    } catch(e) {}
  }
}
scan();
