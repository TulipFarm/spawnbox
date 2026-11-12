import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://spawnbox.tulipfarm.ai",
  markdown: {
    shikiConfig: { theme: "github-light" },
  },
});
