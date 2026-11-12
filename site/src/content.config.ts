import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defineCollection } from "astro:content";
import type { LoaderContext } from "astro/loaders";
import { docPages, docSections } from "./data/docs";

const readme = fileURLToPath(new URL("../../README.md", import.meta.url));

async function sync({ store, renderMarkdown, generateDigest }: LoaderContext) {
  const sections = docSections(await readFile(readme, "utf8"));
  const pages = await Promise.all(
    docPages.map(async (page) => {
      const body = sections.get(page.slug)!;
      return { page, body, rendered: await renderMarkdown(body) };
    }),
  );
  const ids = new Map(pages.map((p) => [p.page.slug, new Set(p.rendered.metadata?.headings?.map((h) => h.slug))]));
  for (const { page, body } of pages) {
    for (const [, slug, anchor] of body.matchAll(/\]\(\/docs\/([^/]+)\/#([^)]+)\)/g)) {
      if (!ids.get(slug)?.has(anchor)) throw new Error(`/docs/${page.slug}/ links to a missing heading: /docs/${slug}/#${anchor}`);
    }
  }
  store.clear();
  for (const { page, body, rendered } of pages) {
    store.set({ id: page.slug, data: {}, body, rendered, digest: generateDigest(body) });
  }
}

const docs = defineCollection({
  loader: {
    name: "readme-docs",
    load: async (context) => {
      await sync(context);
      context.watcher?.add(readme);
      context.watcher?.on("change", (path) => {
        if (path === readme) void sync(context);
      });
    },
  },
});

export const collections = { docs };
