// The /docs pages. Each one is a "## " section of the repository README, so the docs never drift from it.
export interface DocPage {
  slug: string;
  /** The "## " heading in README.md. */
  heading: string;
  name: string;
  description: string;
}

export const docPages: DocPage[] = [
  {
    slug: "getting-started",
    heading: "Getting started",
    name: "Getting started",
    description: "Get a Linux host, install Spawnbox, check KVM and create your first sandbox, step by step.",
  },
  {
    slug: "cli",
    heading: "Use the CLI",
    name: "CLI",
    description: "Use the spawnbox command for sandboxes, commands, terminals, files, templates, volumes and secrets.",
  },
  {
    slug: "guides",
    heading: "How to use Spawnbox",
    name: "Guides",
    description:
      "Run commands, build templates, use the coding agent templates, keep secrets outside the sandbox, control network access, fork, pause and more.",
  },
  {
    slug: "fleet",
    heading: "Use more than one host",
    name: "Fleets",
    description: "Run Spawnbox on more than one host: a primary, workers and edges, failover, draining and autoscaling.",
  },
  {
    slug: "api",
    heading: "API reference",
    name: "API reference",
    description: "Every HTTP endpoint for sandboxes, commands, files, templates, services, secrets, volumes, tenants, events and nodes.",
  },
  {
    slug: "configuration",
    heading: "Configuration",
    name: "Configuration",
    description: "Change the server settings in /etc/spawnbox/spawnbox.env: the flags of spawn-api serve and their defaults.",
  },
  {
    slug: "troubleshooting",
    heading: "Troubleshooting",
    name: "Troubleshooting",
    description: "Common problems, their causes and what to do: KVM, host capacity, keys, quotas and template builds.",
  },
  {
    slug: "architecture",
    heading: "How Spawnbox works",
    name: "How it works",
    description: "How a sandbox runs: a Firecracker microVM restored from a template snapshot, an agent over vsock, and one egress proxy for network rules and secrets.",
  },
  {
    slug: "development",
    heading: "Development",
    name: "Development",
    description: "Build Spawnbox from source, run its tests with real VMs, and find your way around the repository.",
  },
];

export const repoUrl = "https://github.com/TulipFarm/spawnbox";
const fence = /^\s*(```|~~~)/;

/** GitHub's heading anchor: lower case, punctuation removed, spaces as hyphens. */
export function slugify(text: string): string {
  return text
    .replace(/`/g, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

interface Section {
  heading: string;
  body: string[];
  /** README anchor → anchor on the section's own page. */
  anchors: Map<string, string>;
}

/** Splits the README at each "## " heading and rewrites its links for /docs. */
export function docSections(readme: string): Map<string, string> {
  const lines = readme.split("\n");
  const sections: Section[] = [];
  const counts = new Map<string, number>();
  const unique = (seen: Map<string, number>, text: string) => {
    const base = slugify(text);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return n ? `${base}-${n}` : base;
  };
  let current: Section | undefined;
  let local = new Map<string, number>();
  let inFence = false;
  for (const line of lines) {
    if (fence.test(line)) inFence = !inFence;
    const h = inFence ? null : /^(#{1,6}) (.+)$/.exec(line);
    if (h && h[1] === "##") {
      current = { heading: h[2], body: [], anchors: new Map() };
      local = new Map();
      sections.push(current);
      current.anchors.set(unique(counts, h[2]), "");
      continue;
    }
    if (h) {
      const global = unique(counts, h[2]);
      if (current && h[1].length > 2) current.anchors.set(global, unique(local, h[2]));
    }
    current?.body.push(line);
  }

  const anchorPage = new Map<string, [string | undefined, string]>();
  for (const s of sections) {
    const page = docPages.find((p) => p.heading === s.heading);
    for (const [global, own] of s.anchors) anchorPage.set(global, [page?.slug, own]);
  }
  const link = (target: string) => {
    if (/^[a-z]+:/i.test(target)) return target;
    if (target.startsWith("#")) {
      const found = anchorPage.get(target.slice(1));
      if (!found) throw new Error(`README link to a missing heading: ${target}`);
      const [slug, own] = found;
      if (!slug) return `${repoUrl}${target}`;
      return `/docs/${slug}/${own ? `#${own}` : ""}`;
    }
    return `${repoUrl}/blob/main/${target}`;
  };

  const out = new Map<string, string>();
  for (const page of docPages) {
    const s = sections.find((x) => x.heading === page.heading);
    if (!s) throw new Error(`README has no "## ${page.heading}" section`);
    let inBodyFence = false;
    const body = s.body.map((line) => {
      if (fence.test(line)) {
        inBodyFence = !inBodyFence;
        return line;
      }
      if (inBodyFence) return line;
      // The page title is the h1, so each heading moves up one level.
      const demoted = line.replace(/^#(#{2,6}) /, "$1 ");
      return demoted.replace(/\]\(([^)\s]+)\)/g, (_, t: string) => `](${link(t)})`);
    });
    out.set(page.slug, body.join("\n").trim());
  }
  return out;
}

