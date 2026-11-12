import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Resvg } from "@resvg/resvg-js";
import satori from "satori";
import { useCases } from "../data/use-cases";

export interface OgCard {
  eyebrow: string;
  h1: string;
  hl: string;
  summary: string;
  planned?: boolean;
}

export const ogCards: Record<string, OgCard> = {
  home: {
    eyebrow: "OPEN SOURCE · SELF-HOSTED",
    h1: "Sandboxes for AI agents,",
    hl: "on your own servers.",
    summary: "Firecracker microVMs on your own Linux servers, with a gVisor fallback.",
  },
  "use-cases": {
    eyebrow: "USE CASES",
    h1: "What you can run.",
    hl: "Each one, step by step.",
    summary: "Code from tool calls and workflow steps, MCP servers, coding agents, web apps, browser use and computer use.",
  },
  ...Object.fromEntries(
    useCases.map((u) => [
      u.slug,
      {
        eyebrow: `USE CASE · ${u.status === "today" ? "WORKS TODAY" : "TEMPLATE COMING"}`,
        h1: u.h1,
        hl: u.hl,
        summary: u.summary,
        planned: u.status === "soon",
      },
    ]),
  ),
};

const require = createRequire(import.meta.url);
const font = (pkg: string, weight: number) =>
  readFileSync(require.resolve(`@fontsource/${pkg}/files/${pkg}-latin-${weight}-normal.woff`));
const fonts = [
  { name: "Sans", data: font("ibm-plex-sans-condensed", 400), weight: 400 as const },
  { name: "Sans", data: font("ibm-plex-sans-condensed", 700), weight: 700 as const },
  { name: "Mono", data: font("ibm-plex-mono", 500), weight: 500 as const },
  { name: "Mono", data: font("ibm-plex-mono", 600), weight: 600 as const },
];

const ink = "#0a1f4d";
const muted = "#4a5f86";
const blue = "#1d4ed8";
const line = "rgba(29, 78, 216, 0.22)";

type Node = { type: string; props: Record<string, unknown> };
const h = (type: string, style: Record<string, unknown>, ...children: (Node | string)[]): Node => ({
  type,
  props: { style, children },
});
const img = (src: string, width: number, height: number): Node => ({ type: "img", props: { src, width, height } });
const svgUri = (svg: string) => `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;

// Same isometric projection as components/Box.astro.
const C = Math.cos(Math.PI / 6);
function box(i: number, j: number, k: number, w: number, d: number, ht: number, s: number, tone: "solid" | "deep" | "wire") {
  const p = (a: number, b: number, c: number) => `${((a - b) * C * s).toFixed(1)},${((a + b) * 0.5 * s - c * s).toFixed(1)}`;
  const faces = {
    top: [p(i, j, k + ht), p(i + w, j, k + ht), p(i + w, j + d, k + ht), p(i, j + d, k + ht)],
    left: [p(i, j + d, k), p(i + w, j + d, k), p(i + w, j + d, k + ht), p(i, j + d, k + ht)],
    right: [p(i + w, j, k), p(i + w, j + d, k), p(i + w, j + d, k + ht), p(i + w, j, k + ht)],
  };
  const fill = {
    solid: { top: "#f2f6ff", left: "#c9dafd", right: "#93b4fb" },
    deep: { top: "#dbe7ff", left: "#7ea3f5", right: "#4f7fe8" },
    wire: { top: "#ffffff", left: "#ffffff", right: "#e8f0ff" },
  }[tone];
  const dash = tone === "wire" ? ' stroke-dasharray="8 6"' : "";
  return (["left", "right", "top"] as const)
    .map((f) => `<polygon points="${faces[f].join(" ")}" fill="${fill[f]}" stroke="${blue}" stroke-width="2.4" stroke-linejoin="round"${dash}/>`)
    .join("");
}

// A planned use case shows its top box as a dashed outline, like PLANNED steps on the page.
const art = (planned: boolean) =>
  svgUri(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-170 -230 340 360" width="340" height="360">${
      box(-1.3, -1.3, 0, 2.6, 2.6, 0.5, 52, "deep") +
      box(-1, -1, 0.5, 2, 2, 1.2, 52, "solid") +
      box(-0.6, -0.6, 1.7, 1.2, 1.2, 1, 52, planned ? "wire" : "solid")
    }</svg>`,
  );
const mark = svgUri(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-22 -26 44 48" width="44" height="48">${box(-0.5, -0.5, 0, 1, 1, 1, 20, "solid")}</svg>`,
);

const kv = (k: string, v: string, first = false, grow = 1): Node =>
  h(
    "div",
    { display: "flex", flexDirection: "column", flexGrow: grow, padding: "14px 22px", gap: 4, borderLeft: first ? "none" : `1px solid ${line}` },
    h("div", { fontFamily: "Mono", fontSize: 14, fontWeight: 500, color: muted, letterSpacing: 2 }, k),
    h("div", { fontFamily: "Mono", fontSize: 20, fontWeight: 600, color: ink, letterSpacing: 1 }, v),
  );

// Keep each headline line on one line in the 760px text column.
const headline = (c: OgCard) => {
  const longest = Math.max(c.h1.length, c.hl.length);
  return longest <= 27 ? 62 : longest <= 31 ? 52 : 44;
};

export async function renderOg(c: OgCard): Promise<Buffer> {
  const tree = h(
    "div",
    {
      width: 1200,
      height: 630,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      backgroundColor: "#fbfcfe",
      backgroundImage:
        "linear-gradient(rgba(29,78,216,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(29,78,216,0.07) 1px, transparent 1px)",
      backgroundSize: "28px 28px",
    },
    h(
      "div",
      { display: "flex", flexDirection: "column", width: 1144, height: 574, border: `2px solid ${blue}`, backgroundColor: "#fbfcfe" },
      h(
        "div",
        { display: "flex", flexGrow: 1, padding: "34px 40px 0" },
        h(
          "div",
          { display: "flex", flexDirection: "column", width: 760 },
          h(
            "div",
            { display: "flex", alignItems: "center", gap: 14 },
            img(mark, 40, 44),
            h("div", { fontFamily: "Mono", fontSize: 24, fontWeight: 600, color: ink, letterSpacing: 4 }, "SPAWNBOX"),
          ),
          h(
            "div",
            { display: "flex", marginTop: 36 },
            h(
              "div",
              { fontFamily: "Mono", fontSize: 18, fontWeight: 600, color: blue, letterSpacing: 3, border: `1.5px solid ${blue}`, padding: "4px 10px" },
              c.eyebrow,
            ),
          ),
          h(
            "div",
            { display: "flex", flexDirection: "column", marginTop: 22, fontFamily: "Sans", fontWeight: 700, fontSize: headline(c), lineHeight: 1.05, color: ink },
            h("div", {}, c.h1),
            h("div", { color: blue }, c.hl),
          ),
          h("div", { marginTop: 20, fontFamily: "Sans", fontSize: 28, lineHeight: 1.3, color: muted, maxWidth: 700 }, c.summary),
        ),
        h("div", { display: "flex", flexGrow: 1, alignItems: "center", justifyContent: "center" }, img(art(!!c.planned), 340, 360)),
      ),
      h(
        "div",
        { display: "flex", borderTop: `1.5px solid ${blue}` },
        kv("PROJECT", "SPAWNBOX", true),
        kv("RUNTIME", "FIRECRACKER · gVISOR"),
        kv("LICENSE", "APACHE-2.0"),
        kv("SOURCE", "github.com/TulipFarm/spawnbox", false, 2),
      ),
    ),
  );
  const svg = await satori(tree as Parameters<typeof satori>[0], { width: 1200, height: 630, fonts });
  return new Resvg(svg).render().asPng();
}
