import { readFile } from "node:fs/promises";

// Serves the repository's own installer so the site never ships a stale copy.
export async function GET() {
  return new Response(await readFile("../install.sh"));
}
