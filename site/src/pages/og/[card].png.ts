import type { APIRoute, GetStaticPaths } from "astro";
import { ogCards, renderOg } from "../../lib/og";

export const getStaticPaths: GetStaticPaths = () => Object.keys(ogCards).map((card) => ({ params: { card } }));

export const GET: APIRoute = async ({ params }) =>
  new Response(new Uint8Array(await renderOg(ogCards[params.card!])), {
    headers: { "Content-Type": "image/png" },
  });
