// Content for /use-cases. Every request, field and event name must exist in the README's API reference.
import type logos from "../logos.json";

export type LogoName = keyof typeof logos;
export type Status = "today" | "soon";
export type Lane = "app" | "api" | "vm";

export interface Snippet {
  lang: "http" | "bash" | "json";
  code: string;
  label?: string;
}

export interface Stop {
  lane: Lane;
  title: string;
  body: string;
  call?: Snippet;
  reply?: Snippet;
  events?: [string, string][];
  planned?: boolean;
}

export interface Extra {
  title: string;
  body: string;
  call: Snippet;
}

export interface Runs {
  title: string;
  items: [LogoName | null, string][];
}

export interface UseCase {
  slug: string;
  name: string;
  status: Status;
  summary: string;
  title: string;
  description: string;
  h1: string;
  hl: string;
  lede: string;
  actor: string;
  inside: string;
  logos: LogoName[];
  runs: Runs;
  first: string;
  stops: Stop[];
  extrasTitle?: string;
  extras?: Extra[];
  note?: string;
  limits: string[];
}

export const laneName: Record<Lane, string> = {
  app: "YOUR APP",
  api: "SPAWNBOX API",
  vm: "IN THE SANDBOX",
};

const soonNote =
  "Every step except the last one uses features that work today. The last step, marked PLANNED, is the tested, ready-made template and guide that are coming.";

export const runtimeNote =
  "Each sandbox is a Firecracker microVM on a host with KVM. On a host without KVM, Spawnbox uses gVisor. To require microVMs, set the tenant's isolation to microvm-only.";

export const useCases: UseCase[] = [
  {
    slug: "code-execution",
    name: "Code execution",
    status: "today",
    summary: "Run the code that a chat model or a workflow step writes, and send the output back.",
    title: "Run code from AI tool calls and workflow steps — Spawnbox",
    description:
      "Give your chat model or workflow a run-code tool. Each call runs in its own Firecracker microVM on your own servers and returns stdout, stderr and the exit code.",
    h1: "Run the code your model writes.",
    hl: "One tool call, one sandbox.",
    lede: "Give your chat model or workflow a run-code tool. Each call runs in its own microVM on your servers, and you get back stdout, stderr and the exit code. The code cannot reach your app, your keys or your network.",
    actor: "CHAT MODEL",
    inside: "python3 main.py",
    logos: ["python", "node", "typescript"],
    runs: {
      title: "Any language you install in the template",
      items: [["python", "Python"], ["node", "Node.js"], ["typescript", "TypeScript"], ["bun", "Bun"], ["deno", "Deno"], ["go", "Go"], ["rust", "Rust"], ["ruby", "Ruby"], ["bash", "Bash"]],
    },
    first: "POST /v1/sandboxes",
    stops: [
      {
        lane: "app",
        title: "The model calls your tool",
        body: "Your chat app or workflow engine gets a tool call with code in it. Treat that code as untrusted. The model wrote it, and a user's prompt can steer the model.",
        call: {
          lang: "json",
          label: "TOOL CALL",
          code: `{
  "type": "tool_use",
  "id": "call_7f3",
  "name": "run_python",
  "input": {
    "code": "import pandas as pd\\ndf = pd.read_csv('sales.csv')\\nprint(df.groupby('region').total.sum())"
  }
}`,
        },
      },
      {
        lane: "api",
        title: "Your app gets a sandbox",
        body: "py is a template you build once, with Python and pandas. Send the tool call ID in X-Spawnbox-Step. The events of the request get this ID, so you can find them later with ?step_id=. With a warm pool, the sandbox is ready in about 8 ms. This one cannot reach the internet.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes
X-Spawnbox-Step: call_7f3

{"template": "py", "timeout_s": 3600,
 "egress": {"mode": "deny_all"}}`,
        },
        events: [["sandbox.created", "sbx_c7mty9fysaf0t3d5"]],
      },
      {
        lane: "api",
        title: "Put the code and its data in",
        body: "Write each file with one request. A relative path starts at /workspace. Spawnbox replaces a file only after it gets the full body.",
        call: {
          lang: "http",
          code: `PUT /v1/sandboxes/$S/files?path=main.py
PUT /v1/sandboxes/$S/files?path=sales.csv`,
        },
        events: [
          ["file.written", "/workspace/main.py"],
          ["file.written", "/workspace/sales.csv"],
        ],
      },
      {
        lane: "vm",
        title: "Run it",
        body: "Set a time limit, so a loop cannot run forever. If the code tries to reach a website, the DNS answer is REFUSED and the log keeps a record.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes/$S/exec
X-Spawnbox-Step: call_7f3

{"cmd": "python3 main.py", "timeout_s": 30}`,
        },
        reply: {
          lang: "json",
          label: "RESPONSE",
          code: `{"stdout": "region\\neu    18240\\nus    31977\\n...",
 "stderr": "", "exit_code": 0,
 "timed_out": false, "duration_ms": 412}`,
        },
        events: [
          ["exec.started", "python3 main.py"],
          ["exec.finished", "exit 0"],
        ],
      },
      {
        lane: "app",
        title: "Send the result back to the model",
        body: "Return stdout as the tool result, or stderr and the exit code if it failed. Keep the sandbox for the next turn of the chat: its files stay. After 10 minutes with no requests, it pauses by itself and frees its CPU and memory. The next request wakes it in about 65 ms. Spawnbox deletes it when its timeout_s ends. Paused time does not count.",
        call: {
          lang: "json",
          label: "TOOL RESULT",
          code: `{
  "type": "tool_result",
  "tool_use_id": "call_7f3",
  "content": "region\\neu    18240\\nus    31977\\n..."
}`,
        },
        events: [["sandbox.paused", "idle"]],
      },
    ],
    extrasTitle: "In a workflow",
    extras: [
      {
        title: "Tag each step",
        body: "Send the step ID with each request. Later, get all the events of that step.",
        call: { lang: "http", code: `GET /v1/events?step_id=report.3` },
      },
      {
        title: "Try three ways from one point",
        body: "Copy a running sandbox with its memory, processes and files. Up to 16 copies in less than 1 s.",
        call: { lang: "http", code: `POST /v1/sandboxes/$S:fork\n\n{"count": 3}` },
      },
      {
        title: "Keep the output",
        body: "Mount a volume. Its files stay after the sandbox is deleted, for the next step to use.",
        call: { lang: "json", code: `"volumes": [{"volume": "reports",\n             "path": "/data"}]` },
      },
    ],
    limits: [
      "Each exec is a new process. Files stay between calls, but variables in memory do not. To keep them, run a long-lived process in the sandbox.",
      "Output over 1 MiB for each stream is cut. The response then has stdout_truncated or stderr_truncated. Stdin is at most 1 MiB, so put larger inputs in a file.",
      "There are no TypeScript or Python SDKs yet. Use the HTTP API or the spawnbox command.",
    ],
  },
  {
    slug: "mcp-servers",
    name: "MCP servers",
    status: "today",
    summary: "Run an MCP server that you did not write in its own sandbox, with its tokens kept outside.",
    title: "Run MCP servers in sandboxes — Spawnbox",
    description:
      "Run each MCP server in its own Firecracker microVM. Its API tokens stay outside the sandbox, it can reach only the hosts you list, and every connection is logged.",
    h1: "Run MCP servers you did not write.",
    hl: "Each one in its own sandbox.",
    lede: "An MCP server runs someone else's code with your tokens. Run each one in its own microVM. Its tokens stay outside, it can reach only the hosts you list, and every connection it makes is logged.",
    actor: "MCP CLIENT",
    inside: "node server.js",
    logos: ["mcp", "node", "python"],
    runs: {
      title: "Servers that speak Streamable HTTP, in any language",
      items: [["mcp", "MCP"], ["typescript", "TypeScript"], ["node", "Node.js"], ["python", "Python"], ["go", "Go"], ["rust", "Rust"]],
    },
    first: "POST /v1/secrets",
    stops: [
      {
        lane: "app",
        title: "Save the token that the server needs",
        body: "This server calls the GitHub API. Save the token in Spawnbox, not in the server's settings. Inside the sandbox, $GITHUB_TOKEN holds only a placeholder.",
        call: {
          lang: "http",
          code: `POST /v1/secrets

{"name": "github", "type": "http_header",
 "value": "ghp_…",
 "allowed_hosts": ["api.github.com"],
 "env": "GITHUB_TOKEN"}`,
        },
      },
      {
        lane: "api",
        title: "Start the server as a service",
        body: "mcp-github is a template you build once, with the server's code in /workspace/mcp. Spawnbox keeps the server running, checks its port and starts it again if it stops. This sandbox can reach api.github.com and no other site.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes

{"template": "mcp-github",
 "secrets": ["github"],
 "egress": {"mode": "allowlist",
            "allow": ["api.github.com"]},
 "services": [{
   "name": "mcp",
   "command": ["node", "server.js"],
   "cwd": "/workspace/mcp",
   "port": 8000,
   "access": "private",
   "health": {"tcp": true}
 }]}`,
        },
        events: [
          ["sandbox.created", "sbx_4kq2m8wd0xjr7n1p"],
          ["service.started", "mcp"],
        ],
      },
      {
        lane: "app",
        title: "Point your MCP client at it",
        body: "The service's port gets a private preview URL. Give it to your agent's MCP client with an API key that has only the sandboxes:read scope. Spawnbox checks the key and removes it before the request reaches the server. The server must use the Streamable HTTP transport.",
        call: { lang: "http", code: `GET /v1/sandboxes/$S/ports` },
        reply: {
          lang: "json",
          label: "MCP CLIENT SETTINGS",
          code: `{"mcpServers": {"github": {
  "url": "https://{label}.preview.example.com/mcp",
  "headers": {"Authorization": "Bearer <read-only key>"}
}}}`,
        },
      },
      {
        lane: "vm",
        title: "Your agent calls a tool",
        body: "The call goes through the preview URL to the server. The server calls GitHub with the placeholder. On the way out, Spawnbox puts in the real token.",
        call: {
          lang: "json",
          label: "MCP REQUEST",
          code: `{"jsonrpc": "2.0", "id": 7,
 "method": "tools/call",
 "params": {"name": "list_issues",
            "arguments": {"repo": "acme/api"}}}`,
        },
        events: [
          ["net.dns", "api.github.com"],
          ["net.connection", "api.github.com:443"],
          ["secret.injected", "api.github.com"],
        ],
      },
      {
        lane: "vm",
        title: "It tries to send data somewhere else",
        body: "A bad or hacked server can try to post your data to a different host. The DNS answer is REFUSED. A connection to a raw IP address is blocked too. Both go in the log.",
        events: [
          ["net.dns", "paste.example.net · REFUSED"],
          ["net.blocked", "203.0.113.9:443"],
        ],
      },
      {
        lane: "api",
        title: "It crashes and comes back",
        body: "Spawnbox starts the server again after 1 s, then 2 s and 4 s, up to 30 s. The last 1 MiB of its output stays in its log.",
        call: { lang: "http", code: `GET /v1/sandboxes/$S/services/mcp/logs?follow=true` },
        events: [
          ["service.exited", "mcp · code 1"],
          ["service.restarted", "mcp · exit"],
        ],
      },
    ],
    limits: [
      "Spawnbox does not have its own MCP server yet, so an agent cannot create sandboxes through MCP. It is planned.",
      "The server must use Streamable HTTP. For a server that has only stdio, add an HTTP bridge to the template.",
      "Services need a template that was built after services were added. An older template gives 409 conflict. Build it again.",
      "Preview URLs support HTTP/1.1 and WebSockets.",
    ],
  },
  {
    slug: "coding-agents",
    name: "Coding agents",
    status: "today",
    summary: "Run Claude Code, Codex or Copilot CLI on a real repo, with root in its own microVM.",
    title: "Run coding agents in sandboxes — Spawnbox",
    description:
      "Run Claude Code, Codex or Copilot CLI on a real repo in a Firecracker microVM on your own servers. API keys stay outside the sandbox.",
    h1: "Let coding agents break things.",
    hl: "Only their own sandbox breaks.",
    lede: "Run Claude Code, Codex or Copilot CLI on a real repo, with root in its own microVM. Spawnbox has a ready-made template for each one. Our scale test ran 768 Claude Code agents at once, and every one finished.",
    actor: "YOUR AGENT",
    inside: "claude -p",
    logos: ["claude", "codex", "copilot"],
    runs: {
      title: "Any agent with a command line, for example",
      items: [["claude", "Claude Code"], ["codex", "Codex"], ["copilot", "Copilot CLI"], ["gemini", "Gemini CLI"]],
    },
    first: "POST /v1/sandboxes",
    stops: [
      {
        lane: "api",
        title: "Build the agent template once",
        body: "The templates folder of the Spawnbox repo has claude-code, codex and copilot. Each installs one pinned npm release on the base disk, with Node.js 26. A build takes a few minutes, one time for each server. From the next release, a new install builds all three for you.",
        call: {
          lang: "bash",
          code: `# waits until the build is ready
spawnbox templates build templates/claude-code.json`,
        },
      },
      {
        lane: "api",
        title: "Keep the model key outside",
        body: "Save the key as a held secret. Claude Code sends it in the x-api-key header. The agent sees only a placeholder. The proxy puts the real key in requests to api.anthropic.com.",
        call: {
          lang: "http",
          code: `POST /v1/secrets

{"name": "anthropic", "type": "http_header",
 "value": "sk-ant-...", "env": "ANTHROPIC_API_KEY",
 "allowed_hosts": ["api.anthropic.com"],
 "header": "x-api-key", "format": "{value}"}`,
        },
      },
      {
        lane: "api",
        title: "Start a sandbox from the template",
        body: "It starts from the saved snapshot, with the agent already installed. On our test host this took about 0.1 s. The sandbox can reach only the model API, GitHub and npm.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes

{"template": "claude-code",
 "secrets": ["anthropic", "github"],
 "egress": {"mode": "allowlist", "allow": [
   "api.anthropic.com", "github.com",
   "registry.npmjs.org"]}}`,
        },
        events: [["sandbox.created", "sbx_9tr3c0vbq6ym2e8h"]],
      },
      {
        lane: "vm",
        title: "Clone the repo",
        body: "A git_https secret opens private repos. The GitHub token does not go into the sandbox.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes/$S/git:clone

{"url": "https://github.com/acme/api", "depth": 1}`,
        },
        events: [["net.connection", "github.com:443"]],
      },
      {
        lane: "vm",
        title: "Run the agent and watch it live",
        body: "Ask for a stream to get stdout and stderr as they come. If you close the stream, Spawnbox stops the agent.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes/$S/exec
Accept: text/event-stream

{"cmd": "claude -p 'fix the failing test' --permission-mode acceptEdits",
 "cwd": "/workspace/api", "timeout_s": 1800}`,
        },
        events: [
          ["exec.started", "claude -p …"],
          ["secret.injected", "api.anthropic.com"],
          ["exec.finished", "exit 0"],
        ],
      },
      {
        lane: "api",
        title: "Try three fixes from the same point",
        body: "Copy the sandbox with its memory, processes and files. Give each copy a different prompt, and keep the best result.",
        call: { lang: "http", code: `POST /v1/sandboxes/$S:fork\n\n{"count": 3}` },
        events: [["sandbox.forked", "3 copies"]],
      },
    ],
    limits: [
      "Each template pins one release of its agent. To update the agent, change the version in its file and build the template again.",
      "Copilot CLI has no held-secret setup yet, because we have not checked which hosts it sends its token to.",
      "Fork does not work on a paused sandbox or on a sandbox with volumes.",
      "Each copy counts against the quotas of the tenant.",
      "The agent's own settings (permissions, models) are up to you. Spawnbox controls what the sandbox can reach, not what the agent decides.",
    ],
  },
  {
    slug: "web-apps",
    name: "Hosting a web app",
    status: "soon",
    summary: "Keep a Next.js or Vite app running in a sandbox and share it with a preview link.",
    title: "Host a web app in a sandbox — Spawnbox",
    description:
      "Run a Next.js or Vite app in a sandbox on your own servers, keep it running as a service, and share it with a public, token or private preview link.",
    h1: "Host the app your agent built.",
    hl: "Behind a link you control.",
    lede: "Run a Next.js or Vite app in a sandbox, keep it running as a service, and share it with a link. This works today. A ready-made web app template and a guide are coming.",
    actor: "VISITOR",
    inside: "npm run start",
    logos: ["next", "vite", "astro"],
    runs: {
      title: "Any app that serves HTTP, for example",
      items: [["next", "Next.js"], ["vite", "Vite"], ["react", "React"], ["astro", "Astro"], ["svelte", "SvelteKit"], ["django", "Django"], ["fastapi", "FastAPI"]],
    },
    first: "POST /v1/templates",
    note: soonNote,
    stops: [
      {
        lane: "api",
        title: "Build the app into a template",
        body: "Setup runs one time, as root, with network access. The response is 202 with a build. Wait until the build is ready, or the next step gives 409.",
        call: {
          lang: "http",
          code: `POST /v1/templates

{"name": "shop", "base": "node:22-bookworm-slim",
 "setup": [
   "git clone --depth 1 https://github.com/acme/shop /workspace/app",
   "cd /workspace/app && npm ci && npm run build",
   "chown -R 1000:1000 /workspace/app"]}`,
        },
      },
      {
        lane: "api",
        title: "Start it and keep it running",
        body: "A persistent sandbox stays until you delete it. The service starts the app, checks it over HTTP and starts it again if it stops.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes

{"template": "shop", "persistent": true,
 "services": [{
   "name": "web",
   "command": ["npm", "run", "start"],
   "cwd": "/workspace/app",
   "port": 3000, "access": "public",
   "health": {"http": "/"}
 }]}`,
        },
        events: [
          ["sandbox.created", "sbx_2hn7k4pz9qe1wx6d"],
          ["service.started", "web"],
        ],
      },
      {
        lane: "app",
        title: "Share the link",
        body: "Access can be public, need a token, or need a session token for one person. A request waits up to 30 s for the app to be healthy.",
        call: { lang: "http", code: `GET /v1/sandboxes/$S/ports` },
        reply: { lang: "bash", label: "URL", code: `https://{label}.preview.example.com` },
      },
      {
        lane: "vm",
        title: "It crashes and comes back",
        body: "Spawnbox starts the app again after 1 s, then 2 s and 4 s, up to 30 s. It also restarts the app after 3 failed health checks in a row.",
        events: [
          ["service.exited", "web · code 1"],
          ["service.restarted", "web · exit"],
        ],
      },
      {
        lane: "vm",
        title: "It sleeps when no one visits",
        body: "After 10 minutes with no requests, the sandbox pauses and frees its CPU and memory. The next visit wakes it in about 65 ms. If its VM is lost, the next request starts it again from the template, with the same link.",
        events: [
          ["sandbox.paused", "idle"],
          ["sandbox.resumed", ""],
        ],
      },
      {
        lane: "api",
        title: "Coming: a ready-made web app template",
        body: "Templates for Next.js and Vite apps, and a step-by-step guide to host one.",
        planned: true,
      },
    ],
    limits: [
      "Persistent sandboxes run only on the primary server. They cannot move to a worker yet.",
      "A tenant needs the persistent_sandboxes quota. It is 0 by default.",
      "Files outside a volume are lost when the VM is lost. Keep uploads and databases in a volume. A volume is on one server, with no backup copy.",
    ],
  },
  {
    slug: "browser-use",
    name: "Browser use",
    status: "soon",
    summary: "Give an agent its own headless browser that can visit only the sites you allow.",
    title: "Browser use in sandboxes — Spawnbox",
    description:
      "Give an AI agent its own Chromium in a Firecracker microVM on your own servers. It can visit only the sites you allow, and every DNS query and connection is logged.",
    h1: "Give your agent a browser.",
    hl: "It can visit only the sites you allow.",
    lede: "Run Chromium and Playwright in the agent's own microVM. It reads pages, fills forms and takes screenshots. This works today on a plain sandbox. A ready-made browser template and a guide are coming.",
    actor: "YOUR AGENT",
    inside: "chromium",
    logos: ["chrome", "firefox"],
    runs: {
      title: "Browsers and drivers you install, for example",
      items: [[null, "Chromium"], ["firefox", "Firefox"], [null, "Playwright"], ["puppeteer", "Puppeteer"], ["selenium", "Selenium"]],
    },
    first: "POST /v1/templates",
    note: soonNote,
    stops: [
      {
        lane: "api",
        title: "Make a template with a browser",
        body: "The base disk has no apt package lists, so run apt-get update first. The response is 202 with a build. Wait until the build is ready, or the next step gives 409.",
        call: {
          lang: "http",
          code: `POST /v1/templates

{"name": "browser",
 "setup": [
   "apt-get update && apt-get install -y chromium python3-pip",
   "pip install --break-system-packages playwright"],
 "resources": {"vcpus": 2, "memory_mib": 2048}}`,
        },
      },
      {
        lane: "api",
        title: "Start it with a list of sites",
        body: "This browser can open news.ycombinator.com and no other site. Private addresses and cloud metadata are always blocked.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes

{"template": "browser",
 "egress": {"mode": "allowlist",
            "allow": ["news.ycombinator.com"]}}`,
        },
        events: [["sandbox.created", "sbx_6wd1j8fn3ka0tz5r"]],
      },
      {
        lane: "vm",
        title: "The agent runs its script",
        body: "The agent writes a Playwright script that opens the page, reads it and saves a screenshot. Then it runs the script.",
        call: {
          lang: "http",
          code: `PUT  /v1/sandboxes/$S/files?path=browse.py
POST /v1/sandboxes/$S/exec

{"cmd": "python3 browse.py", "timeout_s": 120}`,
        },
        events: [
          ["net.dns", "news.ycombinator.com"],
          ["net.connection", "news.ycombinator.com:443"],
        ],
      },
      {
        lane: "vm",
        title: "A page asks for another site",
        body: "A script or an ad on the page tries to load a different site. The DNS answer is REFUSED, and the log shows the name.",
        events: [["net.dns", "ads.example.net · REFUSED"]],
      },
      {
        lane: "app",
        title: "Get the screenshot",
        body: "Read any file the browser wrote: screenshots, PDFs or downloads.",
        call: { lang: "http", code: `GET /v1/sandboxes/$S/files?path=shot.png` },
      },
      {
        lane: "api",
        title: "Coming: a ready-made browser template",
        body: "A template with Chromium and Playwright installed and tested, and a step-by-step guide.",
        planned: true,
      },
    ],
    limits: [
      "An allowlist checks the TLS SNI or the HTTP Host name, and allows only ports 80 and 443.",
      "Chromium needs memory. Give the template at least 2 GiB.",
    ],
  },
  {
    slug: "computer-use",
    name: "Computer use",
    status: "soon",
    summary: "Give an agent a whole Linux desktop, and watch it from your browser.",
    title: "Computer use in sandboxes — Spawnbox",
    description:
      "Give an AI agent a whole Linux desktop in a Firecracker microVM on your own servers, and watch it from your browser with a private preview link.",
    h1: "Give your agent a whole desktop.",
    hl: "Watch it work from your browser.",
    lede: "Add a desktop to the agent's template. The agent clicks, types and takes screenshots. You watch the same screen in your browser through a private link. You can build this today from a plain sandbox. A ready-made desktop template and a guide are coming.",
    actor: "YOUR AGENT",
    inside: "DISPLAY=:1",
    logos: ["debian", "xfce"],
    runs: {
      title: "The desktop in this example",
      items: [["debian", "Debian"], ["xfce", "Xfce"], [null, "Xvfb"], [null, "noVNC"], [null, "xdotool"]],
    },
    first: "POST /v1/templates",
    note: soonNote,
    stops: [
      {
        lane: "api",
        title: "Make a template with a desktop",
        body: "A virtual screen, a small desktop, a VNC server, a web viewer for VNC, and tools to click and take screenshots. Wait until the build is ready before the next step.",
        call: {
          lang: "http",
          code: `POST /v1/templates

{"name": "desktop",
 "setup": ["apt-get update && apt-get install -y xvfb xfce4 x11vnc novnc websockify xdotool imagemagick"],
 "resources": {"vcpus": 2, "memory_mib": 4096}}`,
        },
      },
      {
        lane: "api",
        title: "Start the desktop as services",
        body: "Spawnbox keeps each part running. The web viewer is private: only a request with your API key or a session token can open it.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes

{"template": "desktop", "services": [
  {"name": "screen", "command": ["sh", "-c",
    "Xvfb :1 -screen 0 1280x800x24 & DISPLAY=:1 startxfce4"]},
  {"name": "vnc", "command": ["x11vnc", "-display", ":1",
    "-forever", "-shared", "-rfbport", "5900"]},
  {"name": "viewer", "command": ["websockify", "--web",
    "/usr/share/novnc", "6080", "localhost:5900"],
   "port": 6080, "access": "private",
   "health": {"tcp": true}}]}`,
        },
        events: [
          ["service.started", "screen"],
          ["service.started", "vnc"],
          ["service.started", "viewer"],
        ],
      },
      {
        lane: "vm",
        title: "The agent clicks and looks",
        body: "Each action is one command on the desktop. A screenshot goes to a file that your app reads and sends to the model.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes/$S/exec

{"cmd": "xdotool mousemove 640 400 click 1 && import -window root s.png",
 "env": {"DISPLAY": ":1"}}`,
        },
        events: [
          ["exec.started", "xdotool mousemove …"],
          ["exec.finished", "exit 0"],
        ],
      },
      {
        lane: "app",
        title: "You watch it live",
        body: "Make a short-lived session token for this sandbox, and open the private viewer link with it. The token works for 15 minutes at most. It opens only this sandbox's terminal and private links, and no other API calls.",
        call: {
          lang: "http",
          code: `POST /v1/sandboxes/$S/session-tokens

{"ttl_s": 900}`,
        },
        reply: { lang: "bash", label: "OPEN", code: `<viewer url>/vnc.html?spawnbox_session=<token>` },
        events: [["sandbox.session_token_created", ""]],
      },
      {
        lane: "api",
        title: "Coming: a ready-made desktop template",
        body: "A tested desktop template with a browser and a web viewer, and a step-by-step guide.",
        planned: true,
      },
    ],
    limits: [
      "A desktop needs more memory than a headless browser. Give the template at least 4 GiB.",
      "The services above are an example of how the parts fit. They are not a tested template yet.",
    ],
  },
];
