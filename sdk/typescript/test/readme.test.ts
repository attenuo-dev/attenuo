/**
 * The TypeScript snippets of the README and the walkthrough, checked as code.
 *
 * Every fenced `ts` block of `sdk/typescript/README.md` and of the
 * "TypeScript SDK" section of `docs/guides/walkthrough.md` is type-checked with the TypeScript
 * compiler against the built SDK
 * types (`dist/index.d.ts`, so `npm run build` first; `src/index.ts` when there is no build),
 * each snippet a module of its own, strict, with Node's globals and no DOM. A first pass finds the names a snippet uses without
 * declaring them; the second declares those (`ob` an `AttenuoClient`, `admin` an `AdminClient`,
 * `root`, `coder` and `token` a `Token`, `SERVER` a `string`, an SDK export imported, anything
 * else `any`) and must report no error. `@modelcontextprotocol/sdk` is not a dependency of this
 * package, so its imports are typed `any`.
 *
 * The "Everything the package exports" section of `sdk/typescript/README.md` must list every
 * name `src/index.ts` exports (values and types), and some code of that README must show every
 * public method of an exported class.
 *
 * With `ATTENUO_INTEGRATION=1`, the self-contained snippets (no undeclared names, no local file,
 * no MCP SDK) also run, against a real `attenuo-server` started from `config/example.toml` with
 * `[dev] allow_root_mint = true`, as the walkthrough starts it, and the fake MCP upstream
 * (binaries from `ATTENUO_BIN_DIR`, as in `integration.test.ts`).
 */

import { type ChildProcess, spawn } from "node:child_process";
import {
  copyFileSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import * as sdk from "../src/index.js";

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(PKG, "../..");
const WALKTHROUGH = join(REPO, "docs", "guides", "walkthrough.md");
const PAGES = [join(PKG, "README.md"), WALKTHROUGH];
const KNOWN: Record<string, string> = {
  SERVER: "string",
  ob: "AttenuoClient",
  admin: "AdminClient",
  root: "Token",
  coder: "Token",
  token: "Token",
};
const LOCAL_FILE = /["'][^"']*\.(jsonl|jwk|jwt|pem)["']/;
const ADMIN_TOKEN = "readme-admin-token-0123456789abcdef0123456789abcdef";
const CODER_SECRET = "coder-secret-change-me"; // the example config's [[agents]] coder

interface Snippet {
  id: string;
  line: number;
  code: string;
}

function snippets(): Snippet[] {
  const found: Snippet[] = [];
  for (const page of PAGES) {
    let text = readFileSync(page, "utf8");
    let offset = 0;
    if (page === WALKTHROUGH) {
      // Only the walkthrough's TypeScript SDK section.
      const start = text.indexOf("\n## TypeScript SDK\n");
      if (start < 0) throw new Error('the walkthrough has no "TypeScript SDK" section');
      const next = text.indexOf("\n## ", start + 1);
      const end = next < 0 ? text.length : next;
      offset = text.slice(0, start).split("\n").length - 1;
      text = text.slice(start, end);
    }
    for (const m of text.matchAll(/^```ts\n([\s\S]*?)^```$/gm)) {
      const line = offset + text.slice(0, m.index).split("\n").length;
      found.push({ id: `${relative(REPO, page)}:${line}`, line, code: m[1] ?? "" });
    }
  }
  return found;
}

const ALL = snippets();

/** The built types when there are some, else the source. */
function sdkTypes(): string {
  const built = join(PKG, "dist", "index.d.ts");
  return existsSync(built) ? built : join(PKG, "src", "index.ts");
}

/** Type-check `files`; the diagnostics per file. */
function check(dir: string, files: string[]): Map<string, ts.Diagnostic[]> {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    moduleDetection: ts.ModuleDetectionKind.Force,
    // No DOM: its globals (`stop`, `name`, ...) would hide a snippet's placeholder names.
    lib: ["lib.es2022.d.ts"],
    types: ["node"],
    typeRoots: [join(PKG, "node_modules", "@types")],
    strict: true,
    // Values from the MCP SDK are `any`, and so are the parameters of callbacks they take.
    noImplicitAny: false,
    noEmit: true,
    skipLibCheck: true,
    paths: { "@attenuo/sdk": [sdkTypes()] },
  };
  const shim = join(dir, "shims.d.ts");
  writeFileSync(shim, 'declare module "@modelcontextprotocol/sdk/*";\n');
  const program = ts.createProgram([...files, shim], options);
  const out = new Map<string, ts.Diagnostic[]>(files.map((f) => [f, []]));
  for (const d of ts.getPreEmitDiagnostics(program)) {
    const name = d.file?.fileName;
    if (name && out.has(name)) out.get(name)?.push(d);
    else out.set("<global>", [...(out.get("<global>") ?? []), d]);
  }
  return out;
}

/** "Cannot find name 'x'" (2304), "... Did you mean 'y'?" (2552) and a shorthand property
 * `{ x }` with no `x` in scope (18004). */
function missingNames(diags: ts.Diagnostic[]): string[] {
  const names = new Set<string>();
  for (const d of diags) {
    if (![2304, 2552, 18004].includes(d.code)) continue;
    const m = /'([^']+)'/.exec(ts.flattenDiagnosticMessageText(d.messageText, "\n"));
    if (m?.[1]) names.add(m[1]);
  }
  return [...names].sort();
}

const exported = new Set(Object.keys(sdk));
// Types are not runtime exports; these are the ones the README names without importing.
const exportedTypes = new Set(["Token"]);

function prelude(missing: string[]): string[] {
  const fromSdk = missing.filter((n) => exported.has(n) || exportedTypes.has(n));
  const lines = [
    `import type { AdminClient as _A, AttenuoClient as _C, Token as _T } from "@attenuo/sdk";`,
  ];
  if (fromSdk.length) lines.push(`import { ${fromSdk.join(", ")} } from "@attenuo/sdk";`);
  for (const n of missing) {
    if (fromSdk.includes(n)) continue;
    const type = { AttenuoClient: "_C", AdminClient: "_A", Token: "_T" }[KNOWN[n] ?? ""];
    // `let`, since a snippet may assign a new token to `token`.
    lines.push(`declare let ${n}: ${type ?? KNOWN[n] ?? "any"};`);
  }
  return lines;
}

let dir = "";
let missing: Map<Snippet, string[]> | undefined;

/** The first pass: the names each snippet uses without declaring them. */
function undeclared(): Map<Snippet, string[]> {
  if (!missing) {
    const files = ALL.map((_, k) => join(dir, `snippet_${k}.ts`));
    ALL.forEach((s, k) => writeFileSync(files[k] as string, s.code));
    const first = check(dir, files);
    missing = new Map(ALL.map((s, k) => [s, missingNames(first.get(files[k] as string) ?? [])]));
  }
  return missing;
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "attenuo-readme-ts-"));
});
afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("README TypeScript snippets", () => {
  it("finds snippets on every page", () => {
    for (const page of PAGES) {
      expect(ALL.some((s) => s.id.startsWith(`${relative(REPO, page)}:`))).toBe(true);
    }
  });

  it("import every SDK export they use", () => {
    // The type check below declares a missing SDK name for the snippet, so a snippet that forgot
    // its import would pass there and fail with a ReferenceError for a reader who copies it.
    const unimported = ALL.flatMap((s) =>
      (undeclared().get(s) ?? []).filter((n) => exported.has(n)).map((n) => `${s.id}: ${n}`),
    );
    expect(unimported, unimported.join("\n")).toEqual([]);
  });

  it("type-check against the SDK", () => {
    const names = undeclared();
    const files = ALL.map((_, k) => join(dir, `snippet_${k}.ts`));
    const heads = ALL.map((s) => prelude(names.get(s) ?? []));
    ALL.forEach((s, k) =>
      writeFileSync(files[k] as string, `${(heads[k] as string[]).join("\n")}\n${s.code}`),
    );
    const second = check(dir, files);
    const errors: string[] = [];
    for (const [file, diags] of second) {
      const k = files.indexOf(file);
      const s = ALL[k];
      for (const d of diags) {
        const text = ts.flattenDiagnosticMessageText(d.messageText, "\n");
        if (!s || !d.file || d.start === undefined) {
          errors.push(`${file}: ${text}`);
          continue;
        }
        const at = d.file.getLineAndCharacterOfPosition(d.start).line;
        const headLines = (heads[k] as string[]).join("\n").split("\n").length;
        const page = s.id.slice(0, s.id.lastIndexOf(":"));
        errors.push(`${page}:${s.line + at + 1 - headLines}: TS${d.code} ${text}`);
      }
    }
    expect(errors, errors.join("\n")).toEqual([]);
  });
});

/**
 * The names `src/index.ts` exports, values and types alike, and the public methods (static ones
 * too) of the classes among them, as `Class.method`.
 */
function publicApi(): { names: string[]; methods: string[] } {
  const index = join(PKG, "src", "index.ts");
  const program = ts.createProgram([index], {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  });
  const checker = program.getTypeChecker();
  const source = program.getSourceFile(index);
  const mod = source && checker.getSymbolAtLocation(source);
  if (!mod) throw new Error(`cannot read the exports of ${index}`);
  const names: string[] = [];
  const methods = new Set<string>();
  for (const sym of checker.getExportsOfModule(mod)) {
    names.push(sym.name);
    const target = sym.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(sym) : sym;
    for (const decl of target.declarations ?? []) {
      if (!ts.isClassDeclaration(decl)) continue;
      for (const m of decl.members) {
        // `#private` names are PrivateIdentifiers, so `isIdentifier` leaves them out.
        if (!ts.isMethodDeclaration(m) || !ts.isIdentifier(m.name)) continue;
        const hidden = ts.ModifierFlags.Private | ts.ModifierFlags.Protected;
        if (ts.getCombinedModifierFlags(m) & hidden) continue;
        methods.add(`${sym.name}.${m.name.text}`);
      }
    }
  }
  return { names, methods: [...methods].sort() };
}

const EXPORTS_SECTION = "## Everything the package exports";

/** The package README's "Everything the package exports" section. */
function exportsSection(): string {
  const text = readFileSync(join(PKG, "README.md"), "utf8");
  const start = text.indexOf(`\n${EXPORTS_SECTION}\n`);
  if (start < 0) throw new Error(`sdk/typescript/README.md has no "${EXPORTS_SECTION}" section`);
  const end = text.indexOf("\n## ", start + 1);
  return text.slice(start, end < 0 ? undefined : end);
}

/** The package README's fenced blocks and inline code spans, where a method is shown in use. */
function readmeCode(): string {
  const text = readFileSync(join(PKG, "README.md"), "utf8");
  const fence = /^```[\w-]*\n([\s\S]*?)^```/gm;
  const fenced = [...text.matchAll(fence)].map((m) => m[1] ?? "");
  const spans = [...text.replace(fence, "").matchAll(/`([^`\n]+)`/g)].map((m) => m[1] ?? "");
  return [...fenced, ...spans].join("\n");
}

const escape = (s: string) => s.replace(/[$]/g, "\\$");

describe("README export reference", () => {
  const api = publicApi();

  it("finds the exports and methods", () => {
    // A change to how they are found must not make the checks below vacuous.
    expect(api.names).toEqual(expect.arrayContaining(["AttenuoClient", "Token", "SseParser"]));
    expect(api.names.length).toBeGreaterThan(exported.size); // the types are counted too
    expect(api.methods).toEqual(
      expect.arrayContaining(["AdminClient.operatorsReload", "SseParser.feed", "DpopKey.generate"]),
    );
  });

  /** The names in the first column of the section's table (a row may list several). */
  const rows = () =>
    [...exportsSection().matchAll(/^\|([^|\n]*)\|/gm)].flatMap((row) =>
      [...(row[1] ?? "").matchAll(/`([A-Za-z_$][\w$]*)/g)].map((m) => m[1] ?? ""),
    );

  it("lists every export in the table", () => {
    const listed = new Set(rows());
    const missing = api.names.filter((n) => !listed.has(n));
    expect(missing, `exported but not under "${EXPORTS_SECTION}": ${missing.join(", ")}`).toEqual(
      [],
    );
  });

  it("lists only exports", () => {
    const listed = rows();
    expect(listed.length).toBeGreaterThan(0);
    const stale = listed.filter((n) => !api.names.includes(n));
    expect(stale, `listed but not exported: ${stale.join(", ")}`).toEqual([]);
  });

  it("shows every public method in code", () => {
    const code = readmeCode();
    const missing = api.methods.filter((cm) => {
      const m = cm.slice(cm.indexOf(".") + 1);
      return !new RegExp(`(?<![\\w$])${escape(m)}(?![\\w$])`).test(code);
    });
    expect(missing, `public but in no code of the README: ${missing.join(", ")}`).toEqual([]);
  });
});

function runnable(s: Snippet): boolean {
  return (
    (undeclared().get(s) ?? ["?"]).length === 0 &&
    !LOCAL_FILE.test(s.code) &&
    !s.code.includes("@modelcontextprotocol/sdk")
  );
}

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.on("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => ok(port));
    });
  });
}

describe.skipIf(process.env.ATTENUO_INTEGRATION !== "1")(
  "README TypeScript snippets against the example config",
  () => {
    const procs: ChildProcess[] = [];
    let work = "";
    let url = "";

    beforeAll(async () => {
      const bin = process.env.ATTENUO_BIN_DIR ?? join(REPO, ".bin");
      const fake = [join(bin, "examples", "fake_mcp"), join(bin, "fake_mcp")].find(existsSync);
      if (!existsSync(join(bin, "attenuo-server")) || !fake) {
        throw new Error(`attenuo-server / fake_mcp not found in ${bin} (see integration.test.ts)`);
      }
      work = mkdtempSync(join(tmpdir(), "attenuo-readme-it-"));
      copyFileSync(join(bin, "attenuo-server"), join(work, "attenuo-server"));
      copyFileSync(fake, join(work, "fake_mcp"));
      const port = await freePort();
      let mcpPort = await freePort();
      while (mcpPort === port) mcpPort = await freePort();
      let config = readFileSync(join(REPO, "config", "example.toml"), "utf8");
      for (const [from, to] of [
        ['listen = "127.0.0.1:8080"', `listen = "127.0.0.1:${port}"`],
        ["127.0.0.1:3001", `127.0.0.1:${mcpPort}`],
        [
          '"config/policies/default.cedar"',
          JSON.stringify(join(REPO, "config/policies/default.cedar")),
        ],
        ["\nallow_root_mint = false\n", "\nallow_root_mint = true\n"],
      ] as const) {
        if (!config.includes(from)) throw new Error(`not in config/example.toml: ${from}`);
        config = config.replace(from, to);
      }
      mkdirSync(join(work, "data"));
      writeFileSync(join(work, "config.toml"), config);
      const log = createWriteStream(join(work, "server.log"));
      const fakeOut = createWriteStream(join(work, "fake.out"));
      await Promise.all([log, fakeOut].map((s) => new Promise((r) => s.once("open", r))));
      procs.push(
        spawn(join(work, "fake_mcp"), ["--port", String(mcpPort)], {
          cwd: work,
          stdio: ["ignore", fakeOut, log],
        }),
        spawn(join(work, "attenuo-server"), ["--config", "config.toml"], {
          cwd: work,
          stdio: ["ignore", log, log],
          env: { ...process.env, ATTENUO_ADMIN_TOKEN: ADMIN_TOKEN, RUST_LOG: "warn" },
        }),
      );
      url = `http://127.0.0.1:${port}`;
      const deadline = Date.now() + 20_000;
      for (;;) {
        let ready = false;
        try {
          ready = (await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1000) })).ok;
        } catch {
          /* not up yet */
        }
        if (ready && readFileSync(join(work, "fake.out"), "utf8").includes("listening")) break;
        if (procs.some((p) => p.exitCode !== null) || Date.now() > deadline) {
          throw new Error(
            `server did not start:\n${readFileSync(join(work, "server.log"), "utf8")}`,
          );
        }
        await new Promise((r) => setTimeout(r, 100));
      }
    });

    afterAll(async () => {
      for (const p of procs) p.kill("SIGTERM");
      await new Promise((r) => setTimeout(r, 200));
      for (const p of procs) if (p.exitCode === null) p.kill("SIGKILL");
      if (work) rmSync(work, { recursive: true, force: true });
    });

    it("runs the self-contained snippets", async () => {
      const run = ALL.filter(runnable);
      // Both quick starts must stay self-contained, or nothing here runs them.
      expect(run.some((s) => s.id.startsWith("docs/guides/walkthrough.md:"))).toBe(true);
      expect(run.some((s) => s.id.startsWith("sdk/typescript/README.md:"))).toBe(true);
      process.env.ATTENUO_ADMIN_TOKEN = ADMIN_TOKEN;
      process.env.ATTENUO_CLIENT_SECRET = CODER_SECRET;
      const src = pathToFileURL(join(PKG, "src", "index.ts")).href;
      for (const [k, s] of run.entries()) {
        const file = join(work, `run_${k}.ts`);
        writeFileSync(
          file,
          s.code
            .replaceAll('"@attenuo/sdk"', JSON.stringify(src))
            .replaceAll("http://127.0.0.1:8080", url),
        );
        const log = vi.spyOn(console, "log").mockImplementation(() => {});
        try {
          await import(/* @vite-ignore */ pathToFileURL(file).href);
          const printed = log.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
          // The quick starts' denial, as their comments show it.
          if (s.code.includes("create_issue") && s.code.includes("DeniedError")) {
            expect(printed, s.id).toContain("capability_denied");
          }
        } catch (e) {
          throw new Error(`${s.id}: ${String(e)}`, { cause: e });
        } finally {
          log.mockRestore();
        }
      }
    });
  },
);
