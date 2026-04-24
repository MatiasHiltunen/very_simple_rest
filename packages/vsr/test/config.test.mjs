import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, chmod, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

import {
  generatedEonPath,
  loadProjectConfig,
  rewriteArgsForSchemaConfig
} from "../src/config.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defineServiceUrl = pathToFileURL(join(packageRoot, "src", "index.js")).href;

async function withTempProject(run) {
  const root = await mkdtemp(join(tmpdir(), "vsr-config-test-"));

  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function writeConfig(root, exported = "default") {
  const exportLine =
    exported === "default"
      ? "export default defineService(schema);"
      : `export const ${exported} = defineService(schema);`;

  await writeFile(
    join(root, "vsr.config.ts"),
    [
      `import { defineService } from ${JSON.stringify(defineServiceUrl)};`,
      "",
      "const schema = {",
      '  module: "demo_api",',
      "  resources: {",
      "    Post: {",
      '      api_name: "posts",',
      "      fields: {",
      '        id: { type: "I64", id: true },',
      '        title: { type: "String" }',
      "      }",
      "    }",
      "  }",
      "};",
      "",
      exportLine,
      ""
    ].join("\n")
  );
}

async function writeNativeStub(root) {
  const stubPath = join(root, "fake-vsr.mjs");
  await writeFile(
    stubPath,
    [
      "#!/usr/bin/env node",
      'import { existsSync, readFileSync, writeFileSync } from "node:fs";',
      "",
      "const args = process.argv.slice(2);",
      "",
      'if (args[0] === "render-schema") {',
      '  const outputFlagIndex = args.indexOf("--output");',
      "  const outputPath = args[outputFlagIndex + 1];",
      '  let input = "";',
      "  for await (const chunk of process.stdin) {",
      "    input += chunk;",
      "  }",
      "  const service = JSON.parse(input);",
      '  writeFileSync(outputPath, `module: "${service.module}"\\n`);',
      "  process.exit(0);",
      "}",
      "",
      'const configFlagIndex = args.indexOf("--config");',
      'const inputFlagIndex = args.indexOf("--input");',
      "const configPath = configFlagIndex >= 0 ? args[configFlagIndex + 1] : null;",
      "const inputPath = inputFlagIndex >= 0 ? args[inputFlagIndex + 1] : null;",
      "const schemaPath = inputPath ?? configPath;",
      "",
      "if (!configPath || !schemaPath || !existsSync(configPath) || !existsSync(schemaPath)) {",
      '  console.error("missing generated schema");',
      "  process.exit(1);",
      "}",
      "",
      'if (!readFileSync(schemaPath, "utf8").includes(\'module: "demo_api"\')) {',
      '  console.error("unexpected generated schema");',
      "  process.exit(1);",
      "}",
      "",
      "process.exit(0);",
      ""
    ].join("\n")
  );
  await chmod(stubPath, 0o755);
  return stubPath;
}

test("loadProjectConfig reads a TypeScript default export", async () => {
  await withTempProject(async (root) => {
    await writeConfig(root);

    const service = await loadProjectConfig(join(root, "vsr.config.ts"));

    assert.equal(service.module, "demo_api");
    assert.equal(service.resources.Post.api_name, "posts");
    assert.deepEqual(service.resources.Post.fields.id, { type: "I64", id: true });
  });
});

test("loadProjectConfig reads named service exports", async () => {
  await withTempProject(async (root) => {
    await writeConfig(root, "service");

    const service = await loadProjectConfig(join(root, "vsr.config.ts"));

    assert.equal(service.module, "demo_api");
    assert.equal(service.resources.Post.fields.title.type, "String");
  });
});

test("rewriteArgsForSchemaConfig points check commands at the generated api.eon", async () => {
  await withTempProject(async (root) => {
    await writeConfig(root);

    const configPath = join(root, "vsr.config.ts");
    const generatedPath = generatedEonPath(configPath);
    const resolved = rewriteArgsForSchemaConfig(["check", "--strict"], root);

    assert.equal(resolved.configPath, configPath);
    assert.deepEqual(resolved.args, ["--config", generatedPath, "check", "--strict"]);
  });
});

test("rewriteArgsForSchemaConfig rewrites explicit config input paths", () => {
  const root = resolve(tmpdir(), "example-project");
  const configPath = join(root, "vsr.config.ts");
  const generatedPath = generatedEonPath(configPath);
  const resolved = rewriteArgsForSchemaConfig(
    ["check", "--input", "vsr.config.ts", "--strict"],
    root
  );

  assert.equal(resolved.configPath, configPath);
  assert.deepEqual(resolved.args, ["check", "--input", generatedPath, "--strict"]);
});

test("vsr wrapper materializes api.eon before invoking the native binary", async () => {
  await withTempProject(async (root) => {
    await writeConfig(root);
    const stubPath = await writeNativeStub(root);
    const wrapperPath = join(packageRoot, "bin", "vsr.mjs");

    const result = spawnSync(process.execPath, [wrapperPath, "check", "--strict"], {
      cwd: root,
      env: {
        ...process.env,
        VSR_NATIVE_BINARY: stubPath
      },
      encoding: "utf8"
    });

    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});
