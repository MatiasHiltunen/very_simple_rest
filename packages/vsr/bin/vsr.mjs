#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { materializeSchema, rewriteArgsForSchemaConfig } from "../src/config.mjs";
import { resolveNativeInvocation } from "../src/native.mjs";

function firstSubcommand(args) {
  const valueFlags = new Set(["--config", "-c", "--database-url", "-d"]);

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (valueFlags.has(current)) {
      index += 1;
      continue;
    }

    if (!current.startsWith("-")) {
      return current;
    }
  }

  return null;
}

function shouldSkipSchemaMaterialization(args, subcommand) {
  if (!subcommand) {
    return true;
  }

  if (subcommand === "init" || subcommand === "render-schema") {
    return true;
  }

  return args.includes("--help") || args.includes("-h") || args.includes("--version") || args.includes("-V");
}

function hasFormatFlag(args) {
  return args.includes("--format");
}

const originalArgs = process.argv.slice(2);
const subcommand = firstSubcommand(originalArgs);
const nativeInvocation = resolveNativeInvocation();

let forwardedArgs = [...originalArgs];

try {
  if (subcommand === "init" && !hasFormatFlag(forwardedArgs)) {
    forwardedArgs.push("--format", "ts");
  }

  if (!shouldSkipSchemaMaterialization(forwardedArgs, subcommand)) {
    const resolved = rewriteArgsForSchemaConfig(forwardedArgs, process.cwd());
    if (resolved.configPath) {
      await materializeSchema(resolved.configPath, nativeInvocation);
    }
    forwardedArgs = resolved.args;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}

const result = spawnSync(
  nativeInvocation.command,
  [...nativeInvocation.argsPrefix, ...forwardedArgs],
  {
    cwd: nativeInvocation.cwd,
    stdio: "inherit"
  }
);

if (result.error) {
  process.stderr.write(`${result.error.message}\n`);
  process.exit(1);
}

process.exit(result.status ?? 0);
