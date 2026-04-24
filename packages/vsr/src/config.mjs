import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { tsImport } from "tsx/esm/api";

const SUPPORTED_CONFIG_NAMES = [
  "vsr.config.ts",
  "vsr.config.js",
  "vsr.config.mjs",
  "vsr.config.cjs"
];

function isSupportedConfigPath(value) {
  if (!value) {
    return false;
  }

  return SUPPORTED_CONFIG_NAMES.some((name) => value.endsWith(name));
}

function toAbsoluteConfigPath(value, cwd) {
  return resolve(cwd, value);
}

function hasInputFlag(args) {
  return args.includes("--input") || args.includes("-i");
}

function firstCommandIndex(args) {
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (
      current === "--config" ||
      current === "-c" ||
      current === "--database-url" ||
      current === "-d"
    ) {
      index += 1;
      continue;
    }

    if (!current.startsWith("-")) {
      return index;
    }
  }

  return -1;
}

function injectRequiredInput(args, generatedPathValue) {
  const rewritten = [...args];
  const commandIndex = firstCommandIndex(rewritten);

  if (commandIndex < 0) {
    return rewritten;
  }

  const command = rewritten[commandIndex];
  const subcommand = rewritten[commandIndex + 1];

  if (command === "build") {
    const next = rewritten[commandIndex + 1];
    if (!next || next.startsWith("-")) {
      rewritten.splice(commandIndex + 1, 0, generatedPathValue);
    }
    return rewritten;
  }

  if (hasInputFlag(rewritten)) {
    return rewritten;
  }

  const injectAfter = (offset) => {
    rewritten.splice(commandIndex + offset, 0, "--input", generatedPathValue);
    return rewritten;
  };

  if (command === "openapi") {
    return injectAfter(1);
  }

  if (command === "client" && subcommand === "ts") {
    return injectAfter(2);
  }

  if (command === "server" && ["emit", "expand", "build", "serve"].includes(subcommand)) {
    return injectAfter(2);
  }

  if (command === "migrate" && ["generate", "check", "inspect"].includes(subcommand)) {
    return injectAfter(2);
  }

  return rewritten;
}

export function findProjectConfig(cwd = process.cwd()) {
  for (const name of SUPPORTED_CONFIG_NAMES) {
    const candidate = join(cwd, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

export function generatedEonPath(configPath) {
  return join(dirname(configPath), "api.eon");
}

export function rewriteArgsForSchemaConfig(args, cwd = process.cwd()) {
  const rewritten = [...args];

  for (let index = 0; index < rewritten.length; index += 1) {
    const current = rewritten[index];
    const next = rewritten[index + 1];

    if ((current === "--config" || current === "-c" || current === "--input" || current === "-i") && isSupportedConfigPath(next)) {
      const configPath = toAbsoluteConfigPath(next, cwd);
      const generatedPathValue = generatedEonPath(configPath);
      rewritten[index + 1] = generatedPathValue;
      return {
        args:
          current === "--config" || current === "-c"
            ? injectRequiredInput(rewritten, generatedPathValue)
            : rewritten,
        configPath
      };
    }

    if (!current.startsWith("-") && isSupportedConfigPath(current)) {
      const configPath = toAbsoluteConfigPath(current, cwd);
      rewritten[index] = generatedEonPath(configPath);
      return {
        args: rewritten,
        configPath
      };
    }
  }

  const configPath = findProjectConfig(cwd);
  if (configPath) {
    const generatedPathValue = generatedEonPath(configPath);
    return {
      args: ["--config", generatedPathValue, ...injectRequiredInput(rewritten, generatedPathValue)],
      configPath
    };
  }

  return {
    args: rewritten,
    configPath: null
  };
}

function looksLikeServiceConfig(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      ("resources" in value || "mixins" in value || "module" in value)
  );
}

function unwrapConfigExport(value, visited = new Set()) {
  if (looksLikeServiceConfig(value)) {
    return value;
  }

  if (!value || typeof value !== "object" || visited.has(value)) {
    return undefined;
  }

  visited.add(value);

  for (const key of ["default", "service", "config", "module.exports"]) {
    if (!(key in value)) {
      continue;
    }

    const nested = unwrapConfigExport(value[key], visited);
    if (nested !== undefined) {
      return nested;
    }
  }

  return undefined;
}

export async function loadProjectConfig(configPath) {
  let loaded;

  try {
    loaded = await tsImport(pathToFileURL(configPath).href, import.meta.url);
  } catch (error) {
    throw new Error(
      `failed to load ${configPath}: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const service = unwrapConfigExport(loaded);

  if (service === undefined) {
    throw new Error(`no service export found in ${configPath}`);
  }

  return service;
}

export async function materializeSchema(configPath, nativeInvocation) {
  const service = await loadProjectConfig(configPath);
  const generatedPath = generatedEonPath(configPath);
  const renderResult = spawnSync(
    nativeInvocation.command,
    [...nativeInvocation.argsPrefix, "render-schema", "--output", generatedPath],
    {
      cwd: nativeInvocation.cwd,
      input: JSON.stringify(service),
      encoding: "utf8",
      stdio: ["pipe", "inherit", "inherit"]
    }
  );

  if (renderResult.error) {
    throw renderResult.error;
  }

  if (renderResult.status !== 0) {
    throw new Error(
      `vsr render-schema exited with status ${renderResult.status ?? 1}`
    );
  }

  return generatedPath;
}
