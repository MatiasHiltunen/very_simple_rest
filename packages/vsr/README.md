# @matiashiltunen/vsr

TypeScript-first wrapper for `very_simple_rest`.

## Install

```bash
npm install --save-dev @matiashiltunen/vsr typescript
```

## Usage

```ts
import { defineService } from "@matiashiltunen/vsr";

export default defineService({
  module: "demo_api",
  resources: {
    Post: {
      name: "Post",
      api_name: "posts",
      fields: {
        id: { type: "I64", id: true },
        title: { type: "String" }
      }
    }
  }
});
```

The npm wrapper loads `vsr.config.ts/js`, renders a managed `api.eon` beside it, and then delegates to the native `vsr` CLI.
