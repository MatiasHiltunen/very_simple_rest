import {
  defineService,
  type VsrInput,
  type VsrResource,
  type VsrResourceMapValue,
  type VsrService
} from "../src/index.js";
import type { ResourceInputDocument } from "../src/generated/index";

const postResource: VsrResource = {
  name: "Post",
  api_name: "posts",
  fields: {
    id: { type: "I64", id: true },
    title: { type: "String" },
    body: { type: "String", nullable: true }
  }
};

const generatedShape: VsrInput<ResourceInputDocument> = {
  api_name: "posts"
};

const mappedResource: VsrResourceMapValue = {
  api_name: "posts",
  fields: {
    id: { type: "I64", id: true },
    title: { type: "String" }
  }
};

const service: VsrService = defineService({
  module: "demo_api",
  resources: {
    Post: mappedResource
  }
});

defineService({
  module: service.module,
  resources: {
    Post: postResource
  }
});

void generatedShape;
