export type * from "./generated/index";

export type DeepOptional<T> = T extends Array<infer U>
  ? Array<DeepOptional<U>>
  : T extends object
    ? { [K in keyof T]?: DeepOptional<Exclude<T[K], null>> }
    : Exclude<T, null>;

export type VsrInput<T> = DeepOptional<T>;
export type VsrField = VsrInput<import("./generated/FieldInputDocument").FieldInputDocument> & {
  type: import("./generated/FieldTypeDocument").FieldTypeDocument;
};
export type VsrFieldMapValue = import("./generated/FieldTypeDocument").FieldTypeDocument | VsrField;
export type VsrFieldDocuments = Array<VsrField> | Record<string, VsrFieldMapValue>;

export type VsrMixin = VsrInput<Omit<import("./generated/MixinInputDocument").MixinInputDocument, "fields">> & {
  name: string;
  fields: VsrFieldDocuments;
};
export type VsrMixinMapValue =
  | Array<VsrField>
  | (VsrInput<Omit<import("./generated/MixinConfigInputDocument").MixinConfigInputDocument, "fields">> & {
      fields: VsrFieldDocuments;
    });
export type VsrMixinDocuments = Array<VsrMixin> | Record<string, VsrMixinMapValue>;

export type VsrResource = VsrInput<Omit<import("./generated/ResourceInputDocument").ResourceInputDocument, "fields">> & {
  name: string;
  fields: VsrFieldDocuments;
};
export type VsrResourceMapValue =
  VsrInput<Omit<import("./generated/ResourceMapValueInputDocument").ResourceMapValueInputDocument, "fields">> & {
    fields: VsrFieldDocuments;
  };
export type VsrResourceDocuments = Array<VsrResource> | Record<string, VsrResourceMapValue>;

export type VsrService = VsrInput<
  Omit<import("./generated/ServiceInputDocument").ServiceInputDocument, "resources" | "mixins">
> & {
  resources: VsrResourceDocuments;
  mixins?: VsrMixinDocuments;
};

export declare function defineService<const T extends VsrService>(
  service: T
): T;
