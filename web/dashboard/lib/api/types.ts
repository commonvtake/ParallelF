// Named aliases for the generated OpenAPI types (api/openapi/parallelf.v1.yaml).

import type { components } from "./schema.gen";

type Schemas = components["schemas"];

export type Me = Schemas["Me"];
export type Project = Schemas["Project"];
export type ProjectPage = Schemas["ProjectPage"];
export type ProjectCreate = Schemas["ProjectCreate"];
export type SystemStatus = Schemas["SystemStatus"];
export type Component = Schemas["Component"];
export type AIInfo = Schemas["AIInfo"];
export type Capability = Schemas["Capability"];
