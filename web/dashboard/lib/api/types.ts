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

// Cloud
export type Node = Schemas["Node"];
export type NodeList = Schemas["NodeList"];
export type Resources = Schemas["Resources"];
export type MetricPoint = Schemas["MetricPoint"];
export type Metrics = Schemas["Metrics"];
export type Flavor = Schemas["Flavor"];
export type FlavorList = Schemas["FlavorList"];
export type Template = Schemas["Template"];
export type TemplateList = Schemas["TemplateList"];
export type Network = Schemas["Network"];
export type NetworkList = Schemas["NetworkList"];
export type NetworkCreate = Schemas["NetworkCreate"];
export type NetworkKind = Schemas["NetworkKind"];
export type Workload = Schemas["Workload"];
export type WorkloadList = Schemas["WorkloadList"];
export type WorkloadCreate = Schemas["WorkloadCreate"];
export type WorkloadState = Schemas["WorkloadState"];
export type WorkloadEventList = Schemas["WorkloadEventList"];
export type QuotaStatus = Schemas["QuotaStatus"];
export type AuditEntry = Schemas["AuditEntry"];
export type AuditPage = Schemas["AuditPage"];
export type AuditVerification = Schemas["AuditVerification"];
