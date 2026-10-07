// API Types matching backend schemas

export interface UUID {
  value: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// Organization
export interface Organization {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface OrganizationCreate {
  name: string;
  description?: string;
}

export interface OrganizationUpdate {
  name?: string;
  description?: string;
}

// Project
export interface Project {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  status: ProjectStatus;
  created_at: string;
  updated_at: string;
}

export type ProjectStatus = "draft" | "active" | "paused" | "completed" | "archived";

export interface ProjectCreate {
  name: string;
  description?: string;
  status?: ProjectStatus;
}

export interface ProjectUpdate {
  name?: string;
  description?: string;
  status?: ProjectStatus;
}

export interface ProjectMember {
  id: string;
  project_id: string;
  user_id: string;
  user_email: string;
  user_full_name: string;
  created_at: string;
}

// Scope
export interface Scope {
  id: string;
  project_id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface ScopeDetail extends Scope {
  rules: ScopeRule[];
}

export interface ScopeCreate {
  name: string;
  description?: string;
}

export interface ScopeUpdate {
  name?: string;
  description?: string;
  is_active?: boolean;
}

// Scope Rule
export interface ScopeRule {
  id: string;
  scope_id: string;
  order: number;
  effect: ScopeRuleEffect;
  target_type: ScopeRuleTargetType;
  pattern: string;
  note: string | null;
  created_at: string;
  updated_at: string;
}

export type ScopeRuleEffect = "include" | "exclude";
export type ScopeRuleTargetType = "domain" | "subdomain_pattern" | "ip" | "cidr" | "url" | "api" | "apk" | "other";

export interface ScopeRuleCreate {
  effect: ScopeRuleEffect;
  target_type: ScopeRuleTargetType;
  pattern: string;
  note?: string;
}

export interface ScopeRuleUpdate {
  effect?: ScopeRuleEffect;
  target_type?: ScopeRuleTargetType;
  pattern?: string;
  note?: string;
  order?: number;
}

// Scope Snapshot
export interface ScopeSnapshot {
  id: string;
  scope_id: string;
  version: number;
  payload: Record<string, unknown>;
  created_at: string;
}

// Target
export interface Target {
  id: string;
  project_id: string;
  scope_id: string | null;
  name: string;
  description: string | null;
  scope_status: ScopeStatus;
  target_type: string | null;
  created_at: string;
  updated_at: string;
}

export type ScopeStatus = "in_scope" | "out_of_scope" | "unknown" | "third_party";

export interface TargetCreate {
  name: string;
  description?: string;
  scope_id?: string;
  target_type: "domain" | "subdomain_pattern" | "ip" | "cidr" | "url" | "api" | "apk" | "other";
}

export interface TargetUpdate {
  name?: string;
  description?: string;
  scope_id?: string | null;
  scope_status?: ScopeStatus;
}

export interface TargetStatusUpdate {
  status: ScopeStatus;
}

// Asset
export interface Asset {
  id: string;
  project_id: string;
  kind: AssetKind;
  name: string;
  value: string;
  parent_id: string | null;
  created_at: string;
  updated_at: string;
}

export type AssetKind = "domain" | "subdomain" | "ip_address" | "port" | "url" | "endpoint" | "web_application" | "api_definition" | "apk" | "certificate" | "technology" | "other";

// Finding
export interface Finding {
  id: string;
  project_id: string;
  target_id: string | null;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  created_at: string;
  updated_at: string;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "very_low" | "low" | "medium" | "high" | "very_high";
export type FindingStatus = "open" | "needs_review" | "confirmed" | "false_positive" | "duplicate" | "accepted_risk" | "resolved";

// Scan
export interface Scan {
  id: string;
  project_id: string;
  target_id: string | null;
  initiated_by: string | null;
  name: string;
  scan_type: ScanType;
  status: ScanStatus;
  configuration: Record<string, unknown>;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export type ScanType = "discovery" | "enumeration" | "vulnerability" | "methodology" | "manual" | "other";
export type ScanStatus = "pending" | "running" | "paused" | "completed" | "failed" | "cancelled";

// Scan Progress
export interface ScanProgress {
  scan_id: string;
  status: string;
  progress: number;
  total_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  running_jobs: number;
  queued_jobs: number;
  started_at: string | null;
  finished_at: string | null;
}

// Scan Job
export interface ScanJob {
  id: string;
  scan_id: string;
  name: string;
  status: ScanJobStatus;
  configuration: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
  worker_id: string | null;
}

export type ScanJobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

// Scan Event
export interface ScanEvent {
  id: string;
  scan_id: string;
  scan_job_id: string | null;
  event_type: string;
  level: string;
  message: string;
  payload: Record<string, unknown>;
  occurred_at: string;
}

// Scan Create/Update
export interface ScanCreate {
  name: string;
  scan_type: ScanType;
  target_id?: string;
  configuration?: Record<string, unknown>;
}

export interface ScanUpdate {
  name?: string;
  configuration?: Record<string, unknown>;
}

export interface ScanDetail extends Scan {
  jobs: ScanJob[];
  project?: {
    id: string;
    name: string;
  };
}

// Auth
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  user: User;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  full_name: string;
  password: string;
  organization_name: string;
}

// Error
export interface ApiError {
  error_code: string;
  message: string;
  details?: Record<string, unknown>;
}