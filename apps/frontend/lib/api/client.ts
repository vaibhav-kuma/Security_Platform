// API Client with React Query hooks

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type {
  Organization,
  OrganizationCreate,
  OrganizationUpdate,
  Project,
  ProjectCreate,
  ProjectUpdate,
  ProjectMember,
  Scope,
  ScopeDetail,
  ScopeCreate,
  ScopeUpdate,
  ScopeRule,
  ScopeRuleCreate,
  ScopeRuleUpdate,
  ScopeSnapshot,
  Target,
  TargetCreate,
  TargetUpdate,
  Asset,
  Finding,
  Scan,
  ScanDetail,
  ScanProgress,
  ScanCreate,
  ScanUpdate,
  ScanType,
  ScanJob,
  TokenResponse,
  LoginRequest,
  RegisterRequest,
  PaginatedResponse,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "/api/v1";

class ApiErrorClass extends Error {
  constructor(
    public status: number,
    public errorCode: string,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    credentials: "include",
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new ApiErrorClass(
      response.status,
      errorData.error?.error_code || "UNKNOWN_ERROR",
      errorData.error?.message || response.statusText,
      errorData.error?.details
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

// Query keys
export const queryKeys = {
  organizations: {
    all: ["organizations"] as const,
    detail: (id: string) => ["organizations", id] as const,
  },
  projects: {
    all: ["projects"] as const,
    list: (orgId: string) => ["projects", orgId] as const,
    detail: (id: string) => ["projects", id] as const,
    members: (projectId: string) => ["projects", projectId, "members"] as const,
  },
  scopes: {
    all: ["scopes"] as const,
    list: (projectId: string) => ["scopes", projectId] as const,
    detail: (id: string) => ["scopes", id] as const,
    rules: (scopeId: string) => ["scopes", scopeId, "rules"] as const,
    snapshots: (scopeId: string) => ["scopes", scopeId, "snapshots"] as const,
  },
  targets: {
    all: ["targets"] as const,
    list: (projectId: string) => ["targets", projectId] as const,
    detail: (id: string) => ["targets", id] as const,
  },
  findings: {
    all: ["findings"] as const,
    list: (projectId: string) => ["findings", projectId] as const,
    detail: (id: string) => ["findings", id] as const,
  },
  scans: {
    all: ["scans"] as const,
    list: (projectId: string) => ["scans", projectId] as const,
    detail: (id: string) => ["scans", id] as const,
  },
  auth: {
    me: ["auth", "me"] as const,
  },
} as const;

// Auth API
export function useLogin() {
  return useMutation({
    mutationFn: (data: LoginRequest) =>
      fetchApi<TokenResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useRegister() {
  return useMutation({
    mutationFn: (data: RegisterRequest) =>
      fetchApi<TokenResponse>("/auth/register", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useLogout() {
  return useMutation({
    mutationFn: () =>
      fetchApi<void>("/auth/logout", { method: "POST" }),
  });
}

export function useRefreshToken() {
  return useMutation({
    mutationFn: () =>
      fetchApi<TokenResponse>("/auth/refresh", { method: "POST" }),
  });
}

// Organization API
export function useOrganizations() {
  return useQuery({
    queryKey: queryKeys.organizations.all,
    queryFn: () => fetchApi<PaginatedResponse<Organization>>("/organizations"),
  });
}

export function useOrganization(id: string) {
  return useQuery({
    queryKey: queryKeys.organizations.detail(id),
    queryFn: () => fetchApi<Organization>(`/organizations/${id}`),
    enabled: !!id,
  });
}

export function useCreateOrganization() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: OrganizationCreate) =>
      fetchApi<Organization>("/organizations", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.organizations.all });
    },
  });
}

export function useUpdateOrganization() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: OrganizationUpdate }) =>
      fetchApi<Organization>(`/organizations/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.organizations.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.organizations.detail(id) });
    },
  });
}

export function useDeleteOrganization() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      fetchApi<void>(`/organizations/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.organizations.all });
    },
  });
}

// Project API
export function useProjects(organizationId: string) {
  return useQuery({
    queryKey: queryKeys.projects.list(organizationId),
    queryFn: () => fetchApi<PaginatedResponse<Project>>(`/organizations/${organizationId}/projects`),
    enabled: !!organizationId,
  });
}

export function useProject(id: string) {
  return useQuery({
    queryKey: queryKeys.projects.detail(id),
    queryFn: () => fetchApi<Project>(`/projects/${id}`),
    enabled: !!id,
  });
}

export function useCreateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ orgId, data }: { orgId: string; data: ProjectCreate }) =>
      fetchApi<Project>(`/organizations/${orgId}/projects`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { orgId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.list(orgId) });
    },
  });
}

export function useUpdateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: ProjectUpdate }) =>
      fetchApi<Project>(`/projects/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.detail(id) });
    },
  });
}

export function useDeleteProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      fetchApi<void>(`/projects/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.all });
    },
  });
}

export function useProjectMembers(projectId: string) {
  return useQuery({
    queryKey: queryKeys.projects.members(projectId),
    queryFn: () => fetchApi<ProjectMember[]>(`/projects/${projectId}/members`),
    enabled: !!projectId,
  });
}

export function useAddProjectMember() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, userId }: { projectId: string; userId: string }) =>
      fetchApi<ProjectMember>(`/projects/${projectId}/members`, {
        method: "POST",
        body: JSON.stringify({ user_id: userId }),
      }),
    onSuccess: (_, { projectId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.members(projectId) });
    },
  });
}

export function useRemoveProjectMember() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, userId }: { projectId: string; userId: string }) =>
      fetchApi<void>(`/projects/${projectId}/members/${userId}`, { method: "DELETE" }),
    onSuccess: (_, { projectId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.members(projectId) });
    },
  });
}

// Scope API
export function useScopes(projectId: string) {
  return useQuery({
    queryKey: queryKeys.scopes.list(projectId),
    queryFn: () => fetchApi<PaginatedResponse<Scope>>(`/projects/${projectId}/scopes`),
    enabled: !!projectId,
  });
}

export function useScope(scopeId: string) {
  return useQuery({
    queryKey: queryKeys.scopes.detail(scopeId),
    queryFn: () => fetchApi<ScopeDetail>(`/scopes/${scopeId}`),
    enabled: !!scopeId,
  });
}

export function useCreateScope() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, data }: { projectId: string; data: ScopeCreate }) =>
      fetchApi<Scope>(`/projects/${projectId}/scopes`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { projectId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.list(projectId) });
    },
  });
}

export function useUpdateScope() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scopeId, data }: { scopeId: string; data: ScopeUpdate }) =>
      fetchApi<Scope>(`/scopes/${scopeId}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { scopeId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.detail(scopeId) });
    },
  });
}

export function useDeleteScope() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scopeId: string) =>
      fetchApi<void>(`/scopes/${scopeId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.all });
    },
  });
}

export function useIncrementScopeVersion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scopeId: string) =>
      fetchApi<Scope>(`/scopes/${scopeId}/version`, { method: "POST" }),
    onSuccess: (_, scopeId) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.detail(scopeId) });
    },
  });
}

// Scope Rules API
export function useScopeRules(scopeId: string) {
  return useQuery({
    queryKey: queryKeys.scopes.rules(scopeId),
    queryFn: () => fetchApi<PaginatedResponse<ScopeRule>>(`/scopes/${scopeId}/rules`),
    enabled: !!scopeId,
  });
}

export function useCreateScopeRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scopeId, data }: { scopeId: string; data: ScopeRuleCreate }) =>
      fetchApi<ScopeRule>(`/scopes/${scopeId}/rules`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { scopeId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.rules(scopeId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.detail(scopeId) });
    },
  });
}

export function useUpdateScopeRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scopeId, ruleId, data }: { scopeId: string; ruleId: string; data: ScopeRuleUpdate }) =>
      fetchApi<ScopeRule>(`/scopes/${scopeId}/rules/${ruleId}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { scopeId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.rules(scopeId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.detail(scopeId) });
    },
  });
}

export function useDeleteScopeRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scopeId, ruleId }: { scopeId: string; ruleId: string }) =>
      fetchApi<void>(`/scopes/${scopeId}/rules/${ruleId}`, { method: "DELETE" }),
    onSuccess: (_, { scopeId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.rules(scopeId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.scopes.detail(scopeId) });
    },
  });
}

// Scope Snapshots API
export function useScopeSnapshots(scopeId: string) {
  return useQuery({
    queryKey: queryKeys.scopes.snapshots(scopeId),
    queryFn: () => fetchApi<ScopeSnapshot[]>(`/scopes/${scopeId}/snapshots`),
    enabled: !!scopeId,
  });
}

export function useScopeSnapshot(scopeId: string, version: number) {
  return useQuery({
    queryKey: [...queryKeys.scopes.snapshots(scopeId), version],
    queryFn: () => fetchApi<ScopeSnapshot>(`/scopes/${scopeId}/snapshots/${version}`),
    enabled: !!scopeId && version > 0,
  });
}

// Target API
export function useTargets(projectId: string, params?: { page?: number; page_size?: number }) {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set("page", params.page.toString());
  if (params?.page_size) searchParams.set("page_size", params.page_size.toString());
  const queryString = searchParams.toString() ? `?${searchParams.toString()}` : "";

  return useQuery({
    queryKey: [...queryKeys.targets.list(projectId), params],
    queryFn: () => fetchApi<PaginatedResponse<Target>>(`/projects/${projectId}/targets${queryString}`),
    enabled: !!projectId,
  });
}

export function useTarget(targetId: string) {
  return useQuery({
    queryKey: queryKeys.targets.detail(targetId),
    queryFn: () => fetchApi<Target>(`/targets/${targetId}`),
    enabled: !!targetId,
  });
}

export function useCreateTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, data }: { projectId: string; data: TargetCreate }) =>
      fetchApi<Target>(`/projects/${projectId}/targets`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { projectId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.targets.list(projectId) });
    },
  });
}

export function useUpdateTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ targetId, data }: { targetId: string; data: TargetUpdate }) =>
      fetchApi<Target>(`/targets/${targetId}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { targetId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.targets.detail(targetId) });
    },
  });
}

export function useDeleteTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (targetId: string) =>
      fetchApi<void>(`/targets/${targetId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.targets.all });
    },
  });
}

// Scope Evaluation API
export function useEvaluateTarget() {
  return useMutation({
    mutationFn: ({ projectId, targetId }: { projectId: string; targetId: string }) =>
      fetchApi<Target>(`/projects/${projectId}/scope/evaluate/${targetId}`, {
        method: "POST",
      }),
  });
}

export function useEvaluateAllTargets() {
  return useMutation({
    mutationFn: ({ projectId }: { projectId: string }) =>
      fetchApi<{
        project_id: string;
        total_evaluated: number;
        status_breakdown: Record<string, number>;
        targets: { id: string; name: string; scope_status: string }[];
      }>(`/projects/${projectId}/scope/evaluate-all`, {
        method: "POST",
      }),
  });
}

export function useEvaluateScopeTargets() {
  return useMutation({
    mutationFn: ({ projectId, scopeId }: { projectId: string; scopeId: string }) =>
      fetchApi<{
        project_id: string;
        scope_id: string;
        total_evaluated: number;
        status_breakdown: Record<string, number>;
        targets: { id: string; name: string; scope_status: string }[];
      }>(`/projects/${projectId}/scope/evaluate-scope/${scopeId}`, {
        method: "POST",
      }),
  });
}

export function useOverrideTargetStatus() {
  return useMutation({
    mutationFn: ({ projectId, targetId, status }: { projectId: string; targetId: string; status: string }) =>
      fetchApi<Target>(`/projects/${projectId}/scope/targets/${targetId}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      }),
  });
}

// Finding API
export function useFindings(projectId: string) {
  return useQuery({
    queryKey: queryKeys.findings.list(projectId),
    queryFn: () => fetchApi<PaginatedResponse<Finding>>(`/projects/${projectId}/findings`),
    enabled: !!projectId,
  });
}

export function useFinding(findingId: string) {
  return useQuery({
    queryKey: queryKeys.findings.detail(findingId),
    queryFn: () => fetchApi<Finding>(`/findings/${findingId}`),
    enabled: !!findingId,
  });
}

// Scan API
export function useScans(projectId: string) {
  return useQuery({
    queryKey: queryKeys.scans.list(projectId),
    queryFn: () => fetchApi<PaginatedResponse<Scan>>(`/projects/${projectId}/scans`),
    enabled: !!projectId,
  });
}

export function useScan(scanId: string) {
  return useQuery({
    queryKey: queryKeys.scans.detail(scanId),
    queryFn: () => fetchApi<ScanDetail>(`/scans/${scanId}`),
    enabled: !!scanId,
  });
}

export function useScanProgress(scanId: string) {
  return useQuery({
    queryKey: [...queryKeys.scans.detail(scanId), "progress"],
    queryFn: () => fetchApi<ScanProgress>(`/scans/${scanId}/progress`),
    enabled: !!scanId,
    refetchInterval: 5000, // Poll every 5 seconds for progress
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, data }: { projectId: string; data: ScanCreate }) =>
      fetchApi<Scan>(`/projects/${projectId}/scans`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { projectId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.list(projectId) });
    },
  });
}

export function useUpdateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scanId, data }: { scanId: string; data: ScanUpdate }) =>
      fetchApi<Scan>(`/scans/${scanId}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { scanId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.detail(scanId) });
    },
  });
}

export function useDeleteScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      fetchApi<void>(`/scans/${scanId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
    },
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      fetchApi<Scan>(`/scans/${scanId}/start`, { method: "POST" }),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.detail(scanId) });
    },
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      fetchApi<Scan>(`/scans/${scanId}/cancel`, { method: "POST" }),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.detail(scanId) });
    },
  });
}

export function usePauseScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      fetchApi<Scan>(`/scans/${scanId}/pause`, { method: "POST" }),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.detail(scanId) });
    },
  });
}

export function useResumeScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      fetchApi<Scan>(`/scans/${scanId}/resume`, { method: "POST" }),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.detail(scanId) });
    },
  });
}

// Asset API
export function useTargetAssets(targetId: string, params?: { page?: number; page_size?: number }) {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set("page", params.page.toString());
  if (params?.page_size) searchParams.set("page_size", params.page_size.toString());
  const queryString = searchParams.toString() ? `?${searchParams.toString()}` : "";

  return useQuery({
    queryKey: [...queryKeys.targets.list(""), "assets", targetId, params],
    queryFn: () => fetchApi<PaginatedResponse<Asset>>(`/targets/${targetId}/assets${queryString}`),
    enabled: !!targetId,
  });
}