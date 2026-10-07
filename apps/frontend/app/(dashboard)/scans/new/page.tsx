"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Plus, Shield, AlertTriangle, CheckCircle, XCircle, ChevronRight, Play, Settings, Eye, Target, FolderKanban } from "lucide-react";
import { useProjects, useCreateProject } from "@/lib/api/client";
import { useTargets, useCreateTarget } from "@/lib/api/client";
import { useScopes, useCreateScope } from "@/lib/api/client";
import { useCreateScan } from "@/lib/api/client";
import { useEvaluateTarget } from "@/lib/api/client";
import { cn } from "@/lib/utils";
import type { ScanType } from "@/lib/api/types";

export default function NewScanPage() {
  const router = useRouter();
  const [step, setStep] = useState<"project" | "target" | "scope" | "confirm">("project");
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedScopeId, setSelectedScopeId] = useState("");
  const [scanName, setScanName] = useState("");
  const [scanType, setScanType] = useState<ScanType>("vulnerability");
  const [configuration, setConfiguration] = useState<Record<string, unknown>>({});

  // Fetch projects
  const { data: projectsData, isLoading: projectsLoading } = useProjects("1");
  const { data: targetsData, isLoading: targetsLoading } = useTargets(selectedProjectId);
  const { data: scopesData, isLoading: scopesLoading } = useScopes(selectedProjectId);

  const createScan = useCreateScan();
  const evaluateTarget = useEvaluateTarget();

  const handleNext = () => {
    if (step === "project" && selectedProjectId) setStep("target");
    else if (step === "target" && selectedTargetId) setStep("scope");
    else if (step === "scope") setStep("confirm");
  };

  const handleBack = () => {
    if (step === "confirm") setStep("scope");
    else if (step === "scope") setStep("target");
    else if (step === "target") setStep("project");
  };

  const handleSubmit = async () => {
    try {
      await createScan.mutateAsync({
        projectId: selectedProjectId,
        data: {
          name: scanName,
          scan_type: scanType,
          target_id: selectedTargetId || undefined,
          configuration,
        },
      });
      router.push(`/dashboard/projects/${selectedProjectId}/scans`);
    } catch (error: unknown) {
      console.error("Failed to create scan:", error);
    }
  };

  // Scope evaluation for selected target
  const [scopeEvaluation, setScopeEvaluation] = useState<{
    target_id: string;
    scope_status: string;
    in_scope: boolean;
  } | null>(null);

  const handleEvaluateTarget = async (targetId: string) => {
    if (!selectedProjectId) return;
    try {
      const result = await evaluateTarget.mutateAsync({ projectId: selectedProjectId, targetId });
      setScopeEvaluation({
        target_id: result.id,
        scope_status: result.scope_status,
        in_scope: result.scope_status === "in_scope",
      });
    } catch (error: unknown) {
      console.error("Failed to evaluate target:", error);
    }
  };

  if (projectsLoading) {
    return (
      <DashboardLayout>
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </DashboardLayout>
    );
  }

  const projects = projectsData?.items || [];

  return (
    <DashboardLayout>
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Progress Indicator */}
        <div className="flex items-center justify-between">
          {["project", "target", "scope", "confirm"].map((s, i) => (
            <div key={s} className="flex items-center">
              <div
                className={cn(
                  "w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium",
                  step === s || (["project", "target", "scope", "confirm"].indexOf(step) > i)
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted text-muted-foreground"
                )}
              >
                {["project", "target", "scope", "confirm"].indexOf(step) > i ? (
                  <CheckCircle className="h-5 w-5" />
                ) : (
                  i + 1
                )}
              </div>
              {i < 3 && (
                <div
                  className={cn(
                    "w-16 h-0.5 mx-2",
                    ["project", "target", "scope", "confirm"].indexOf(step) > i
                      ? "bg-primary"
                      : "bg-muted"
                  )}
                />
              )}
              <span className={cn("text-sm font-medium hidden sm:block", step === s ? "text-primary" : "text-muted-foreground")}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </span>
            </div>
          ))}
        </div>

        {/* Step Content */}
        <Card className="space-y-0">
          <CardHeader>
            <CardTitle>Create New Scan</CardTitle>
            <CardDescription>
              {step === "project" && "Select the project for this scan"}
              {step === "target" && "Choose the target to scan"}
              {step === "scope" && "Select the applicable scope"}
              {step === "confirm" && "Review and confirm scan configuration"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {step === "project" && (
              <ProjectSelectionStep
                projects={projects}
                selectedProjectId={selectedProjectId}
                onSelectProject={setSelectedProjectId}
              />
            )}

            {step === "target" && (
              <TargetSelectionStep
                projectId={selectedProjectId}
                targets={targetsData?.items || []}
                isLoading={targetsLoading}
                selectedTargetId={selectedTargetId}
                onSelectTarget={setSelectedTargetId}
                onEvaluate={handleEvaluateTarget}
                scopeEvaluation={scopeEvaluation}
              />
            )}

            {step === "scope" && (
              <ScopeSelectionStep
                projectId={selectedProjectId}
                scopes={scopesData?.items || []}
                isLoading={scopesLoading}
                selectedScopeId={selectedScopeId}
                onSelectScope={setSelectedScopeId}
              />
            )}

            {step === "confirm" && (
              <ConfirmStep
                projectId={selectedProjectId}
                projectName={projects.find((p) => p.id === selectedProjectId)?.name || ""}
                targetName={targetsData?.items.find((t) => t.id === selectedTargetId)?.name || "All targets in project"}
                scopeName={scopesData?.items.find((s) => s.id === selectedScopeId)?.name || "Default scope"}
                scanName={scanName}
                setScanName={setScanName}
                scanType={scanType}
                setScanType={setScanType}
                _configuration={configuration}
                _setConfiguration={setConfiguration}
              />
            )}

            {/* Navigation */}
            <div className="flex justify-between pt-4 border-t">
              <Button variant="outline" onClick={handleBack} disabled={step === "project"}>
                Back
              </Button>
              {step === "confirm" ? (
                <Button onClick={handleSubmit} disabled={createScan.isPending || !scanName}>
                  {createScan.isPending ? "Creating..." : "Create Scan"}
                </Button>
              ) : (
                <Button
                  onClick={handleNext}
                  disabled={
                    (step === "project" && !selectedProjectId) ||
                    (step === "target" && !selectedTargetId) ||
                    (step === "scope" && !selectedScopeId)
                  }
                >
                  Next
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}

function ProjectSelectionStep({
  projects,
  selectedProjectId,
  onSelectProject,
}: {
  projects: { id: string; name: string; status: string }[];
  selectedProjectId: string;
  onSelectProject: (id: string) => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-muted-foreground">Select the project this scan belongs to.</p>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {projects.map((project) => (
          <Button
            key={project.id}
            variant={selectedProjectId === project.id ? "default" : "outline"}
            className={cn("w-full h-24 flex-col items-start text-left gap-2", selectedProjectId === project.id && "border-primary")}
            onClick={() => onSelectProject(project.id)}
          >
            <div className="flex items-center gap-2">
              <FolderKanban className="h-5 w-5" />
              <span className="font-medium">{project.name}</span>
            </div>
            <p className="text-sm text-muted-foreground">{project.status}</p>
            {selectedProjectId === project.id && <CheckCircle className="h-4 w-4 text-primary" />}
          </Button>
        ))}
      </div>
    </div>
  );
}

function TargetSelectionStep({
  projectId,
  targets,
  isLoading,
  selectedTargetId,
  onSelectTarget,
  onEvaluate,
  scopeEvaluation,
}: {
  projectId: string;
  targets: { id: string; name: string; target_type: string | null; scope_status: string }[];
  isLoading: boolean;
  selectedTargetId: string;
  onSelectTarget: (id: string) => void;
  onEvaluate: (id: string) => void;
  scopeEvaluation: { target_id: string; scope_status: string; in_scope: boolean } | null;
}) {
  const getStatusBadge = (status: string) => {
    const variants: Record<string, "default" | "success" | "warning" | "info" | "destructive" | "secondary"> = {
      in_scope: "success",
      out_of_scope: "destructive",
      unknown: "secondary",
      third_party: "warning",
    };
    return <Badge variant={variants[status] || "default"}>{status.replace("_", " ")}</Badge>;
  };

  const getTypeIcon = (type: string | null) => {
    switch (type) {
      case "domain":
        return <Target className="h-4 w-4" />;
      case "subdomain":
      case "subdomain_pattern":
        return <Shield className="h-4 w-4" />;
      case "ip":
        return <Target className="h-4 w-4" />;
      case "url":
        return <Target className="h-4 w-4" />;
      default:
        return <Target className="h-4 w-4" />;
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-muted-foreground">Select the target to scan. Use scope evaluation to verify authorization.</p>

      {/* Scope Evaluation Preview */}
      {scopeEvaluation && (
        <Alert className={cn(scopeEvaluation.in_scope ? "border-green-500 bg-green-50" : "border-destructive/20 bg-destructive/10")}>
          <AlertTitle className="flex items-center gap-2">
            {scopeEvaluation.in_scope ? (
              <CheckCircle className="h-4 w-4 text-green-600" />
            ) : (
              <XCircle className="h-4 w-4 text-destructive" />
            )}
            Scope Evaluation Result
          </AlertTitle>
          <AlertDescription>
            Target <strong>{scopeEvaluation.target_id}</strong> is <strong>{scopeEvaluation.scope_status.replace("_", " ")}</strong>.
            {scopeEvaluation.in_scope
              ? " This target is authorized for testing."
              : " This target is NOT authorized for testing. Scan will be blocked."}
          </AlertDescription>
        </Alert>
      )}

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Scope Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {targets.map((target) => (
              <TableRow key={target.id}>
                <TableCell className="font-medium font-mono text-sm">{target.name}</TableCell>
                <TableCell>
                  <span className="flex items-center gap-2 text-muted-foreground">
                    {getTypeIcon(target.target_type)}
                    {target.target_type || "unknown"}
                  </span>
                </TableCell>
                <TableCell>{getStatusBadge(target.scope_status)}</TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => onEvaluate(target.id)}>
                      <Eye className="mr-1 h-3 w-3" />
                      Check Scope
                    </Button>
                    <Button
                      variant={selectedTargetId === target.id ? "default" : "ghost"}
                      size="sm"
                      onClick={() => onSelectTarget(target.id)}
                    >
                      {selectedTargetId === target.id ? "Selected" : "Select"}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
            {targets.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                  No targets found.{" "}
                  <a href={`/dashboard/projects/${projectId}/targets/new`} className="text-primary underline">
                    Add a target
                  </a>{" "}
                  first.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function ScopeSelectionStep({
  projectId,
  scopes,
  isLoading,
  selectedScopeId,
  onSelectScope,
}: {
  projectId: string;
  scopes: { id: string; name: string; description: string | null; version: number; is_active: boolean }[];
  isLoading: boolean;
  selectedScopeId: string;
  onSelectScope: (id: string) => void;
}) {
  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-muted-foreground">Select the scope that defines the authorization boundary for this scan.</p>
      <div className="grid gap-4 md:grid-cols-2">
        {scopes.map((scope) => (
          <Button
            key={scope.id}
            variant={selectedScopeId === scope.id ? "default" : "outline"}
            className={cn("w-full h-24 flex-col items-start text-left gap-2", selectedScopeId === scope.id && "border-primary")}
            onClick={() => onSelectScope(scope.id)}
          >
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              <span className="font-medium">{scope.name}</span>
            </div>
            <p className="text-sm text-muted-foreground">{scope.description || "No description"}</p>
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <span>v{scope.version}</span>
              <Badge variant={scope.is_active ? "success" : "secondary"}>
                {scope.is_active ? "Active" : "Inactive"}
              </Badge>
            </div>
            {selectedScopeId === scope.id && <CheckCircle className="h-4 w-4 text-primary" />}
          </Button>
        ))}
      </div>
      {scopes.length === 0 && (
        <Alert>
          <AlertTitle>No scopes available</AlertTitle>
          <AlertDescription>
            Create a scope first to define the authorization boundary for your scan.
            <a href={`/dashboard/projects/${projectId}/scopes/new`} className="ml-2 text-primary underline">
              Create scope
            </a>
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

function ConfirmStep({
  projectId,
  projectName,
  targetName,
  scopeName,
  scanName,
  setScanName,
  scanType,
  setScanType,
  _configuration,
  _setConfiguration,
}: {
  projectId: string;
  projectName: string;
  targetName: string;
  scopeName: string;
  scanName: string;
  setScanName: (name: string) => void;
  scanType: ScanType;
  setScanType: (type: ScanType) => void;
  _configuration: Record<string, unknown>;
  _setConfiguration: (config: Record<string, unknown>) => void;
}) {
  return (
    <div className="space-y-6">
      {/* Security Confirmation */}
      <Alert className="border-amber-500 bg-amber-50">
        <AlertTitle className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-600" />
          Security Confirmation Required
        </AlertTitle>
        <AlertDescription>
          <p className="mb-2">Please verify the following before starting this scan:</p>
          <ul className="list-disc list-inside space-y-1 text-sm">
            <li>You have explicit written authorization to test the selected target(s)</li>
            <li>The scope rules correctly define the authorized testing boundary</li>
            <li>Rate limits and testing profiles are configured appropriately</li>
            <li>All findings will be reported through the proper channels</li>
          </ul>
        </AlertDescription>
      </Alert>

      {/* Scan Configuration */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              Scan Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="scan-name">Scan Name</Label>
              <Input
                id="scan-name"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="e.g., Q1 Vulnerability Assessment"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="scan-type">Scan Type</Label>
              <Select value={scanType} onValueChange={(value: string) => setScanType(value as ScanType)}>
                <SelectTrigger id="scan-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="vulnerability">Vulnerability Scan</SelectItem>
                  <SelectItem value="discovery">Discovery</SelectItem>
                  <SelectItem value="enumeration">Enumeration</SelectItem>
                  <SelectItem value="methodology">Methodology-based</SelectItem>
                  <SelectItem value="manual">Manual Testing</SelectItem>
                  <SelectItem value="other">Other</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Authorization Summary
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div>
                <Label>Project</Label>
                <p className="font-medium">{projectName}</p>
              </div>
              <div>
                <Label>Target</Label>
                <p className="font-medium font-mono text-sm">{targetName}</p>
              </div>
              <div>
                <Label>Scope</Label>
                <p className="font-medium">{scopeName}</p>
              </div>
              <div>
                <Label>Scan Type</Label>
                <Badge variant="outline">{scanType}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Final Confirmation */}
      <div className="p-4 bg-muted/50 rounded-lg">
        <p className="text-sm text-muted-foreground">
          By creating this scan, you confirm that you have explicit authorization to test the selected targets
          within the defined scope. Unauthorized testing is prohibited and may violate laws and policies.
        </p>
      </div>
    </div>
  );
}