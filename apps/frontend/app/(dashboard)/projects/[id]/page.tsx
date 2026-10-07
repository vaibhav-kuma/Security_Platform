"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Plus, Search, Filter, MoreHorizontal, Edit, Trash2, Eye, Shield, Globe, Target, Users, Key, ChevronRight } from "lucide-react";

export default function ProjectDetailPage() {
  const params = useParams();
  const projectId = params.id as string;

  // This would be replaced with real data from useProject hook
  // For now, we'll show the structure with mock data
  const mockProject = {
    id: projectId,
    name: "E-commerce Platform",
    organization: "Acme Corp",
    status: "active",
    description: "Main e-commerce platform security assessment",
    created_at: "2024-01-15T10:30:00Z",
    updated_at: "2024-01-20T14:22:00Z",
  };

  const [activeTab, setActiveTab] = useState("overview");

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{mockProject.name}</h1>
            <p className="text-muted-foreground">{mockProject.organization} • {mockProject.status}</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" asChild>
              <Link href={`/dashboard/projects/${projectId}/edit`}>
                <Edit className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </Button>
          </div>
        </div>

        {/* Project Info Card */}
        <Card>
          <CardHeader>
            <CardTitle>Project Overview</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label>Description</Label>
                <p className="text-muted-foreground mt-1">{mockProject.description}</p>
              </div>
              <div>
                <Label>Created</Label>
                <p className="text-muted-foreground mt-1">{new Date(mockProject.created_at).toLocaleDateString()}</p>
              </div>
              <div>
                <Label>Last Updated</Label>
                <p className="text-muted-foreground mt-1">{new Date(mockProject.updated_at).toLocaleDateString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Tabs for Scopes, Targets, Members, Scans */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="scopes">Scopes</TabsTrigger>
            <TabsTrigger value="targets">Targets</TabsTrigger>
            <TabsTrigger value="members">Members</TabsTrigger>
            <TabsTrigger value="scans">Scans</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Scopes</p>
                      <p className="text-3xl font-bold">3</p>
                    </div>
                    <Shield className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Targets</p>
                      <p className="text-3xl font-bold">12</p>
                    </div>
                    <Target className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">In Scope</p>
                      <p className="text-3xl font-bold text-green-600">8</p>
                    </div>
                    <Globe className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Active Scans</p>
                      <p className="text-3xl font-bold text-blue-600">2</p>
                    </div>
                    <Users className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="scopes">
            <ScopeManagement projectId={projectId} />
          </TabsContent>

          <TabsContent value="targets">
            <TargetManagement projectId={projectId} />
          </TabsContent>

          <TabsContent value="members">
            <MemberManagement projectId={projectId} />
          </TabsContent>

          <TabsContent value="scans">
            <ScanManagement projectId={projectId} />
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
}

function ScopeManagement({ projectId }: { projectId: string }) {
  const [showCreate, setShowCreate] = useState(false);
  const [newScopeName, setNewScopeName] = useState("");
  const [newScopeDesc, setNewScopeDesc] = useState("");

  const mockScopes = [
    { id: "1", name: "Production Scope", description: "Production environment targets", is_active: true, version: 2, rules_count: 5, created_at: "2024-01-15" },
    { id: "2", name: "Staging Scope", description: "Staging environment targets", is_active: true, version: 1, rules_count: 3, created_at: "2024-01-16" },
    { id: "3", name: "API Scope", description: "API endpoints only", is_active: false, version: 1, rules_count: 2, created_at: "2024-01-17" },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Scopes</h3>
          <p className="text-sm text-muted-foreground">Manage scope definitions and rules</p>
        </div>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Scope
        </Button>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-center">Version</TableHead>
                  <TableHead className="text-center">Rules</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockScopes.map((scope) => (
                  <TableRow key={scope.id}>
                    <TableCell className="font-medium">{scope.name}</TableCell>
                    <TableCell className="text-muted-foreground">{scope.description}</TableCell>
                    <TableCell>
                      <Badge variant={scope.is_active ? "success" : "secondary"}>
                        {scope.is_active ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-center font-mono">v{scope.version}</TableCell>
                    <TableCell className="text-center">{scope.rules_count}</TableCell>
                    <TableCell className="text-muted-foreground">{scope.created_at}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button variant="ghost" size="icon" asChild>
                          <Link href={`/dashboard/projects/${projectId}/scopes/${scope.id}`}>
                            <Eye className="h-4 w-4" />
                          </Link>
                        </Button>
                        <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Create Scope Dialog */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <Card className="w-full max-w-md mx-4">
            <CardHeader>
              <CardTitle>Create New Scope</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="scope-name">Name</Label>
                <Input id="scope-name" value={newScopeName} onChange={(e) => setNewScopeName(e.target.value)} placeholder="e.g., Production Scope" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="scope-desc">Description</Label>
                <Input id="scope-desc" value={newScopeDesc} onChange={(e) => setNewScopeDesc(e.target.value)} placeholder="Optional description" />
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
                <Button onClick={() => { /* create scope */ setShowCreate(false); }}>Create</Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

function TargetManagement({ projectId }: { projectId: string }) {
  const mockTargets = [
    { id: "1", name: "example.com", type: "domain", scope_status: "in_scope", scope: "Production Scope" },
    { id: "2", name: "api.example.com", type: "subdomain", scope_status: "in_scope", scope: "Production Scope" },
    { id: "3", name: "admin.example.com", type: "subdomain", scope_status: "in_scope", scope: "Production Scope" },
    { id: "4", name: "192.168.1.100", type: "ip", scope_status: "out_of_scope", scope: "Production Scope" },
    { id: "5", name: "https://app.example.com/dashboard", type: "url", scope_status: "in_scope", scope: "API Scope" },
  ];

  const getStatusBadge = (status: string) => {
    const variants: Record<string, "default" | "success" | "warning" | "info" | "destructive" | "secondary"> = {
      in_scope: "success",
      out_of_scope: "destructive",
      unknown: "secondary",
      third_party: "warning",
    };
    return <Badge variant={variants[status] || "default"}>{status.replace("_", " ")}</Badge>;
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "domain":
        return <Globe className="h-4 w-4" />;
      case "subdomain":
        return <Shield className="h-4 w-4" />;
      case "ip":
        return <Target className="h-4 w-4" />;
      case "url":
        return <Globe className="h-4 w-4" />;
      default:
        return <Target className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Targets</h3>
          <p className="text-sm text-muted-foreground">Manage assessment targets</p>
        </div>
        <Button asChild>
          <Link href={`/dashboard/projects/${projectId}/targets/new`}>
            <Plus className="mr-2 h-4 w-4" />
            Add Target
          </Link>
        </Button>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Scope Status</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockTargets.map((target) => (
                  <TableRow key={target.id}>
                    <TableCell className="font-medium font-mono text-sm">{target.name}</TableCell>
                    <TableCell>
                      <span className="flex items-center gap-2 text-muted-foreground">
                        {getTypeIcon(target.type)}
                        {target.type}
                      </span>
                    </TableCell>
                    <TableCell>{getStatusBadge(target.scope_status)}</TableCell>
                    <TableCell>{target.scope}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button variant="ghost" size="icon" asChild>
                          <Link href={`/dashboard/targets/${target.id}`}>
                            <Eye className="h-4 w-4" />
                          </Link>
                        </Button>
                        <Button variant="ghost" size="icon" asChild>
                          <Link href={`/dashboard/targets/${target.id}/edit`}>
                            <Edit className="h-4 w-4" />
                          </Link>
                        </Button>
                        <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function MemberManagement({ projectId }: { projectId: string }) {
  const mockMembers = [
    { id: "1", name: "John Doe", email: "john@acme.com", role: "admin", joined: "2024-01-15" },
    { id: "2", name: "Jane Smith", email: "jane@acme.com", role: "tester", joined: "2024-01-16" },
    { id: "3", name: "Bob Wilson", email: "bob@acme.com", role: "viewer", joined: "2024-01-17" },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Project Members</h3>
          <p className="text-sm text-muted-foreground">Manage project access and roles</p>
        </div>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          Add Member
        </Button>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Member</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Joined</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockMembers.map((member) => (
                  <TableRow key={member.id}>
                    <TableCell className="font-medium">{member.name}</TableCell>
                    <TableCell>{member.email}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-capitalize">{member.role}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{member.joined}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive">
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ScanManagement({ projectId }: { projectId: string }) {
  const mockScans = [
    { id: "1", name: "Full Vulnerability Scan", type: "vulnerability", status: "completed", progress: 100, findings: 12 },
    { id: "2", name: "API Discovery", type: "discovery", status: "running", progress: 65, findings: 0 },
    { id: "3", name: "Subdomain Enumeration", type: "enumeration", status: "pending", progress: 0, findings: 0 },
  ];

  const getStatusBadge = (status: string) => {
    const variants: Record<string, "default" | "success" | "warning" | "info" | "destructive" | "secondary"> = {
      completed: "success",
      running: "info",
      pending: "secondary",
      failed: "destructive",
      cancelled: "warning",
    };
    return <Badge variant={variants[status] || "default"}>{status}</Badge>;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Scans</h3>
          <p className="text-sm text-muted-foreground">Manage and monitor security scans</p>
        </div>
        <Button asChild>
          <Link href={`/dashboard/projects/${projectId}/scans/new`}>
            <Plus className="mr-2 h-4 w-4" />
            New Scan
          </Link>
        </Button>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Progress</TableHead>
                  <TableHead className="text-right">Findings</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockScans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell className="font-medium">{scan.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{scan.type}</Badge>
                    </TableCell>
                    <TableCell>{getStatusBadge(scan.status)}</TableCell>
                    <TableCell>
                      <div className="w-32">
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                          <div className="h-full bg-primary transition-all duration-300" style={{ width: `${scan.progress}%` }} />
                        </div>
                        <span className="text-xs text-muted-foreground">{scan.progress}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-mono">{scan.findings}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button variant="ghost" size="icon" asChild>
                          <Link href={`/dashboard/scans/${scan.id}`}>
                            <Eye className="h-4 w-4" />
                          </Link>
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}