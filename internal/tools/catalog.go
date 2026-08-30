// Package tools declares the capabilities the harness can invoke.
//
// # What is here in Phase 6, and what is not
//
// The *declarations* are here: every tool, every action, and the exact shape of
// each action's parameters. The *implementations* are not — they arrive in
// Phase 7.
//
// That split is deliberate rather than a convenience. The declaration is what
// the harness validates against, and it is the contract three other things are
// already written against: the permission matrix in migration 0004 names these
// tool/action pairs, the policy table tiers them, and the agents propose them.
// Writing the descriptors first means those four sources can be reconciled
// against each other — see [harness.PolicyEngine.ReconcileTools] — before any
// code exists that can actually restart a container.
//
// # Why the parameter constraints are this tight
//
// Every value here is assembled by a language model and ends up as an argument
// to an infrastructure call. A container name is constrained to Docker's own
// character class not because Docker would reject anything else, but because a
// name is the one field a model most easily fills with something that is not a
// name. The constraint is the difference between a rejected tool call and a
// value travelling somewhere it will be interpreted.
//
// Nothing in `internal/agents` may import this package. Agents describe tool
// calls; only the harness holds things that can run them.
package tools

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// Common parameter shapes, defined once so the same constraint cannot drift
// between two actions that mean the same thing by "container".
var (
	// containerName matches Docker's own naming rules.
	containerName = ports.ParamSpec{
		Kind: ports.ParamString, Required: true, MaxLen: 255,
		Description: "container name or ID",
		Pattern:     `[a-zA-Z0-9][a-zA-Z0-9_.-]*`,
	}
	// k8sName matches RFC 1123 label rules, which Kubernetes enforces for
	// object names.
	k8sName = ports.ParamSpec{
		Kind: ports.ParamString, Required: true, MaxLen: 253,
		Description: "Kubernetes object name",
		Pattern:     `[a-z0-9]([-a-z0-9]*[a-z0-9])?`,
	}
	k8sNamespace = ports.ParamSpec{
		Kind: ports.ParamString, Required: false, MaxLen: 253,
		Description: "Kubernetes namespace", Default: "default",
		Pattern: `[a-z0-9]([-a-z0-9]*[a-z0-9])?`,
	}
	tailLines = ports.ParamSpec{
		Kind: ports.ParamInt, Required: false, Default: int64(200),
		Description: "how many trailing log lines to read",
		Min:         1, Max: 10000,
	}
	// absolutePath and relativePath forbid parent traversal.
	//
	// Every segment must *start* with an alphanumeric or underscore, which makes
	// "." and ".." unrepresentable as segments. Written that way because Go's
	// RE2 has no negative lookahead, so "any segment that is not .." cannot be
	// expressed directly — and because an allowlist of leading characters cannot
	// be widened by an encoding trick the way a blocklist of sequences can.
	//
	// The cost is that dotfiles are unreadable. For a tool that reads logs and
	// configuration during an incident that is an acceptable trade, and a
	// deliberate one: the earlier pattern here allowed "." inside a segment and
	// therefore accepted /var/log/../../etc/shadow, which is exactly the value
	// this constraint exists to stop.
	pathSegment    = `[a-zA-Z0-9_][a-zA-Z0-9_.-]*`
	absolutePathRE = `/(` + pathSegment + `/)*` + pathSegment
	relativePathRE = `(` + pathSegment + `/)*` + pathSegment

	// serviceName matches systemd unit naming.
	serviceName = ports.ParamSpec{
		Kind: ports.ParamString, Required: true, MaxLen: 255,
		Description: "systemd unit name",
		Pattern:     `[a-zA-Z0-9][a-zA-Z0-9_.@-]*`,
	}
)

// Docker declares the container tool.
func Docker() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name:        "docker",
		Description: "Inspect and manage containers on a Docker host.",
		Actions: map[string]ports.ActionDescriptor{
			"list_containers": {
				Description: "List containers and their state.",
				Params: map[string]ports.ParamSpec{
					"all": {Kind: ports.ParamBool, Description: "include stopped containers", Default: false},
				},
			},
			"inspect_container": {
				Description: "Return a container's full configuration and state.",
				Params:      map[string]ports.ParamSpec{"container": containerName},
			},
			"logs": {
				Description: "Read a container's recent logs.",
				Params: map[string]ports.ParamSpec{
					"container": containerName,
					"tail":      tailLines,
				},
			},
			"restart_container": {
				Description: "Restart a container.",
				Mutating:    true,
				Timeout:     2 * time.Minute,
				Params: map[string]ports.ParamSpec{
					"container": containerName,
					"timeout_seconds": {
						Kind: ports.ParamInt, Description: "grace period before SIGKILL",
						Default: int64(10), Min: 1, Max: 300,
					},
				},
			},
			"start_container": {
				Description: "Start a stopped container.",
				Mutating:    true,
				Params:      map[string]ports.ParamSpec{"container": containerName},
			},
			// Declared so the forbidden tier has something to refuse.
			//
			// A forbidden action that does not appear in the registry would be
			// rejected as *unknown*, which reads in an audit log as "the model
			// invented an action". Declaring it means the ledger records the
			// truth: the model asked for a real, destructive thing, and policy
			// refused it. Those two entries mean very different things about
			// whether the model has drifted.
			"delete_volume": {
				Description: "Delete a volume. Forbidden — declared so the refusal is explicit.",
				Mutating:    true,
				Params:      map[string]ports.ParamSpec{"volume": containerName},
			},
		},
	}
}

// Kubernetes declares the cluster tool.
func Kubernetes() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name:        "kubernetes",
		Description: "Inspect and manage workloads on a Kubernetes cluster.",
		Actions: map[string]ports.ActionDescriptor{
			"get_pods": {
				Description: "List pods and their phase.",
				Params: map[string]ports.ParamSpec{
					"namespace": k8sNamespace,
					"selector": {Kind: ports.ParamString, MaxLen: 512,
						Description: "label selector"},
				},
			},
			"describe_pod": {
				Description: "Return a pod's events and conditions.",
				Params:      map[string]ports.ParamSpec{"pod": k8sName, "namespace": k8sNamespace},
			},
			"logs": {
				Description: "Read a pod's recent logs.",
				Params: map[string]ports.ParamSpec{
					"pod": k8sName, "namespace": k8sNamespace, "tail": tailLines,
					"previous": {Kind: ports.ParamBool, Default: false,
						Description: "read the previous container's logs, which is where an OOMKill leaves its evidence"},
				},
			},
			"restart_deployment": {
				Description: "Trigger a rolling restart.",
				Mutating:    true, Timeout: 5 * time.Minute,
				Params: map[string]ports.ParamSpec{"deployment": k8sName, "namespace": k8sNamespace},
			},
			"scale_deployment": {
				Description: "Change a deployment's replica count.",
				Mutating:    true, Timeout: 5 * time.Minute,
				Params: map[string]ports.ParamSpec{
					"deployment": k8sName, "namespace": k8sNamespace,
					"replicas": {Kind: ports.ParamInt, Required: true, Min: 0, Max: 1000,
						Description: "desired replica count"},
				},
			},
			"rollback_deployment": {
				Description: "Roll a deployment back to its previous revision.",
				Mutating:    true, Timeout: 10 * time.Minute,
				Params: map[string]ports.ParamSpec{"deployment": k8sName, "namespace": k8sNamespace},
			},
			"delete_namespace": {
				Description: "Delete a namespace. Forbidden — declared so the refusal is explicit.",
				Mutating:    true,
				Params:      map[string]ports.ParamSpec{"namespace": k8sName},
			},
		},
	}
}

// Linux declares the host tool.
func Linux() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name:        "linux",
		Description: "Read host state and manage services.",
		Actions: map[string]ports.ActionDescriptor{
			"read_metrics": {
				Description: "Read CPU, memory and disk utilisation.",
				Params: map[string]ports.ParamSpec{
					"host": {Kind: ports.ParamString, MaxLen: 253,
						Description: "host to read", Pattern: `[a-zA-Z0-9]([-a-zA-Z0-9.]*[a-zA-Z0-9])?`},
				},
			},
			"read_file": {
				Description: "Read a file from an allowlisted path.",
				Params: map[string]ports.ParamSpec{
					// Absolute paths only, with no parent traversal. See
					// absolutePathRE for why the constraint is expressed as a
					// leading-character allowlist.
					"path": {Kind: ports.ParamString, Required: true, MaxLen: 4096,
						Description: "absolute path, no parent traversal",
						Pattern:     absolutePathRE},
					"tail": tailLines,
				},
			},
			"restart_service": {
				Description: "Restart a systemd unit.",
				Mutating:    true, Timeout: 2 * time.Minute,
				Params: map[string]ports.ParamSpec{"service": serviceName},
			},
		},
	}
}

// Monitoring declares the metrics tool.
func Monitoring() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name:        "monitoring",
		Description: "Query the metrics backend.",
		Actions: map[string]ports.ActionDescriptor{
			"query": {
				Description: "Run an instant query.",
				Params: map[string]ports.ParamSpec{
					"query": {Kind: ports.ParamString, Required: true, MaxLen: 4096,
						Description: "PromQL expression"},
				},
			},
			"query_range": {
				Description: "Run a range query.",
				Params: map[string]ports.ParamSpec{
					"query": {Kind: ports.ParamString, Required: true, MaxLen: 4096,
						Description: "PromQL expression"},
					"minutes": {Kind: ports.ParamInt, Default: int64(30), Min: 1, Max: 10080,
						Description: "how far back to look"},
				},
			},
			"alerts": {
				Description: "List firing alerts.",
				Params:      map[string]ports.ParamSpec{},
			},
		},
	}
}

// Security declares the inspection tool.
func Security() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name:        "security",
		Description: "Inspect images and configuration for known weaknesses.",
		Actions: map[string]ports.ActionDescriptor{
			"scan_image": {
				Description: "Scan a container image for known vulnerabilities.",
				Timeout:     5 * time.Minute,
				Params: map[string]ports.ParamSpec{
					"image": {Kind: ports.ParamString, Required: true, MaxLen: 512,
						Description: "image reference",
						Pattern:     `[a-zA-Z0-9][a-zA-Z0-9_.:/@-]*`},
				},
			},
			"check_config": {
				Description: "Check a workload's security configuration.",
				Params:      map[string]ports.ParamSpec{"target": k8sName, "namespace": k8sNamespace},
			},
		},
	}
}

// Git declares the repository tool.
func Git() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name:        "git",
		Description: "Read repository history to correlate incidents with changes.",
		Actions: map[string]ports.ActionDescriptor{
			"diff": {
				Description: "Show what changed between two revisions.",
				Params: map[string]ports.ParamSpec{
					"from": {Kind: ports.ParamString, Required: true, MaxLen: 100,
						Description: "base revision", Pattern: `[a-zA-Z0-9_./~^-]+`},
					"to": {Kind: ports.ParamString, MaxLen: 100, Default: "HEAD",
						Description: "target revision", Pattern: `[a-zA-Z0-9_./~^-]+`},
				},
			},
			"read": {
				Description: "Read a file at a revision.",
				Params: map[string]ports.ParamSpec{
					"path": {Kind: ports.ParamString, Required: true, MaxLen: 4096,
						Description: "repository-relative path, no parent traversal",
						Pattern:     relativePathRE},
					"revision": {Kind: ports.ParamString, MaxLen: 100, Default: "HEAD",
						Description: "revision to read at", Pattern: `[a-zA-Z0-9_./~^-]+`},
				},
			},
		},
	}
}

// Database declares the database tool.
//
// Every action here is either high risk or forbidden. Declared anyway, for the
// same reason as docker.delete_volume: the ledger should record that a model
// asked for something real and destructive, not that it invented a word.
func Database() ports.ToolDescriptor {
	table := ports.ParamSpec{
		Kind: ports.ParamString, Required: true, MaxLen: 128,
		Description: "table name", Pattern: `[a-zA-Z_][a-zA-Z0-9_]*`,
	}
	return ports.ToolDescriptor{
		Name:        "database",
		Description: "Manage database instances. Mostly forbidden by policy.",
		Actions: map[string]ports.ActionDescriptor{
			"restart": {
				Description: "Restart a database instance.",
				Mutating:    true, Timeout: 10 * time.Minute,
				Params: map[string]ports.ParamSpec{
					"instance": {Kind: ports.ParamString, Required: true, MaxLen: 255,
						Description: "instance identifier", Pattern: `[a-zA-Z0-9][a-zA-Z0-9_.-]*`},
				},
			},
			"drop_table": {
				Description: "Drop a table. Forbidden.",
				Mutating:    true,
				Params:      map[string]ports.ParamSpec{"table": table},
			},
			"truncate": {
				Description: "Truncate a table. Forbidden.",
				Mutating:    true,
				Params:      map[string]ports.ParamSpec{"table": table},
			},
			"delete_database": {
				Description: "Delete a database. Forbidden.",
				Mutating:    true,
				Params: map[string]ports.ParamSpec{
					"database": {Kind: ports.ParamString, Required: true, MaxLen: 128,
						Description: "database name", Pattern: `[a-zA-Z_][a-zA-Z0-9_]*`},
				},
			},
		},
	}
}

// Catalog returns every declared tool.
//
// The composition root registers these. Phase 7 replaces the inert backing with
// real implementations without changing a descriptor — which is the point of
// writing the contract first.
func Catalog() []ports.ToolDescriptor {
	return []ports.ToolDescriptor{
		Docker(), Kubernetes(), Linux(), Monitoring(), Security(), Git(), Database(),
	}
}
