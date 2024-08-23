# Meta
[meta]: #meta
- Name: Kyverno for non-Kubernetes workloads
- Start Date: Sep 24th, 2023
- Update data: 
- Author(s): @JimBugwadia

# Table of Contents
[table-of-contents]: #table-of-contents
- [Meta](#meta)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Definitions](#definitions)
- [Motivation](#motivation)
- [Proposal](#proposal)
- [Implementation](#implementation)
- [Migration (OPTIONAL)](#migration-optional)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Prior Art](#prior-art)
- [Unresolved Questions](#unresolved-questions)
- [CRD Changes (OPTIONAL)](#crd-changes-optional)

# Overview
[overview]: #overview

Enable use of Kyverno for non-Kubernetes workloads.

# Definitions
[definitions]: #definitions


# Motivation
[motivation]: #motivation

Kyverno is popular with platform engineering teams for Kubernetes policy management, due to its advanced features and simplicity. The platform engineering teams that manage Kubernetes, also typically also manage:
* Cloud infrastructure & services: storage, networking, security, databases, clusters, etc.
* Serverless: access and governance for serverless workloads
* Containers (non-Kubernetes): other application container workloads.

These teams would like to leverage Kyverno across these domains, to unify policy and governance for platform engineering use cases.

# Proposal

Currently, Kyverno runs as an admission controller and a background scanner in Kubernetes clusters and is also available as a CLI that can operate without access to any cluster. The proposal is to extend the Kyverno CLI, and make Kyverno available in two new form factors.

Here are the proposed changes:
1. Extend the Kyverno CLI to process raw JSON data for policy evaluation.
2. An application service that performs policy evaluations via a REST API.
3. A Kyverno Golang library that can be integrated in applications for policy evaluations.

# Implementation

## Extending the Kyverno CLI 

The Kyverno CLI allows passing resources via the `--resource` flag. We can consider a new flag for JSON (e.g. `--resource-json`) or use the same flag and add logic to detect if the resource is of raw JSON type (i.e. not a Kubernetes resource).

When the CLI detects a non-Kubernetes resource, it can format it as a built-in custom resource type (e.g. `kyverno.io/v1alpha1/JSON`) with the assumption that policies are written to match that resource.

Note that this can be done manually today. The enhancement required is to make it easier for users.

## Application Service

A policy management solution requires:
1. A way to configure the service
2. A way to configure and manage policies
3. An API to evaluate policies against application resources and data

Currently for Kyverno, all three of these are done via Kubernetes. Kyverno is deployed and managed as a Kubernetes workload, and it self-registers with the API server as an dynamic admission controller. Policies are managed as Kubernetes custom resources, as are policy reports, and policy exceptions. Evaluation of policies is done by the API server at admission controls, and via periodic background scans.

For policy evaluation for non-Kubernetes services and workloads, Kyverno can provide a REST API. However, Kyverno can still be installed and managed as a Kubernetes application, and Kyverno policies can still be managed as Kubernetes resources.

The service exposed on the existing Kyverno admission controller, as an optional feature, or as a completely separate instance of the Kyverno policy engine packages as a web application.

## Golang library

Internally, Kyverno already has a policy engine package that exposed an interface to evaluate policies. The engine is supplied a set of policies and a resource, and returns a policy decision. 

This interface can be formalized and documented to allow other applictaions to integrate the Kyverno engine.

## Link to the Implementation PR

TBD

# Migration (OPTIONAL)

N/A

# Drawbacks

Kyverno has been focused on Kubenetes, and can leverage Kubernetes internals to simplify policy management for platform engineering teams. While its important to extend Kyverno, we do not want to loose focus or compromise on its core value proposition.

# Alternatives

None. The alternative is to not do this.

# Prior Art

Here is a blog post that discusses a prototype that validates raw JSON with Kyverno policies:

https://nirmata.com/2023/07/20/experimental-generic-json-validation-with-kyverno/

# Unresolved Questions

1. There are several Kubernetes specific declarations in a Kyverno policies, such as the `match` and `exclude` clauses. These will need to be discussed.

# CRD Changes (OPTIONAL)

A new CRD may be required if we want a resource type that represents a raw JSON payload, e.g. `kyverno.io/v1alpha1/JSON`.