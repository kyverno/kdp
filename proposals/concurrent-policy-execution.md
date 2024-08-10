# Meta
[meta]: #meta
- Name: Concurrent Policy Execution
- Start Date: 2024-08-01
- Author(s): KhaledEmaraDev
- Supersedes: N/A

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

This document proposes a design for implementing concurrent policy execution in Kyverno. While initially considered for performance improvements, the primary benefits of this approach lie in enhanced flexibility and potential for future optimizations. The proposal addresses the challenges of shared state, explores various implementation strategies, and outlines a plan for measuring and validating the benefits of concurrency.

# Definitions
[definitions]: #definitions

N/A

# Motivation
[motivation]: #motivation

Although high throughput in Kyveno saturates CPU utilization, limiting the performance gains from concurrency, several other advantages warrant exploration:

* **Improved Latency for Certain Requests:** While average latency might not improve significantly, specific requests with fewer rules or faster-executing rules can experience reduced latency.
* **Enhanced Responsiveness:** Concurrency can prevent slow or long-running policies from blocking the execution of others, thereby improving the system's overall responsiveness.
* **Increased Throughput Potential:** While the current bottleneck is CPU utilization, future optimizations or hardware upgrades could benefit from concurrent policy execution, leading to potential throughput increases.

# Proposal

There are two primary approaches to implementing concurrent policy execution in Kyverno:

* **Per Policy Concurrency:** Concurrency is applied at the policy level. Each policy is processed by a separate goroutine. This approach allows for more straightforward control mechanisms, such as fail-fast behavior when the first rule fails.
* **Per Rule Concurrency:** Concurrency is applied at the rule level within each policy. This can potentially yield finer-grained parallelism but introduces complexity in managing the shared context and synchronization.

Given the requirement to control rule application (e.g., apply only the first rule and fail fast), we lean towards per policy concurrency. However, solutions to manage concurrency at the rule level will also be considered.

# Implementation

The primary challenge in concurrent policy execution is managing the shared JSON context. The current context structure is as follows:

```go
type context struct {
	jp                 jmespath.Interface
	jsonRaw            map[string]interface{}
	jsonRawCheckpoints []map[string]interface{}
	images             map[string]map[string]apiutils.ImageInfo
	operation          kyvernov1.AdmissionOperation
	deferred           DeferredLoaders
}
```

Key components to consider:

* **jsonRaw:** A shared map containing raw JSON data.
* **jsonRawCheckpoints:** A system for checkpointing and restoring state.
* **DeferredLoaders:** Store the state of data they load.

Mutexes were initially considered to synchronize access to the shared context. However, high contention and CPU utilization degraded performance. Thus, alternative synchronization strategies need to be explored.

## Proposed Solutions

1. **Separate JSON Context per Rule:**

Create a separate JSON context for each rule. While this approach avoids contention, it incurs a performance penalty due to deep copying the context for each policy.

**Pros:**

* No contention or synchronization issues.

**Cons:**

* Performance overhead due to deep copying.

2. **Shared Context with Fine-Grained Locking:**

Introduce fine-grained locking to synchronize access to the shared context. This approach requires careful design to minimize contention and avoid deadlocks.

**Pros:**

* Minimal performance overhead compared to deep copying.

**Cons:**

* Complexity in managing fine-grained locks.

3. **Shared Context with Copy-on-Write:**

Implement a copy-on-write mechanism to manage the shared context. This approach minimizes contention by creating a copy of the context when a rule modifies it.

**Pros:**

* Reduced contention compared to fine-grained locking.
* Lower performance overhead compared to deep copying.

**Cons:**

* Complexity in managing copy-on-write semantics.

4. **Forked JSON Context**

Implement a forked JSON context where only mutable fields are copied. Immutable fields are shared among goroutines.

**Pros:**

* Reduced contention compared to fine-grained locking.
* Lower performance overhead compared to deep copying.

**Cons:**

* Complexity in managing forked context.

5. **Shared Context with Transactional Updates**

Implement transactional updates to the shared context. Each rule applies its changes to a transactional context, which is then merged into the shared context.

**Pros:**

* Reduced contention compared to fine-grained locking.
* Lower performance overhead compared to deep copying.

**Cons:**

* Complexity in managing transactional updates.

6. **Immutable Shared Context**

Implement an immutable shared context where each rule creates a new context with its changes. The shared context remains immutable, and changes are propagated through the context chain.

**Pros:**

* Reduced contention compared to fine-grained locking.
* Lower performance overhead compared to deep copying.

**Cons:**

* Complexity in managing immutable context.

## Plan for Measuring and Validating Benefits

The benefits of concurrent policy execution will be measured using the following metrics:

* **Average Latency:** Measure the average time taken to process a request.
* **Throughput:** Measure the number of requests processed per second.
* **Resource Utilization:** Monitor CPU and memory utilization.

The following steps will be taken to validate the benefits of concurrency:

1. **Baseline Measurement:** Measure the performance of the current sequential execution model.
2. **Concurrent Execution:** Implement concurrent policy execution and measure the performance improvements.
3. **Validation:** Validate the benefits of concurrency through load testing and real-world scenarios.

## Link to the Implementation PR

# Drawbacks

* **Complexity:** Implementing concurrency introduces complexity in managing shared state and synchronization.
* **Performance Overhead:** Incorrect synchronization strategies can lead to performance degradation.
* **Testing Overhead:** Testing concurrent code is more challenging than sequential code.

# Alternatives

* **Sequential Execution:** Continue with the current sequential execution model.
* **Hybrid Approach:** Implement concurrency at the policy level while exploring per-rule concurrency for specific use cases.
* **External Concurrency:** Use external tools or libraries to manage concurrency.

# Prior Art

We have previously used a Worker Pool to apply Audit Policies, while it's still one worker per request, it's a good starting point to explore concurrency in Kyverno.

# Unresolved Questions

- What is the best synchronization strategy for managing shared state?
- How can we minimize the performance overhead of concurrency?
- What are the potential pitfalls of concurrent policy execution?
