# Kyverno Design Proposal - Mutations in kyverno-json

Created: February 13th, 2024
Author: [Charles-Edouard Brétéché](https://github.com/eddycharly)

# Table of Contents

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

Kyverno-JSON supports validation with [assertion trees](https://kyverno.github.io/kyverno-json/latest/policies/asserts/).

This KDP is about supporting mutations, potentially with a construct called _mutation trees_.

# Definitions

Make a list of the definitions that may be useful for those reviewing. Include phrases and words that Kyverno users or other interested parties may not be familiar with.

# Motivation

- Support mutations in kyverno-json policies

# Proposal

This provides a high-level overview of the feature.

- Given an input object and a mutation policy, applying the policy to the input object would eventually result in a new object
- The policy should describe the expected object changes and this description should be done using the YAML syntax
- Such a policy should rely on a generic term called mutation-trees

As we start with an initial object, we can define a mutation by an operation and a value:

- Operation: merge or replace
- Value: an arbitrary object (including `null`)

Mutation notable properties:

- Given an arbitrary input object, applying a merge operation between the given object and an empty object (`{}`) will result in the given input object
- Given an arbitrary input object, applying a merge operation between the given object and itself will result in the given input object

# Functional use cases

In this section, we will detail use cases and examples showcasing the behavior of mutations for real-world scenarios.

## Remove a field from the input object

Removing a field from an input object can be done by setting it to `null` in the mutation definition:

**Input object**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
```

**Mutation**

```yaml
metadata:
  labels: ~
```

**Result**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
```

## Add a field to the input object

Adding a field to an input object can be done by defining it in the mutation definition:

**Input object**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
```

**Mutation**

```yaml
metadata:
  labels:
    foo: bar
```

**Result**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
```

## Replace a field in the input object

Replacing a field in an input object can be tricky.

If the field is a lead, it can be done by defining it in the mutation definition:

**Input object**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
```

**Mutation**

```yaml
metadata:
  labels:
    foo: not-bar
```

**Result**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: not-bar
```

But it really depends on the operation. Take the following case for example:

**Input object**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
```

**Mutation**

```yaml
metadata:
  labels:
    lorem: ipsum
```

**Result**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
    lorem: ipsum
```

In the example above, the input object and the mutation were merged together and the replacement didn't happen in the resulting object.
A potential solution is to mutate twice, removing the field in the first mutation and adding it back with the new value in a second mutation.

**Input object**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
```

**Mutation**

```yaml
metadata:
  labels: ~
---
metadata:
  labels:
    lorem: ipsum
```

**Result**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    lorem: ipsum
```

This time we have the expected result but it's not an optimal solution.

## Replace a field in the input object (revisited)

To replace a field in an input object using a single mutation, we need to explicitly use a replace operation.
Such an operation can be denoted by putting the field name between square brackets (`[]).

**Input object**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    foo: bar
```

**Mutation**

```yaml
metadata:
  [labels]:
    lorem: ipsum
```

**Result**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    lorem: ipsum
```

Note: this needs special processing and explains why this is not the default operation. If it was the default operation, the Mutation notable properties defined in the [Proposal](#proposal) would not be satisfied.

## Link to the Implementation PR

We use this approach in [chainsaw](https://github.com/kyverno/chainsaw). Only the merge operation was implemented, no support for replacement yet.

# Migration (OPTIONAL)

NA

# Drawbacks

NA

# Alternatives

NA

# Prior Art

NA

# Unresolved Questions

NA

# CRD Changes (OPTIONAL)

NA
