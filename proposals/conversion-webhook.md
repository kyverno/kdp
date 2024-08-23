# Conversion Webhook

- **Authors**: [Mariam Fahmy](https://github.com/MariamFahmy98)
- **Created**: December 12th, 2023
- **Abstract**: Implementing a conversion webhook to convert from v1 to v2 and vice versa.

## Overview
- [Introduction](#introduction)
- [Motivation](#motivation)
- [Proposal](#proposal)
- [Implementation](#implementation)
- [Next Steps](#next-steps)

## Introduction
Conversion webhooks are a feature introduced in Kubernetes to facilitate the transformation and validation of custom resources. They enable automatic conversion of incoming requests between different versions of the CRD schema. This ensures backward compatibility as the CRD evolves over time, allowing existing resources to be seamlessly upgraded without disruption.

Some common use cases where conversion is required:
1. custom resource is requested in a different version than stored version.
2. Watch is created in one version but the changed object is stored in another version.
3. custom resource PUT request is in a different version than storage version.

## Motivation
Kyverno CRDs `v1` contain many deprecated fields that require removal. Additionally, there are fields at the `spec` level that are only specific to certain rules and not others. Therefore, we would like to introduce a more stable version, `v2`. Since `v1` and `v2` will have different schema, a conversion webhook is required to convert between them.

## Proposal
In Kubernetes, it is essential that all versions are compatible with each other. This means that if we go from `v1` to `v2` and then back to `v1`, we must not lose any information. Therefore, any changes we make to our API must be compatible with `v1`, and we must ensure that anything we add in `v2` is also supported in `v1`. This requires us to add new fields to `v1` to support any new additions.

Kyverno policy fields can be classified into three categories. The first category includes fields that have been deprecated and replaced with alternative options. The second category includes fields that have been deprecated with no available alternatives. The third category includes fields that have been moved to their respective rules from the `spec` level.

1. Deprecated fields that are replaced with alternative options can be easily converted from one version to another. For example, `ClusterPolicy` v1 that uses `spec.generateExistingOnPolicyUpdate` can be converted to `spec.generateExisting` in v2 using the conversion webhook. There's no loss of information.

2. Deprecated fields with no available alternatives such as `spec.schemaValidation` must now be stored as an annotation in `v2`. The annotation `policies.kyverno.io/conversion-data` can be used to store the source object as json data in the destination object. Alternatively, each deprecated field can have a specific annotation. For example, in the case of `spec.schemaValidation`, it will be `policies.kyverno.io/schema-validation`.

3. Fields that are at the `spec` level and related to specific rules like:
   - `spec.mutateExistingOnPolicyUpdate`
   - `spec.generateExisting`
   - `spec.validationFailureAction`
   - `spec.validationFailureActionOverrides`

   will be moved to their respective rules and can be easily converted from one version to another using the conversion webhook. There's no loss of information.

As per the Kubernetes migration guide, the initial plan for API migration to `v2` will be as follows:

1. For Kyverno v1.12:
   - Migrate v2beta1 -> v2beta2.
   - Deprecate v2beta1.
   - The storage version is v1.
2. For Kyverno v1.13:
   - Migrate v2beta2 -> v2.
   - Deprecate v2beta2 and v1.
   - The storage version is v1.
3. For Kyverno 1.14:
   - The storage version will be v2.
4. For Kyverno 1.15:
   - v2beta1 will be removed.
5. For Kyverno 1.16:
   - v2beta2 will be removed.

But introducing a new beta version `v2beta2` could complicate the implementation of the conversion webhook since each version must be converted to/from the storage version. An alternative solution is to migrate to `v2` directly as follows:
1. For Kyverno v1.12:
   - Migrate v2beta1 -> v2.
   - Deprecate v2beta1 and v1.
   - The storage version is v1.
2. For Kyverno v1.13:
   - The storage version will be v2.
3. For Kyverno 1.14:
   - v2beta1 will be removed.

Note that multiple versions may exist in storage if they were written before the storage version changes – changing the storage version only affects how objects are created/updated after the change.

## Implementation

## Next Steps
