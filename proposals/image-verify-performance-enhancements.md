# Meta
[meta]: #meta
- Name: Image verify performance enhancements
- Start Date: 2024-02-14
- Update data (optional): (fill in today's date: YYYY-MM-DD)
- Author(s): vishal-chdhry
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
  - [Link to the Implementation PR](#link-to-the-implementation-pr)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Prior Art](#prior-art)
- [Unresolved Questions](#unresolved-questions)
- [CRD Changes (OPTIONAL)](#crd-changes-optional)

# Overview
[overview]: #overview

Kyverno's verify images policies checks container image signatures and attestations for software supply chain security. This proposal explores possible changes that can improve the performance of Kyverno's [verify image policies](https://kyverno.io/docs/writing-policies/verify-images/).

# Definitions
[definitions]: #definitions

1. **Artifacts:** Software builds produce artifacts for installation and execution. The type and format of artifacts varies depending on the software. They can be packages, WAR files, container images, or other formats. 
2. **Metadata:** Metadata is used to describe software and the build environment. Provenance (origin) data, SBOMs, and vulnerability scan reports are the essential set of metadata required to assess security risks for software.
3. **Attestations:**  Authenticated metadata is used to attest to the integrity of a software system. Both custom and standardized metadata can be converted into attestations.
4. **Policies:** Policies check and enforce organization standards. Policies should be automatically enforced prior to deployment and via runtime scanning. 

# Motivation
[motivation]: #motivation

- Why should we do this?
  
  Kyverno's verify image policies are slow. They require network calls to fetch data from registries and there are several duplicate network calls. In some cases, policy execution can take around 30 seconds which is far from ideal. 
  > As of v1.11, Kyverno verifies image signatures and attestations one at a time. The bulk of the time is taken in fetching data.
  
  https://github.com/kyverno/kyverno/issues/8802

- What use cases does it support?
  
  This KDP focusses only on perfomance enhancement for kyverno's verify image policies.
  
- What is the expected outcome?

  Measurable improvement in processing time of image verification policies.

# Proposal

This provides a high level overview of the feature.

The following changes can be made to improve performance:
1. Kyverno's image and attestation verifications are independent of each other. They do not share anything between them. We can parallelly process image signature verification and every attestation verification. This will result in more network calls in a shorter timeframe.
2. We can add a in-memory store for [every admission request](https://github.com/kyverno/kyverno/blob/03c6635b6c367aa7f56ec0f5f15f3fbb4330f7f8/pkg/webhooks/resource/imageverification/handler.go#L78) which will store the result for every network call. Subsequent network calls to the same URL will use the in memory store instead of going to the registry. This will help when we have mutliple policies/rules that match the same resource. We will make network calls for the first request and use inmem store for every request after that. There won't be any stale data as we are storing data for the current admission request and the data lives for a few seconds. This will solve the duplicate network call problem. This can easily be done for Notary as we control the [notary registry interface](https://github.com/kyverno/kyverno/blob/03c6635b6c367aa7f56ec0f5f15f3fbb4330f7f8/pkg/notary/repository.go). This will not be of any help for cosign as we have enough control. We can move to sigstore-go and fetch data from registry ourselves. 

In other words, we are improving performance for the following cases:
1. *Single resource and single rule:* Parallelly process images and attestation verification for the rule.
2. *Single resource and multiple rules:* The network calls will be exactly same so we will "cache" those network calls to reduce time taken.

# Implementation

N/A

## Link to the Implementation PR

# Drawbacks

Why should we **not** do this?

sigstore/cosign manages data fetching internally. We cannot provide our own solution for that. A possible fix would be to switch to sigstore-go library which is a more barebone implementation of sigstore.

# Alternatives

- What other designs have been considered?
- Why is this proposal the best?
- What is the impact of not doing this?

# Prior Art

Discuss prior art, both the good and bad.

# Unresolved Questions

- What parts of the design do you expect to be resolved before this gets merged?
- What parts of the design do you expect to be resolved through implementation of the feature?
- What related issues do you consider out of scope for this KDP that could be addressed in the future independently of the solution that comes out of this KDP?

# CRD Changes (OPTIONAL)

Does this KDP entail any proposed changes to the core CRD or any extensions? If so, please document changes here.