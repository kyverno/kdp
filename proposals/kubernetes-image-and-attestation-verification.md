# Meta
[meta]: #meta
- Name: Kubernetes Image and Attestation Verification
- Start Date: 2023-04-29
- Update data (optional): 2023-04-29
- Author(s): [@Vishal-Chdhry](https://github.com/Vishal-Chdhry)

# Table of Contents
[table-of-contents]: #table-of-contents
- [Meta](#meta)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Definitions](#definitions)
- [Motivation](#motivation)
- [Proposal](#proposal)
- [Implementation](#implementation)
    - [Creating an inhouse implementation notary repository which uses crane](#creating-an-inhouse-implementation-notary-repository-which-uses-crane)
    - [Use crane instead of ORAS to fetch attestations and predecates](#use-crane-instead-of-oras-to-fetch-attestations-and-predecates)
    - [Update the authentication method](#update-the-authentication-method)
  - [Link to the Implementation PR](#link-to-the-implementation-pr)
- [Migration (OPTIONAL)](#migration-optional)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
      - [ORAS Client](#oras-client)
      - [Regclient Client](#regclient-client)
      - [Flux OCI Client](#flux-oci-client)
- [Prior Art](#prior-art)
- [Unresolved Questions](#unresolved-questions)
- [CRD Changes (OPTIONAL)](#crd-changes-optional)

# Overview
[overview]: #overview

This proposal aims alter the approach we use for fetching image attestation and verifying signatures on images and attestations.

# Definitions
[definitions]: #definitions

1. **Artifacts:** Software builds produce artifacts for installation and execution. The type and format of artifacts varies depending on the software. They can be packages, WAR files, container images, or other formats. 
2. **Metadata:** Metadata is used to describe software and the build environment. Provenance (origin) data, SBOMs, and vulnerability scan reports are the essential set of metadata required to assess security risks for software.
3. **Attestations:**  Authenticated metadata is used to attest to the integrity of a software system. Both custom and standardized metadata can be converted into attestations.
4. **Policies:** Policies check and enforce organization standards. Policies should be automatically enforced prior to deployment and via runtime scanning. 

# Motivation
[motivation]: #motivation
The goal of this proposal is to improve the image verification in kyverno to have 
1. Less number of overall dependencies for improved security and maintainability.
2. A robust authentication system with direct support for GCP, AWS, Azure.
3. Support for fetching attestations and verifying Cosign and Notary signatures.

# Proposal

Currently Kyverno uses Notary and Cosign for software supply chain security validation policies. We fetch image signature definitions from an OCI compliant registry using ORAS client and run signature validation checks. The signature is in NotaryV2 or Cosign format.

We fetch attestations (signed metadata) using [ORAS](https://pkg.go.dev/oras.land/oras-go/v2) Client stored with the image to run signature and data validation checks as defined by the policy. The notary signature verification also uses ORAS repository implementataion for its verification method. 

For authentication with registry, we create a secret containing username password and server information and use that for authentication. We use [GCR Crane](https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane) for authentication using credentials.

Our current Authentication system works but it is not perfect and as robust as other implementations. We support authentication using credentials but we dont have direct support for major OCI registry (Azure, AWS, GCP).

Also we are dependent on ORAS as well as Crane at the same time. Both library serve the same purpose of communicating with OCI registries and have very similar methods.

This Proposal proposes the following:
1. Create an inhouse implementation Notary repository which uses crane instead of ORAS to remove the indirect dependency on ORAS.
2. Use crane instead of ORAS to fetch attestations and predicates.
3. Update the authentication to support Azure, AWS, GCP or use [Flux Auth](https://pkg.go.dev/github.com/fluxcd/pkg/oci/auth@v0.23.0) package, which implements crane.

# Implementation

To update the Notary Repository to use crane, We will need to create a Repository client which implements the following interfact

### Creating an inhouse implementation notary repository which uses crane
```go
type Repository interface {
	// Resolve resolves a reference(tag or digest) to a manifest descriptor
	Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error)

	// ListSignatures returns signature manifests filtered by fn given the
	// artifact manifest descriptor
	ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error

	// FetchSignatureBlob returns signature envelope blob and descriptor for
	// given signature manifest descriptor
	FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error)

	// PushSignature creates and uploads an signature manifest along with its
	// linked signature envelope blob.
	PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error)
}
```
All these methods in [Notary's implementation](https://github.com/notaryproject/notation-go/blob/v1.0.0-rc.4/registry/repository.go) currently use ORAS.
Here is the implementation of all these functions using crane: https://gist.github.com/Vishal-Chdhry/74dcf98df56aed4f900496847de210bb

### Use crane instead of ORAS to fetch attestations and predecates
Here is the implementation of `FetchAttestation` method using crane: https://gist.github.com/Vishal-Chdhry/a751b237ef8df6a68faff5056d3ea810#file-notary-go-L133

### Update the authentication method
The Flux OCI client uses crane and SDK of various providers for its authentication methods: https://github.com/fluxcd/pkg/blob/oci/v0.23.0/oci/client/login.go

We can either use flux's implementation or create our own implementation which follows the same idea.

## Link to the Implementation PR
[kyverno#6800](https://github.com/kyverno/kyverno/pull/6800)

# Migration (OPTIONAL)

This section should document breaks to public API and breaks in compatibility due to this KDP's proposed changes. In addition, it should document the proposed steps that one would need to take to work through these changes.

# Drawbacks

Crane currently doesn't support some manifest media types.

The crane.Manifest function calls [get](https://github.com/google/go-containerregistry/blob/4b081f801f399fa293f23e42ba4c4ac6a6003f2c/pkg/v1/remote/descriptor.go#LL118C1-L118C1) function which takes acceptedMediaTypes in its arguments and only returns with a manifest if the media type of the manifest is in the given list.

We recieve error `"code":"MANIFEST_UNKNOWN","message":"OCI artifact found, but accept header does not support OCI artifacts"` when we query for a manifest of type `application/vnd.oci.artifact.manifest.v1+json`

# Alternatives

The following alternatives were considered when picking the OCI client. And here are the findings.
#### ORAS Client
**Positives**
- Has a method for fetching manifests, and referrers, it is the approach we are using right now.
- Has a login method that takes the URL, username, and password
- Notation go client uses ORAS repository as an input for its client

**Negatives**
- Doesn’t support Provider (GCR, Azure, AWS) specific login methods like Flux.
	Oras Auth: https://pkg.go.dev/oras.land/oras-go/v2@v2.0.2/registry/remote/auth
- Doesn’t directly support fetching referrers, had to replicate its discover method.

#### Regclient Client
**Positives**
- It is the most popular library of all.
- Has direct support for fetching referrers.

**Negatives**
- The referrers method doesn’t work properly for all the providers
  Oras discover shows the artifacts properly while regctl returns nothing

  ```bash
  » regctl artifact list jimnotarytest.azurecr.io/jim/net-monitor:v1                                                                 
  Subject:   jimnotarytest.azurecr.io/jim/net-monitor:v1

  Referrers:
  » oras discover -o tree jimnotarytest.azurecr.io/jim/net-monitor:v1                                                               
  jimnotarytest.azurecr.io/jim/net-monitor:v1
  ├── vuln-scan
  │   └── sha256:10c0b24faa551466b708d1677694eb65bbe4679ba10c3a5290ecec2e4f0af6c8
  │       └── application/vnd.cncf.notary.signature
  │           └── sha256:22aed3423fda62d88a09c47cbf1e4ca0441376fbc0270cafb193d4b9146eedc4
  └── application/vnd.cncf.notary.signature
      └── sha256:e9277c9696d262e699583b7f4304eb9a3e7899a0d6c6b3c6b88327926347aaec
  ```
- Does not support manifest fetching for some artifact types
- When fetching vuln-scan (in the previous code block) using regctl, it gives `MANIFEST_UNKNOWN` Error because the type of manifest for OCI artifact is not found in accept headers.
  ```bash
  » regctl manifest get --format body jimnotarytest.azurecr.io/jim/net-monitor@sha256:10c0b24faa551466b708d1677694eb65bbe4679ba10c3a5290ecec2e4f0af6c8 | jq .
  failed to get manifest jimnotarytest.azurecr.io/jim/net-monitor@sha256:10c0b24faa551466b708d1677694eb65bbe4679ba10c3a5290ecec2e4f0af6c8: request failed: not found [http 404]: {"errors":[{"code":"MANIFEST_UNKNOWN","message":"OCI artifact found, but accept header does not support OCI artifacts"}]}
  ```

#### Flux OCI Client
**Positives**
- Has the best login support with support for different providers.
  
**Negatives**
- Doesn’t have following functions
  - Flux client doesn’t have a method to fetch referrers from an OCI registry,
  - Since it is using crane to fetch manifest, it also faces the same issue with some artifact types as regctl does (mentioned above).
  - Flux client has a method to [fetch OCI artifacts](https://pkg.go.dev/github.com/fluxcd/pkg/oci@v0.23.0/client#Client.Pull), but it places it in a directory, 
  - This will require upstream contributions

# Prior Art

Discuss prior art, both the good and bad.

# Unresolved Questions

- What parts of the design do you expect to be resolved before this gets merged?
- What parts of the design do you expect to be resolved through implementation of the feature?
- What related issues do you consider out of scope for this KDP that could be addressed in the future independently of the solution that comes out of this KDP?

# CRD Changes (OPTIONAL)

Does this KDP entail any proposed changes to the core CRD or any extensions? If so, please document changes here.