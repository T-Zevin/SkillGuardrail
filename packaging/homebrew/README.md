# Homebrew packaging

The release workflow turns `skillguardrail.rb.tmpl` into a versioned formula using the SHA-256 digests of the macOS and Linux release archives.

To publish automatically:

1. create the public repository `T-Zevin/homebrew-tap`;
2. add a `Formula` directory on its default `main` branch;
3. create a fine-grained token that can write repository contents only to that tap;
4. save it in the SkillGuardrail repository as the Actions secret `HOMEBREW_TAP_GITHUB_TOKEN`;
5. push a semantic-version tag such as `v0.1.0` whose commit is on `main`.

The workflow verifies that the tag already exists and points to a commit in the
history of `main`; it does not verify a Git signature. Signed tags are still
recommended as an additional maintainer practice.

GitHub release immutability is a repository setting and is not enabled by this
workflow. If you want immutable assets and GitHub-generated release
attestations, enable **Settings → General → Releases → Enable release
immutability** before publishing the first release.

Without that secret, the generated `skillguardrail.rb` is still attached to the GitHub Release for manual review and publication.

Before publishing, test the generated formula from a release artifact:

```bash
brew install --formula ./skillguardrail.rb
brew test skillguardrail
brew audit --strict skillguardrail
```

Users install from the tap with:

```bash
brew install T-Zevin/tap/skillguardrail
```
