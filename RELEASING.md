# Releasing

Releases go to Maven Central through the `release` workflow. The workflow only uploads and
validates the release. Nothing becomes public until a maintainer confirms it on the Central Portal.

## One-time setup

Repository secrets, used by `.github/workflows/release.yml`:

| Secret | Content |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | user token name, generated on central.sonatype.com |
| `MAVEN_CENTRAL_PASSWORD` | user token password |
| `GPG_PRIVATE_KEY` | ASCII-armored private key that signs the artifacts |
| `GPG_PASSPHRASE` | passphrase of that key |

- The namespace (the `groupId`) must be verified on the Central Portal.
- The public half of the GPG key must be on a public key server.

## Steps

1. **Check that `main` is green.** That means CI, `./scripts/scrub-check.sh` and
   `./scripts/mutation-check.sh`.
2. **Set the release version.** It must not be a snapshot:

   ```bash
   ./mvnw versions:set -DnewVersion=X.Y.Z -DgenerateBackupPoms=false
   ```

3. **Update `CHANGELOG.md`:** move the entries from `[Unreleased]` to `[X.Y.Z]` with today's date.
   Then update the version in the documentation snippets (README, quickstart).
4. **Commit and tag:**

   ```bash
   git commit -am "chore(release): X.Y.Z"
   git tag -a vX.Y.Z -m "X.Y.Z"
   git push origin main vX.Y.Z
   ```

5. **Let the workflow run.** Pushing the tag starts the `release` workflow. It:
   - checks that the pom version matches the tag and is not a snapshot;
   - runs the build and tests;
   - signs the artifacts and uploads them.

   You can also start it by hand (`workflow_dispatch`) on the tag.
6. **Confirm on the Central Portal.** Open central.sonatype.com → *Deployments*. Check the validated
   deployment: the parent POM and the starter, with sources, javadoc and signatures, and no sample
   module. Then press *Publish*. If something is wrong, press *Drop* and fix it with a new version:
   a published version can never be replaced.
7. **Create a GitHub release** from the tag, with the changelog section as notes.
8. **Go back to a snapshot:**

   ```bash
   ./mvnw versions:set -DnewVersion=X.Y.(Z+1)-SNAPSHOT -DgenerateBackupPoms=false
   git commit -am "chore: start X.Y.(Z+1)-SNAPSHOT"
   git push origin main
   ```

## Trying the release build locally

The same build without signing and without upload:

```bash
./mvnw -Prelease -Dgpg.skip -DskipTests verify
```

It must end with exit code 0 and produce `-sources.jar` and `-javadoc.jar` for the starter.

## Security fixes

Prepare the fix in a private fork of a GitHub security advisory (see [SECURITY.md](SECURITY.md)).
Release it as above, then publish the advisory once the version is available on Maven Central.
