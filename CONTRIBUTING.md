# Contributing to mcp-policy-gateway

## Release Process

We use PyPI's Trusted Publishing via GitHub Actions. To cut a new release and publish it to PyPI, follow these steps:

1. **Bump the Version**: Update the version number in `pyproject.toml`.
   ```toml
   [project]
   version = "0.2.0"  # Example bump
   ```
2. **Commit and Push**: Commit the version bump to `main`.
3. **Create a GitHub Release**:
   - Go to the **Releases** page on GitHub.
   - Click **Draft a new release**.
   - Create a new tag (e.g., `v0.2.0`) pointing to `main`.
   - Add release notes.
   - Click **Publish release**.

The `.github/workflows/publish.yml` GitHub Action will automatically trigger upon publishing the release. It will build the package and publish it to PyPI using OIDC.

### Initial PyPI Setup (Trusted Publishing)
Before the very first release, a repository admin must configure PyPI:
1. Create the project on PyPI (or configure a Pending Publisher).
2. Go to Publishing settings for the project.
3. Add a new Trusted Publisher with:
   - **Publisher name**: GitHub
   - **Owner**: `Spuddy10345`
   - **Repository name**: `mcp-policy-gateway`
   - **Workflow name**: `publish.yml`
   - **Environment name**: `pypi`
