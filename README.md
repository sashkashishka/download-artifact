# Download artifacts outside action

This action can download and extract artifacts as from current repo (as [default action]() do) and
from other repository. 

Inputs list:

|Input|Required|Description|
|---|---|---|
|github_token|yes|access token. With `${{ secrets.GITHUB_TOKEN }}` token runner can access only current repo. To access other your or your's organization repositories - [create own token](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token).|
|workflow|yes|name of workflow yml file with extension (`workflow.yml`)|
|name|yes|artifact name|
|owner|no|onwer of the repository. If not specified - default to current repository owner|
|repo|no|name of the repository. If not specified - default to current repository name|
|path|no|path where to download artifacts. If not specified - default to root of repository|
|branch|no|branch which is associated with workflow run and artifact|
|commit|no|commit which is associated with workflow run and artifact|

Note: if brach and commit specified simultaneously - branch have precedence over commit.

```yml
- use: sashkashishka/download-artifact-outside@v1
  with:
    # required
    github_token: ${{ secrets.GITHUB_TOKEN }}
    # required
    workflow: workflow-file-name.yml
    # required
    name: artifact-name
    # optional
    owner: owner
    # optional
    repo: repo-name
    # optional
    path: path/to/extract/artifact
    # optional
    branch: master
    # optional
    commit: ${{ github.sha }}
```
