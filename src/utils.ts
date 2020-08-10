import { homedir } from 'os';
import * as core from '@actions/core';
import * as github from '@actions/github';
import * as R from 'ramda';

enum Inputs {
  Name = 'name',
  Workflow = 'workflow',
  Path = 'path',
  Repo = 'repo',
  Owner = 'owner',
  GithubToken = 'github_token',
  Branch = 'branch',
  Commit = 'commit',
}

export interface Output {
  name: string;
  workflow: string;
  githubToken: string;
  repo: string;
  owner: string;
  branch: string;
  commit: string;
  path: string;
}

const setDefaults = (defaultVal: string) => R.when<string, string>(
  R.isEmpty,
  R.always(defaultVal),
);

export const getActionInputs = (): Output => {
  const name = core.getInput(Inputs.Name, { required: true });
  const workflow = core.getInput(Inputs.Workflow, { required: true });
  const githubToken = core.getInput(Inputs.GithubToken, { required: true });
  const repo = setDefaults(
    github.context.repo.repo
  )(
    core.getInput(Inputs.Repo, { required: false })
  );
  const owner = setDefaults(
    github.context.repo.owner
  )(
    core.getInput(Inputs.Owner, { required: false })
  );
  const branch = core.getInput(Inputs.Branch, { required: false });
  const commit = core.getInput(Inputs.Commit, { required: false });
  let path = core.getInput(Inputs.Path, { required: false });

  return {
    name,
    workflow,
    githubToken,
    repo,
    owner,
    branch,
    commit,
    path,
  };
};

const pathLens = R.lens(R.prop('path'), R.assoc('path'));

export const transformPath = R.when<Output, Output>(
  R.compose(
    R.test(/^~/),
    R.view(pathLens),
  ),
  R.over(pathLens, path => path.replace('~', homedir())),
);
