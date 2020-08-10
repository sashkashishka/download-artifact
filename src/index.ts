import { homedir } from 'os';
import * as core from '@actions/core';
import * as github from '@actions/github';
import * as OctokitTypes from '@octokit/types';
import * as artifact from '@actions/artifact';
import * as R from 'ramda';

enum Inputs {
  Name = 'name',
  Workflow = 'workflow',
  Path = 'path',
  Repo = 'repo',
  Owner = 'owner',
  GithubToken = 'github_token',
  Commit = 'commit',
  Branch = 'branch',
  PR = 'pr',
}

async function run(): Promise<void> {
  try {
    const name = core.getInput(Inputs.Name, { required: true });
    const workflow = core.getInput(Inputs.Workflow, { required: true });
    const githubToken = core.getInput(Inputs.GithubToken, { required: true });
    const repo = R.defaultTo(github.context.repo.repo)(
      core.getInput(Inputs.Repo, { required: false })
    );
    const owner = R.defaultTo(github.context.repo.owner)(
      core.getInput(Inputs.Owner, { required: false })
    );
    const branch = R.defaultTo('master')(
      core.getInput(Inputs.Branch, { required: false })
    );
    let path = core.getInput(Inputs.Path, { required: false });

    if (path.indexOf('~') === 0) {
      path = path.replace('~', homedir());
    }

    const octokit = github.getOctokit(githubToken);

    const workflowList = await octokit.actions.listRepoWorkflows({
      owner,
      repo,
    });

    type WorkflowItem = OctokitTypes.ActionsListRepoWorkflowsResponseData['workflows'][0];

    const currWorkflow = R.find<WorkflowItem>(
      R.compose(
        R.test(new RegExp(workflow)),
        R.prop('path'),
      ),
    )(workflowList.data.workflows);

    core.info(JSON.stringify(currWorkflow, null, ' '))

    const workflowRuns = await octokit.actions.listWorkflowRuns({
      owner,
      repo,
      workflow_id: R.defaultTo(0)(currWorkflow?.id),
      status: 'completed',
      branch,
    });

    console.log('')
    core.info(JSON.stringify(workflowRuns, null, ' '))
    console.log('')
    console.log('homedir', homedir())
    console.log('')
    console.log('github', github)

  } catch (e) {
    core.setFailed(e.message);
  }
}

run();
