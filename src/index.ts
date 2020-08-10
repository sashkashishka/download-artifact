import * as core from '@actions/core';
import * as github from '@actions/github';
import * as OctokitTypes from '@octokit/types';
import * as artifact from '@actions/artifact';
import * as R from 'ramda';

import { getActionInputs, transformPath, Output } from './utils';

async function* run(): AsyncGenerator<void, void, void> {
  try {
    const {
      name,
      workflow,
      githubToken,
      repo,
      owner,
      branch,
      commit,
      path,
    } = R.compose<Output, Output>(
      transformPath,
      getActionInputs,
    )();

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

    // async while on generators
    let run;

    while (run) {

    }

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
    console.log('github', github)

  } catch (e) {
    core.setFailed(e.message);
  }
}

run();


