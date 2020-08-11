import * as core from '@actions/core';
import * as github from '@actions/github';
import * as OctokitTypes from '@octokit/types';
import * as R from 'ramda';

import {
  getActionInputs,
  transformPath,
  Output,
  unzip,
} from './utils';

async function run(): Promise<void> {
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

    core.info(`###: Connecting to ${owner}/${repo}`);

    const octokit = github.getOctokit(githubToken);

    core.info(`###: Connected to ${owner}/${repo}`);

    const workflowList = await octokit.actions.listRepoWorkflows({
      owner,
      repo,
    });

    core.info(`###: Look for workflow ${workflow}`);

    type WorkflowItem = OctokitTypes.ActionsListRepoWorkflowsResponseData['workflows'][0];

    const selectedWorkflow = R.find<WorkflowItem>(
      R.compose(
        R.test(new RegExp(workflow)),
        R.prop('path'),
      ),
    )(workflowList.data.workflows);

    if (!selectedWorkflow) {
      throw new Error(
        `Repository ${owner}/${repo} has no workflow with path: ${workflow}`
      );
    }

    core.info(`###: Found workflow ${workflow} - id ${selectedWorkflow.id}`);

    type WorkflowRun = OctokitTypes.ActionsListWorkflowRunsResponseData['workflow_runs'][0];

    let run: WorkflowRun | void;
    let page = 1;

    core.info(
      `###: Look for workflow runs that satisfy search params:
        ${branch ? `- branch: ${branch}` : ''}
        ${commit ? `- commit: ${commit}` : ''}
      `
    );

    while (!run) {
      const workflowRuns = await octokit.actions.listWorkflowRuns({
        owner,
        repo,
        workflow_id: selectedWorkflow.id,
        status: 'completed',
        branch,
        per_page: 100,
        page,
      });

      // 1. branch: status
      // 2. pr: commit
      // 3. commit: commit
      // 4. last successful: status

      run = R.cond([
        [
          R.partial<string, string, boolean>(R.complement(R.isEmpty), [branch]),
          R.find<WorkflowRun>(
            R.propEq('status', 'completed'),
          ),
        ],
        [
          R.partial<string, string, boolean>(R.complement(R.isEmpty), [commit]),
          R.find<WorkflowRun>(
            R.propEq('head_sha', commit),
          ),
        ],
        [
          R.T,
          R.find<WorkflowRun>(
            R.propEq('status', 'completed'),
          ),
        ],
      ])(workflowRuns.data.workflow_runs);

      page += 1;
    }

    if (!run) {
      throw new Error(
        `Repository ${owner}/${repo} has no workflow runs (path: ${workflow}) that satisfy search params:
          - branch: ${branch}
          - commit: ${commit}
        Or this workflow hasn't started yet.
        Remember that if branch and commit specified simultaneously - branch
        have precedence over commit.
        `
      );
    }

    core.info(`###: Get artifacts`);

    type Artifact = OctokitTypes.ActionsListWorkflowRunArtifactsResponseData['artifacts'][0];

    const artifacts = await octokit.actions.listWorkflowRunArtifacts({
      owner,
      repo,
      run_id: run.id,
    });

    const artifact = R.find<Artifact>(
      R.propEq('name', name)
    )(artifacts.data.artifacts);

    if (!artifact) {
      throw new Error(
        `Repository ${owner}/${repo} has no artifact in ${workflow} with name: ${name}`
      );
    }

    core.info(`###: Download artifact ${name} into ${path} directory`);

    const artifactArchive = await octokit.actions.downloadArtifact({
      repo,
      owner,
      artifact_id: artifact.id,
      archive_format: 'zip',
    });

    core.info(`###: Artifact ${name} from ${owner}/${repo} was successfuly downloaded`);

    unzip(artifactArchive.data, path);

    core.info(`###: Artifact ${name} from ${owner}/${repo} was successfuly extracted`);
  } catch (e) {
    core.setFailed(e.message);
  }
}

run();
