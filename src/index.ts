import * as core from '@actions/core';
import * as github from '@actions/github';

enum Inputs {
  Name = 'name',
  Path = 'path'
}

async function run() {
  try {
    const name = core.getInput(Inputs.Name, {required: false})
    const path = core.getInput(Inputs.Path, {required: false})

    const octokit = github.getOctokit('')

    console.log(name)
    console.log(path)
    console.log(octokit)

  } catch(e) {

  }
}

run();
