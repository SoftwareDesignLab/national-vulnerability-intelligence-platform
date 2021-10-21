/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.rit.se.nvip.cvepatches.commits;

import java.util.List;

import org.eclipse.jgit.revwalk.RevCommit;

/**
 *
 * @author Fawaz Alhenaki <faa5019@rit.edu>
 */
public class JGithubCommit {

	private final String sha;
	private final List<String> foundBugs;
	private final List<String> foundCves;
	private final List<String> foundVulns;
	private final RevCommit commit;
	private final List<String> affectedFiles;

	public JGithubCommit(String sha, List<String> foundCves, List<String> foundBugs, List<String> foundVulns,
			RevCommit commit, List<String> affectedFiles) {
		this.sha = sha;
		this.foundCves = foundCves;
		this.foundBugs = foundBugs;
		this.foundVulns = foundVulns;
		this.commit = commit;
		this.affectedFiles = affectedFiles;
	}

	public List<String> getFoundBugs() {
		return foundBugs;
	}

	public List<String> getFoundCves() {
		return foundCves;
	}

	public List<String> getFoundVulns() {
		return foundVulns;
	}

	public RevCommit getCommit() {
		return commit;
	}

	public boolean isFixingCve() {
		return this.foundCves.size() > 0;
	}

	public boolean isFixingBug() {
		return this.foundBugs.size() > 0;
	}

	public boolean isFixingVuln() {
		return this.foundVulns.size() > 0;
	}

	public List<String> getAffectedFiles() {
		return this.affectedFiles;
	}

	public String getSha() {
		return sha;
	}
}
