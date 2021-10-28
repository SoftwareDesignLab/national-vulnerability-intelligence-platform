/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.rit.se.nvip.patchfinder.commits;

import java.util.List;

import org.eclipse.egit.github.core.CommitFile;
import org.eclipse.jgit.revwalk.DepthWalk.Commit;

/**
 *
 * @author Joanna C. S. Santos <jds5109@rit.edu>
 */
public class GithubCommit {

	private final String sha;
	private final List<String> foundBugs;
	private final List<String> foundCves;
	private final Commit commit;
	private final List<CommitFile> affectedFiles;

	public GithubCommit(String sha, List<String> foundCves, List<String> foundBugs, Commit commit,
			List<CommitFile> affectedFiles) {
		this.sha = sha;
		this.foundCves = foundCves;
		this.foundBugs = foundBugs;
		this.commit = commit;
		this.affectedFiles = affectedFiles;
	}

	public List<String> getFoundBugs() {
		return foundBugs;
	}

	public List<String> getFoundCves() {
		return foundCves;
	}

	public Commit getCommit() {
		return commit;
	}

	public boolean isFixingCve() {
		return this.foundCves.size() > 0;
	}

	public boolean isFixingBug() {
		return this.foundBugs.size() > 0;
	}

	public List<CommitFile> getAffectedFiles() {
		return this.affectedFiles;
	}

	public String getSha() {
		return sha;
	}
}
