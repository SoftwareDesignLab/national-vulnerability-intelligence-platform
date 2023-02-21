/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.patchfinder.commits;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.internal.storage.file.WindowCache;
import org.eclipse.jgit.lib.ProgressMonitor;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.storage.file.WindowCacheConfig;
import org.eclipse.jgit.util.FileUtils;

/**
 * Author: Fawaz Alhenaki Edited by: Andrew Pickard (As of 10/19/2021)
 */
public class JGitParser {

	private static final Logger logger = LogManager.getLogger(JGitParser.class.getName());

	private static final String REGEX_VULN = "vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)";
	private static final String REGEX_CVE = "(CVE[-]*[0-9]*[-]*[0-9]*)";
	private static final Pattern PATTERN_VULN = Pattern.compile(REGEX_VULN);
	private static final Pattern PATTERN_CVES = Pattern.compile(REGEX_CVE);
	private Repository localRepo;
	private Git git;
	private final List<JGithubCommit> fixCommits;

	private final String localDownloadLoc;
	private final String remoteLoc;
	private String projectName;

	public JGitParser(String remoteLoc, String localDownloadLoc) {
		this.fixCommits = new ArrayList<>();
		this.localDownloadLoc = localDownloadLoc;
		try {
			String fileName = remoteLoc.substring(remoteLoc.lastIndexOf('/') + 1);
			this.projectName = fileName.substring(0, fileName.lastIndexOf('.'));
			this.localRepo = new FileRepository(localDownloadLoc + File.separator + projectName + "/.git");
		} catch (IOException e) {
			logger.error(e.getMessage());
		}

		assert this.localRepo != null;
		this.git = new Git(this.localRepo);
		this.remoteLoc = remoteLoc;
	}

	/**
	 * This function clones a repo parms: RemoteLocation. Format:
	 * https://github.com/user/example.git return: Git object of cloned repo
	 */
	public void cloneRepository() {
		try {
			logger.info("Cloning Repo to " + localDownloadLoc + File.separator + projectName + "...");
			git = Git.cloneRepository().setURI(remoteLoc)
					.setDirectory(new File(localDownloadLoc + File.separator + projectName))
					.setProgressMonitor(new ProgressMonitor() {

						private int total_completed;

						@Override
						public void start(int totalTasks) {
							total_completed = 0;
							logger.info("------- Starting work on " + totalTasks + " tasks");
						}

						@Override
						public void beginTask(String title, int totalWork) {
							total_completed = 0;
							logger.info("------- Start " + title + ": " + totalWork);
						}

						@Override
						public void update(int completed) {
							total_completed += completed;
							if (total_completed % 100000 == 0)
								logger.info("------- " + total_completed);
						}

						@Override
						public void endTask() {
							logger.info("------- Done");
						}

						@Override
						public boolean isCancelled() {
							return false;
						}
					}).call();

			logger.info("Repo " + projectName + " successfully cloned!");
		} catch (Exception e) {
			logger.info(e.getMessage());
		}
	}

	/**
	 * Deletes repository from storage (used after patch data is pulled)
	 */
	public void deleteRepository() {
		logger.info("Deleting Repo...");
		try {
			WindowCacheConfig config = new WindowCacheConfig();
			config.setPackedGitMMAP(true);
			WindowCache.reconfigure(config);

			File dir = new File(localDownloadLoc + File.separator + projectName);
			this.git.close();

			FileUtils.delete(dir, 1);

			logger.info("Repo " + projectName + " deleted successfully!");
		} catch (IOException e) {
			logger.info(e.getMessage());
		}
	}

	/**
	 * Collects all commits from a repo and returns them in a list
	 * 
	 * @return
	 */
	private List<RevCommit> getAllCommitList() {
		List<RevCommit> revCommits = new ArrayList<>();
		try {
			for (RevCommit rev : git.log().call()) {
				revCommits.add(rev);
			}
			return revCommits;
		} catch (GitAPIException e) {
			e.getMessage();
			logger.info(e.toString());
		}
		return null;
	}

	/**
	 * Parse commits to prepare for extraction of patches for a repo Uses preset
	 * Regex to find commits related to CVEs or bugs for patches
	 * 
	 * @throws IOException
	 * @throws GitAPIException
	 * @return
	 */
	public Map<Date, ArrayList<String>> parseCommits(String cveId) {
		logger.info("Parsing Commits...");

		List<RevCommit> allCommits = this.getAllCommitList();

		if (allCommits != null) {

			for (RevCommit repoCommit : allCommits) {

				String message = repoCommit.getFullMessage();
				Matcher matcherCve = PATTERN_CVES.matcher(message);
				List<String> foundCves = new ArrayList<>();

				List<String> foundVulns = new ArrayList<>();
				Matcher matcherVuln = PATTERN_VULN.matcher(message);

				// Search for 'CVE' commits
				if (matcherCve.find()) {

					boolean cveCheck = true;

					if (matcherCve.group(0).contains("CVE-")) {
						if (matcherCve.group(0).contains(cveId)) {
							logger.info("Found CVE Commit " + matcherCve.group(0));
							foundCves.add(matcherCve.group(0));
						} else {
							cveCheck = false;
						}
					}

					if (cveCheck) {
						logger.info("Found CVE Commit " + matcherCve.group(0));
						foundCves.add(matcherCve.group(0));
					}
				}

				// Search for 'Vulnerability' commits
				else if (matcherVuln.find()) {
					logger.info("Found Vuln Commit " + matcherVuln.group(0));
					foundVulns.add(matcherVuln.group(0));
				}

				if (!foundCves.isEmpty() || !foundVulns.isEmpty()) {
					JGithubCommit githubCommit = new JGithubCommit(repoCommit.getName(), repoCommit);
					this.fixCommits.add(githubCommit);
				}
			}
		}

		return extractJGithubComits(fixCommits);

	}

	/**
	 * Generate a TreeParser from a Tree that's obtained from a given commit to
	 * allow for no inspection duplicates
	 *
	 * @return
	 * @return
	 * @param fixCommits
	 */
	private Map<Date, ArrayList<String>> extractJGithubComits(List<JGithubCommit> fixCommits) {

		Map<Date, ArrayList<String>> commits = new HashMap<>();

		for (JGithubCommit fixCommit : fixCommits) {

			ArrayList<String> commitData = new ArrayList<>();

			commitData.add(fixCommit.getCommit().getId().toString());
			commitData.add(fixCommit.getCommit().getFullMessage());

			commits.put(fixCommit.getCommit().getAuthorIdent().getWhen(), commitData);
		}

		logger.info("Commits from repo " + projectName + " parsed successfully!");
		return commits;

	}
}
