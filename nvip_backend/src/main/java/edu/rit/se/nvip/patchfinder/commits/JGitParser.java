package edu.rit.se.commits;

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.RawTextComparator;
import org.eclipse.jgit.errors.MissingObjectException;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.internal.storage.file.WindowCache;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.WindowCacheConfig;
import org.eclipse.jgit.util.FileUtils;
import org.eclipse.jgit.util.io.DisabledOutputStream;

/**
 * Author: Fawaz Alhenaki
 * Edited by: Andrew Pickard (As of 10/19/2021)
 */
public class JGitParser {

    private static final Logger logger = LogManager.getLogger(JGitParser.class.getName());

	private static final String REGEX_VULN = "vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)";
	private static final String REGEX_CVE = "(CVE[-]*[0-9]*[-]*[0-9]*)";
	private static final String REGEX_BUG = "bug|BUG|Bug[ #]*([0-9]+)";
	private static final Pattern PATTERN_VULN = Pattern.compile(REGEX_VULN);
	private static final Pattern PATTERN_CVES = Pattern.compile(REGEX_CVE);
	private Repository localRepo;
	private Git git;
	private List<JGithubCommit> fixCommits;

	private String localDownloadLoc;
	private String remoteLoc;
	private String projectName;

	public JGitParser(String remoteLoc, String localDownloadLoc) {
		this.fixCommits = new ArrayList<>();
		this.localDownloadLoc = localDownloadLoc;
		try {
			String fileName = remoteLoc.substring(remoteLoc.lastIndexOf('/') + 1);
			this.projectName = fileName.substring(0, fileName.lastIndexOf('.'));
			this.localRepo = new FileRepository(localDownloadLoc + File.separator + projectName + "/.git");
		} catch (IOException e) {
			e.getMessage();
		}

		assert this.localRepo != null;
		this.git = new Git(this.localRepo);
		this.remoteLoc = remoteLoc;
	}

	/**
	 * This function clones a repo parms: RemoteLocation. Format:
	 * https://github.com/user/example.git return: Git object of cloned repo
	 */
	public void cloneRepository()  {
		try {
			logger.info("Cloning Repo to " + localDownloadLoc + File.separator + projectName + "...");
			git = Git.cloneRepository()
					.setURI(remoteLoc)
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
					})
					.call();

			//git.close();

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
			this.git.getRepository().close();
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

				List<String> foundBugs = new ArrayList<>();
				//Matcher matcherBug = PATTERN_BUGS.matcher(message);

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
					try {
						JGithubCommit githubCommit = new JGithubCommit(repoCommit.getName(), foundCves, foundBugs, foundVulns,
								repoCommit, getFilesPathsByCommit(repoCommit));
						this.fixCommits.add(githubCommit);
					} catch (IOException ex) {
						logger.error(ex.getMessage());
					}
				}
			}
		}

		return extractJGithubComits(fixCommits);

	}

	/**
	 * Obtains a files paths for a specific commit
	 * 
	 * @param commit
	 * @return
	 * @throws IOException
	 * @throws MissingObjectException
	 * @throws GitAPIException
	 */
	private List<String> getFilesPathsByCommit(RevCommit commit)
			throws IOException, MissingObjectException {

		List<String> paths = new ArrayList();

		RevWalk rw = new RevWalk(localRepo);
		ObjectId head = localRepo.resolve(Constants.HEAD);
		RevCommit parent = rw.parseCommit(commit.getParent(0).getId());
		DiffFormatter df = new DiffFormatter(DisabledOutputStream.INSTANCE);

		df.setRepository(localRepo);
		df.setDiffComparator(RawTextComparator.DEFAULT);
		df.setDetectRenames(true);

		List<DiffEntry> diffs = df.scan(parent.getTree(), commit.getTree());

		for (DiffEntry diff : diffs) {
			paths.add(diff.getNewPath());
		}
		return paths;
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
