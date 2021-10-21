package edu.rit.se.nvip.cvepatches.commits;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.egit.github.core.RepositoryCommit;
import org.eclipse.egit.github.core.RepositoryId;
import org.eclipse.egit.github.core.client.GitHubClient;
import org.eclipse.egit.github.core.service.CommitService;

/**
 *
 * @author Joanna C. S. Santos <jds5109@rit.edu>
 */
public class GithubParser {

	private static final String REGEX_CVE = "(CVE-[0-9]+-[0-9]+)";
	// FIXME this regex won't work very well for things like: fixed bugs 123 and
	// 456. In such case, the patch is for both bugs!
	private static final String REGEX_BUG = "bug|BUG|Bug[ #]*([0-9]+)";
	private static final Pattern PATTERN_CVES = Pattern.compile(REGEX_CVE);
	private static final Pattern PATTERN_BUGS = Pattern.compile(REGEX_BUG);
	private final String user;
	private final String repo;
	private final String username;
	private final String password;

	private final List<GithubCommit> fixCommits;

	public GithubParser(String user, String repo, String username, String password) {
		this.user = user;
		this.repo = repo;
		this.username = username;
		this.password = password;
		this.fixCommits = new ArrayList<>();

	}

	public void parseCommits() throws IOException {
		// Basic authentication
		GitHubClient client = new GitHubClient();
		client.setCredentials(username, password);

		CommitService service = new CommitService(client);

		RepositoryId repository = new RepositoryId(user, repo);
		List<RepositoryCommit> commitsList = service.getCommits(repository);

		System.out.println("Found " + commitsList.size() + " commits");
		commitsList.stream().forEachOrdered((repoCommit) -> {
			Commit commit = repoCommit.getCommit();
			String message = commit.getMessage();
			Matcher matcherCve = PATTERN_CVES.matcher(message);
			List<String> foundCves = new ArrayList<>();
			while (matcherCve.find()) {
				System.out.println("Found CVE Commit" + matcherCve.group(0));
				foundCves.add(matcherCve.group(0));
			}
			List<String> foundBugs = new ArrayList<>();
			Matcher matcherBug = PATTERN_BUGS.matcher(message);
			if (matcherBug.find()) {
				System.out.println("Found BUG commit" + matcherBug.group(0));
				foundBugs.add(matcherBug.group(0));
			}
			if (foundBugs.size() > 0 || foundCves.size() > 0) {
				GithubCommit githubCommit = new GithubCommit(repoCommit.getSha(), foundCves, foundBugs, commit,
						repoCommit.getFiles());
				this.fixCommits.add(githubCommit);
			}
		});
	}

	public List<GithubCommit> getCveCommits() {
		List<GithubCommit> cveCommits = new ArrayList<>();
		fixCommits.stream().filter((c) -> (c.isFixingCve())).forEachOrdered((c) -> {
			cveCommits.add(c);
		});
		return cveCommits;
	}

	public List<GithubCommit> getBugCommits() {
		List<GithubCommit> bugCommits = new ArrayList<>();
		fixCommits.stream().filter((c) -> (c.isFixingBug())).forEachOrdered((c) -> {
			bugCommits.add(c);
		});
		return bugCommits;
	}

	public List<GithubCommit> getFixCommits() {
		List<GithubCommit> bugCommits = new ArrayList<>();
		fixCommits.stream().filter((c) -> (c.isFixingBug())).forEachOrdered((c) -> {
			bugCommits.add(c);
		});
		return bugCommits;
	}

}
