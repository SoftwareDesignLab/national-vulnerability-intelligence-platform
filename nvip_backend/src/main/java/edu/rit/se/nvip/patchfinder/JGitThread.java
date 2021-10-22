package edu.rit.se.nvip.patchfinder;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

import edu.rit.se.nvip.patchfinder.commits.JGitParser;

public class JGitThread extends Thread {
	private ArrayBlockingQueue<String> allRepos;
	private String clonePath;
	private ArrayList<String> cveIds;
	private JGitParser myParser = null;

	public JGitThread(ArrayBlockingQueue<String> repos, String cP, ArrayList<String> cveIds) {
		this.allRepos = repos;
		this.clonePath = cP;
		this.cveIds = cveIds;
	}

	public void run() {
		for (String cveId : cveIds) {
			try {
				String r = this.allRepos.poll();
				if (r != null) {
					JGitParser repo = new JGitParser(r + ".git", this.clonePath);
					repo.cloneRepository();
					Map<Date, ArrayList<String>> commits = repo.parseCommits(cveId);

					if (commits.isEmpty()) {
						JGitCVEPatchDownloader.deletePatchSource(r);
					} else {
						for (java.util.Date commit : commits.keySet()) {
							JGitCVEPatchDownloader.insertPatchCommitData(r, commits.get(commit).get(0), commit, commits.get(commit).get(1));
						}
					}

					if (this.myParser != null) {
						this.myParser.deleteRepository();
					}

					this.myParser = repo;
				}
			} catch (Exception e) {
				System.err.println(e.toString());
			}
		}
	}
}
