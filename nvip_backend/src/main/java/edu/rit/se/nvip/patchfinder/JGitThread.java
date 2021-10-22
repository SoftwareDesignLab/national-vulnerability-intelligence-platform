package edu.rit.se.nvip.patchfinder;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

import edu.rit.se.nvip.patchfinder.commits.JGitParser;

public class JGitThread extends Thread {
	private HashMap<Integer, String> sources;
	private String clonePath;
	private JGitParser myParser = null;

	public JGitThread(HashMap<Integer, String> sources, String cP) {
		this.sources = sources;
		this.clonePath = cP;
	}

	public void run() {
		for (String cveId : cveIds) {
			try {
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
			} catch (Exception e) {
				System.err.println(e.toString());
			}
		}
	}
}
