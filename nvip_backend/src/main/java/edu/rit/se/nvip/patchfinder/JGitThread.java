package edu.rit.se.nvip.patchfinder;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.patchfinder.commits.JGitParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JGitThread implements Runnable {
	private HashMap<Integer, String> sources;
	private String clonePath;
	private static final Logger logger = LogManager.getLogger(JGitCVEPatchDownloader.class.getName());
	private JGitParser previous;
	private static final DatabaseHelper db = DatabaseHelper.getInstance();

	public JGitThread(HashMap<Integer, String> sources, String cP) {
		this.sources = sources;
		this.clonePath = cP;
	}

	@Override
	public void run() {
		for (Map.Entry<Integer, String> source : sources.entrySet()) {
			try {
				JGitParser repo = new JGitParser(source.getValue() + ".git", this.clonePath);
				repo.cloneRepository();
				Map<Date, ArrayList<String>> commits = repo.parseCommits(db.getCveId(source.getKey()+""));
				if (commits.isEmpty()) {
					JGitCVEPatchDownloader.deletePatchSource(source.getValue());
				} else {
					for (java.util.Date commit : commits.keySet()) {
						JGitCVEPatchDownloader.insertPatchCommitData(source.getValue(), commits.get(commit).get(0), commit, commits.get(commit).get(1));
					}
				}

				if (previous != null) {
					previous.deleteRepository();
				}

				previous = repo;

			} catch (Exception e) {
				logger.error(e.toString());
			}
		}
	}
}
