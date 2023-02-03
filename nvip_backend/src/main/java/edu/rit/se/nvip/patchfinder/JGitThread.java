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
	private final HashMap<Integer, String> sources;
	private final String clonePath;
	private static final Logger logger = LogManager.getLogger(JGitCVEPatchDownloader.class.getName());
	private JGitParser previous;
	private static final DatabaseHelper db = DatabaseHelper.getInstance();
	private final JGitCVEPatchDownloader patchDownloader;

	public JGitThread(HashMap<Integer, String> sources, String cP, JGitCVEPatchDownloader patchDownloader) {
		this.sources = sources;
		this.clonePath = cP;
		this.patchDownloader = patchDownloader;
	}

	@Override
	public void run() {
		for (Map.Entry<Integer, String> source : sources.entrySet()) {
			try {
				JGitParser repo = new JGitParser(source.getValue() + ".git", this.clonePath);
				repo.cloneRepository();
				Map<Date, ArrayList<String>> commits = repo.parseCommits(db.getCveId(source.getKey()+""));
				if (commits.isEmpty()) {
					patchDownloader.deletePatchSource(source.getValue());
				} else {
					for (java.util.Date commit : commits.keySet()) {
						patchDownloader.insertPatchCommitData(source.getValue(), commits.get(commit).get(0), commit, commits.get(commit).get(1));
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
