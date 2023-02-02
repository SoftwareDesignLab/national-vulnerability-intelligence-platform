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
package edu.rit.se.nvip.utils;

import java.io.File;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.CloneCommand;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.PullCommand;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.lib.StoredConfig;

/**
 * 
 * Clone/pull a Git repo from <remotePath> to <localPath>
 * 
 * @author axoeec
 *
 */
public class GitController {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private String localPath;
	private String remotePath;

	public GitController(String localPath, String remotePath) {
		super();
		this.localPath = localPath;
		this.remotePath = remotePath;
	}

	/**
	 * pull repo
	 * 
	 * @return
	 */
	public boolean pullRepo() {
		logger.info("Checking for updates for {} repo!...", localPath);
		try (FileRepository localRepo = new FileRepository(localPath + "/.git");) {
			try (Git git = new Git(localRepo)) {
				PullCommand pull = git.pull();
				pull.call();
			} catch (Exception e) {
				logger.error("Error while pulling repo {} {} ", remotePath, e.toString());
				return false;
			}
		} catch (Exception e) {
			logger.error("Error while initializing FileRepository for {}: {} ", remotePath, e.toString());
			return false;
		}
		return true;
	}

	/**
	 * clone git repo
	 * 
	 * @return
	 */
	public boolean cloneRepo() {
		Git git = null;
		File localFileDir;
		try {
			logger.info("{} repository does not exist! Cloning repo now, this will take some time, please wait!...", localPath);
			localFileDir = new File(localPath);
			CloneCommand cloneCommand = Git.cloneRepository();
			cloneCommand.setURI(remotePath);
			cloneCommand.setDirectory(localFileDir);
			cloneCommand.call();

			git = Git.open(localFileDir);
			StoredConfig config = git.getRepository().getConfig();
			config.setString("branch", "master", "merge", "refs/heads/master");
			config.setString("branch", "master", "remote", "origin");
			config.setString("remote", "origin", "fetch", "+refs/heads/*:refs/remotes/origin/*");
			config.setString("remote", "origin", "url", remotePath);
			config.save();
		} catch (Exception e) {
			logger.error("Error while cloning repo at: " + remotePath + ", " + e.toString());
			return false;
		} finally {
			git.close();
		}
		return true;
	}

}
