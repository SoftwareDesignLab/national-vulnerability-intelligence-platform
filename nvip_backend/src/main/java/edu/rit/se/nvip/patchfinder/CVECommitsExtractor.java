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

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.rit.se.nvip.patchfinder.commits.GithubCommit;
import edu.rit.se.nvip.patchfinder.commits.GithubParser;

/**
 *
 * @author Joanna C. S. Santos <jds5109@rit.edu>
 */
public class CVECommitsExtractor {

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {

		if (args.length < 4) {
			printUsage();
			System.exit(-1);
		}

		String repoPath = args[0];
		String username = args[2];
		String password = args[3];

		try {
			String[] parts = repoPath.split("/");
			GithubParser parser = new GithubParser(parts[0], parts[1], username, password);
			parser.parseCommits();
			List<GithubCommit> cveCommits = parser.getCveCommits();
			// DataManager dataManager = new DataManager();
			String csvOutputPath = repoPath.replace("/", "__") + "_cve-commits.csv";
			String csvCommitsFiles = repoPath.replace("/", "__") + "_cve-files.csv";
			// dataManager.saveCommits(new File(csvOutputPath), cveCommits);
			// dataManager.savePatchMetadata(new File(csvCommitsFiles), cveCommits);
		} catch (IOException ex) {
			Logger.getLogger(CVECommitsExtractor.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private static void printUsage() {
		System.out.println("Usage:");
		System.out.println("\t<GitHub repository> <GitHub_Username> <GitHub_Password>");
	}

}
