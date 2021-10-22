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
