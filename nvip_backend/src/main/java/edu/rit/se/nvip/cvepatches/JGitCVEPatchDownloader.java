package edu.rit.se.nvip.cvepatches;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.util.FileUtils;

import edu.rit.se.nvip.cvepatches.commits.JGitParser;
import edu.rit.se.nvip.db.DatabaseHelper;

public final class JGitCVEPatchDownloader {

	private static final Logger logger = LogManager.getLogger(JGitCVEPatchDownloader.class.getName());
	private static JGitParser previousRepo = null;
	private static final DatabaseHelper db = DatabaseHelper.getInstance();

	/**
	 * TODO: Update this so that it can pull CVE IDs from vulnerability table for
	 * the 3rd parameter Parses out patch data from a preset list of repos within a
	 * csv file
	 * 
	 * @param repoFile
	 * @param clonePath
	 * @throws IOException
	 */
	public static void parse(File repoFile, String clonePath) throws IOException {
		List<String> repos = processInputFile(repoFile);
		repos = new ArrayList<>(new HashSet<>(repos));
		for (int i = 0; i < repos.size(); i++) {
			pullCommitData(repos.get(i), clonePath, "");
		}
	}

	/**
	 * Extract Method called multiple times for parsing an individual URL
	 * 
	 * @param clonePath
	 * @throws SQLException
	 * @throws IOException
	 * @throws GitAPIException
	 */
	public static void parse(String clonePath, String limit) throws IOException {

		File dir = new File(clonePath);
		FileUtils.delete(dir, 1);

		try {
			Connection conn = getConn();

			String querySourceUrl = "SELECT vuln_id, source_url FROM patchsourceurl";
			String queryCveId = "SELECT cve_id FROM vulnerability WHERE vuln_id = ?;";

			if (limit != null) {
				int max = Integer.parseInt(limit);
				querySourceUrl += " LIMIT " + max;
			}

			querySourceUrl += ";";
			PreparedStatement stmtUrl = conn.prepareStatement(querySourceUrl);
			ResultSet resultUrls = stmtUrl.executeQuery(querySourceUrl);

			while (resultUrls.next()) {
				PreparedStatement stmtCveID = conn.prepareStatement(querySourceUrl);
				ResultSet resultCveId = stmtCveID.executeQuery(queryCveId);
				pullCommitData(resultUrls.getString("source_url"), clonePath, resultCveId.getString("cve_id"));
			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Extract Method used for pulling commit data from a repo vi a source link and
	 * parsing commits for any commits related to CVEs
	 * 
	 * @param sourceURL
	 * @param clonePath
	 * @throws IOException
	 * @throws GitAPIException
	 */
	private static void pullCommitData(String sourceURL, String clonePath, String cveId) {

		JGitParser parser = new JGitParser(sourceURL + ".git", clonePath);

		parser.cloneRepository();

		Map<java.util.Date, ArrayList<String>> commits = parser.parseCommits(cveId);

		if (commits.isEmpty()) {
			deletePatchSource(sourceURL);
		} else {
			for (java.util.Date commit : commits.keySet()) {
				insertPatchCommitData(sourceURL, commits.get(commit).get(0), commit, commits.get(commit).get(1));
			}
		}

		// Delete previously cloned local repo after storing
		// patch/commit data (to ensure the .pack file is closed in the .git directory)
		if (previousRepo != null) {
			previousRepo.deleteRepository();
		}
		previousRepo = parser;

	}

	/**
	 * TODO: Update this so that it can pull CVE IDs from vulnerability table for
	 * the 3rd parameter
	 * 
	 * @param repoFile
	 * @param clonePath
	 * @throws IOException
	 */
	public static void parseCLI(File repoFile, String clonePath) throws IOException {
		List<String> repos = processInputFile(repoFile);
		for (int i = 0; i < repos.size(); i++) {
			JGitParser parser = new JGitParser(repos.get(i) + ".git", clonePath);
			parser.cloneRepository();
			parser.parseCommits("");
		}
	}

	/**
	 * @param clonePath
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public void parseCLIConcurrent(String clonePath) throws InterruptedException {

		int maxThreads = Runtime.getRuntime().availableProcessors();

		ExecutorService es = Executors.newCachedThreadPool();
		for (int i = 0; i < maxThreads; i++) {
			// es.execute(new JGitThread(clonePath, cveId));
		}
		es.shutdown();
	}

	/**
	 * Updates patch field by adding provided commit message and date that was
	 * pulled when parsing commits
	 * 
	 * @param commitDate
	 * @param commitMessage
	 */
	private static void insertPatchCommitData(String sourceURL, String commitId, java.util.Date commitDate,
			String commitMessage) {

		logger.info("Inserting commit data to patchcommit table...");
		String selUrlIdQuery = "SELECT source_url_id FROM patchsourceurl WHERE source_url = ?;";
		String insertCommitQuery = "INSERT INTO patchcommit (source_id, commit_url, commit_date, commit_message) VALUES (?, ?, ?, ?);";

		if (commitMessage.length() > 300) {
			commitMessage = commitMessage.substring(0, 299);
		}

		commitId = commitId.split(" ")[1];

		try {
			Connection conn = getConn();

			PreparedStatement pstmt = conn.prepareStatement(selUrlIdQuery);
			pstmt.setString(1, sourceURL);
			ResultSet rs = pstmt.executeQuery();

			if (rs.next()) {
				pstmt = conn.prepareStatement(insertCommitQuery);
				pstmt.setInt(1, rs.getInt("source_url_id"));
				pstmt.setString(2, sourceURL + "/commit/" + commitId);
				pstmt.setDate(3, new java.sql.Date(commitDate.getTime()));
				pstmt.setString(4, commitMessage);
				pstmt.executeUpdate();
				logger.info("Inserted commit from source ID: " + rs.getInt("source_url_id"));
			}

		} catch (Exception e) {
			logger.error((e.getMessage()));
		}
	}

	/**
	 * Method used to delete Patch entries that lead to no commit data related to
	 * CVEs or patches
	 * 
	 * @param sourceURL
	 */
	private static void deletePatchSource(String sourceURL) {

		logger.info("Deleting patch from database...");

		String selUrlIdQuery = "SELECT source_url_id FROM patchsourceurl WHERE source_url = ?;";
		String delPatchQuery = "DELETE FROM patchcommit WHERE source_id = ?;";
		String delPatchUrlQuery = "DELETE FROM patchsourceurl WHERE source_url_id = ?;";

		try {

			PreparedStatement pstmt = conn.prepareStatement(selUrlIdQuery);
			pstmt.setString(1, sourceURL);

			ResultSet rs = pstmt.executeQuery();

			if (rs.next()) {
				int id = rs.getInt("source_url_id");

				// Delete Patch Entry
				pstmt = conn.prepareStatement(delPatchQuery);
				pstmt.setInt(1, id);
				pstmt.executeUpdate();

				// Delete Patch URL Entry
				pstmt = conn.prepareStatement(delPatchUrlQuery);
				pstmt.setInt(1, id);
				pstmt.executeUpdate();

			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 *
	 * @param file
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static List<String> processInputFile(File file) throws FileNotFoundException, IOException {
		ArrayList<String> repos = new ArrayList<String>();

		BufferedReader br = new BufferedReader(new FileReader(file));
		String line;
		br.readLine(); // ignoring id in csv
		while ((line = br.readLine()) != null) {
			String[] entries = line.split(",");

			String repo = entries[0].trim();
			repos.add(repo.replace("https://api.", "https://").replace(".com/repos/", ".com/"));
		}
		return repos;
	}
}
