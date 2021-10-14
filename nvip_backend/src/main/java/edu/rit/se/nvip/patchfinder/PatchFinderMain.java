package edu.rit.se.nvip.patchfinder;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.eclipse.jgit.api.LsRemoteCommand;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.db.DatabaseHelper;

/**
 * Start patch finder for a given repository list (as .csv)
 * 
 * @author 15854
 *
 */
public class PatchFinderMain {

	private static DatabaseHelper db;
	private static final String[] ADDRESS_BASES = { "https://github.com/", "https://bitbucket.org/",
			"https://gitlab.com/" };

	/**
	 * Main method just for calling to find all patch URLs
	 * 
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {

		System.out.println("PatchFinder Started!");

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpes = db.getCPEsByCVE();

		if (!args[0].isEmpty()) {
			parseURLByCVE(args[0]);
		} else {
			// Create github URLs based on CPEs for given CVEs
			for (Entry<String, ArrayList<String>> cpe : cpes.entrySet()) {
				parseURL(cpe);
			}
		}

		System.out.println("PatchFinder Finished!");

	}

	/**
	 * Gets a URL via a specified CVE and parses and tests
	 * 
	 * @throws IOException
	 */
	public static void parseURLByCVE(String cve_id) throws IOException {

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpe = db.getCPEsByCVE(cve_id);

		System.out.print(cpe);

		if (cpe.size() != 0) {
			for (Entry<String, ArrayList<String>> entry : cpe.entrySet()) {
				parseURL(entry);
			}
		}

	}

	/**
	 * Parses URL with github.com base and cpe keywords tests connection and inserts
	 * into DB if so.
	 * 
	 * @param cpe
	 * @throws IOException
	 */
	private static void parseURL(Entry<String, ArrayList<String>> cpe) throws IOException {

		String[] wordArr = cpe.getKey().split(":");
		ArrayList<String> newAddresses = null;

		// Parse keywords from CPE to create links for github, bitbucket and gitlab
		if (!wordArr[3].equals("*")) {

			HashSet<String> addresses = initializeAddresses(wordArr[3]);

			for (String address : addresses) {

				if (!wordArr[4].equals("*")) {
					address += wordArr[4];
					newAddresses = testConnection(address, wordArr[3], wordArr[4], cpe);
				} else {
					newAddresses = testConnection(address, wordArr[3], null, cpe);
				}

				// Place all successful links in DB
				if (!newAddresses.isEmpty()) {
					for (String newAddress : newAddresses) {
						insertPatchURL(newAddress, cpe);
					}
				} else {
					// advanceParseSearch(address, wordArr[3], wordArr[4], cpe);
				}

			}

		} else if (!wordArr[4].equals("*")) {

			for (String base : ADDRESS_BASES) {
				newAddresses = testConnection(base + wordArr[4], null, wordArr[4], cpe);

				if (!newAddresses.isEmpty()) {
					for (String newAddress : newAddresses) {
						insertPatchURL(newAddress, cpe);
					}
				} else {
					// advanceParseSearch(newAddress, wordArr[3], wordArr[4], cpe);
				}
			}

		}

	}

	/**
	 * Inistializes the address set with additional addresses based on cpe keywords
	 */
	private static HashSet<String> initializeAddresses(String keyword) {
		HashSet<String> addresses = new HashSet<>();

		for (String base : ADDRESS_BASES) {
			addresses.add(base + keyword + "/");
			addresses.add(base + keyword + "_");
			addresses.add(base + keyword + "-");
			addresses.add(base + keyword);
		}

		return addresses;
	}

	/**
	 * Tests connetion of a crafted URL, If successful, insert in DB else, search
	 * for correct repo via github company page (Assuming the link directs to it for
	 * now)
	 * 
	 * @param address
	 * @param cpe
	 * @return
	 * @throws IOException
	 */
	private static ArrayList<String> testConnection(String address, String keyword1, String keyword2,
			Entry<String, ArrayList<String>> cpe) throws IOException {

		ArrayList<String> urlList = new ArrayList<String>();

		URL url = new URL(address);
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		int response = urlConnection.getResponseCode();

		// Check if the url leads to an actual GitHub repo
		// If so, push the source link into the DB
		if (response == HttpURLConnection.HTTP_OK) {
			urlConnection.connect();

			InputStream is = urlConnection.getInputStream();
			String newURL = urlConnection.getURL().toString();

			urlConnection.disconnect();
			is.close();

			LsRemoteCommand lsCmd = new LsRemoteCommand(null);

			lsCmd.setRemote(newURL + ".git");

			try {
				lsCmd.call();
				urlList.add(newURL);
			} catch (Exception e) {
				// If unsuccessful on git remote check, perform a advaced search, assuming the
				// link instead leads to
				// a github company home page
				System.out.println(e);
				return searchForRepos(keyword1, keyword2, newURL);
			}

		}
		return urlList;
	}

	/**
	 * Searches for all links within a comapanies github page to find the correct
	 * repo the cpe is correlated to. Uses keywords from cpe to validate and checks
	 * for git remote connection with found links
	 * 
	 * Uses jSoup framework
	 * 
	 * @param keyword1
	 * @param keyword2
	 * @param newURL
	 */
	private static ArrayList<String> searchForRepos(String keyword1, String keyword2, String newURL) {
		System.out.println("Grabbing repos...");

		ArrayList<String> urls = new ArrayList<String>();

		// Obtain all linls from the current company github page
		try {
			Document doc = Jsoup.connect(newURL).get();
			Elements links = doc.select("a[href]");

			// Loop through all links to find the repo page link (repo tab)
			for (Element link : links) {
				if (link.attr("href").contains("repositories")) {

					newURL = ADDRESS_BASES[0] + link.attr("href").substring(1);

					Document reposPage = Jsoup.connect(newURL).get();

					Elements repoLinks = reposPage.select("li.Box-row a.d-inline-block[href]");

					// Loop through all repo links in the repo tab page and test for git clone
					// verification
					// Retrun the list of all successful links afterwards
					for (Element repoLink : repoLinks) {
						if (!repoLink.attr("href").isEmpty()) {

							System.out.println(repoLink.attr("abs:href"));
							newURL = repoLink.attr("abs:href");

							if (verifyGitRemote(newURL, keyword1, keyword2)) {
								urls.add(newURL);
							}

						}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return urls;

	}

	/**
	 * Performs an advanced search for the repo link(s) for a CPE using the Github
	 * search feature
	 * 
	 * TODO: Change the return type to an array or list for multiple links
	 * 
	 * @param address
	 * @param keyword1
	 * @param keyword2
	 * @param cpe
	 * @return
	 */
	private static String advanceParseSearch(String keyword1, String keyword2, Entry<String, ArrayList<String>> cpe) {

		String searchParams = ADDRESS_BASES[0] + "search?q=";

		if (!keyword1.equals("*")) {
			searchParams += keyword1;
		}

		if (!keyword2.equals("*")) {
			searchParams += "+" + keyword2;
		}

		try {
			Document searchPage = Jsoup.connect(searchParams + "&type=repositories").get();

			Elements searchResults = searchPage.select("li.repo-list-item a[href]");

			for (Element searchResult : searchResults) {

				if (!searchResult.attr("href").isEmpty()) {

					String newURL = searchResult.attr("abs:href");
					if (verifyGitRemote(newURL, keyword1, keyword2)) {
						return newURL;
					}
				}

			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Method used for verifying Git remote connection to created url via keywords,
	 * checks if the keywords are included as well before performing connection
	 * 
	 * @param newURL
	 * @param keyword1
	 * @param keyword2
	 * @return
	 */
	private static boolean verifyGitRemote(String newURL, String keyword1, String keyword2) {
		if (Pattern.compile(Pattern.quote(keyword1), Pattern.CASE_INSENSITIVE).matcher((CharSequence) newURL).find()
				&& Pattern.compile(Pattern.quote(keyword2), Pattern.CASE_INSENSITIVE).matcher((CharSequence) newURL)
						.find()) {

			LsRemoteCommand lsCmd = new LsRemoteCommand(null);

			lsCmd.setRemote(newURL + ".git");

			try {
				lsCmd.call();
				System.out.println("Successful connection at: " + newURL);
				return true;
			} catch (Exception e) {
				System.out.println(e);
			}

		}
		return false;
	}

	/**
	 * Inserts a successfully connected Patch URL to the DB
	 */
	private static void insertPatchURL(String address, Entry<String, ArrayList<String>> cpe) {
		try {
			db.deletePatch(cpe.getValue().get(0));
			db.insertPatch(cpe.getValue().get(0), cpe.getValue().get(1), address, null, null);
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

}
