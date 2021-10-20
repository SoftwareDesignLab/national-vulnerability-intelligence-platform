package edu.rit.se.nvip.patchfinder;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

	private static final Logger logger = LogManager.getLogger(PatchFinderMain.class.getName());

	private static DatabaseHelper db;
	private static final String[] ADDRESS_BASES = { "https://github.com/" };
	private static String keyword1 = "";
	private static String keyword2 = "";
	private static Entry<String, ArrayList<String>> currentCPE;
	private static boolean advanceSearchCheck;
	private static String previousURL;

	/**
	 * Main method just for calling to find all patch URLs
	 * 
	 * @param args
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String[] args) throws IOException, InterruptedException {

		logger.info("PatchFinder Started!");

		int i = 0;

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpes = db.getCPEsAndCVE();

		if (args.length > 0) {

			if (args[0].equals("true")) {
				parseURLByProductId(Integer.parseInt(args[1]));
			} else {
				parseURLByCVE(args[1]);
			}

		} else {
			// Create github URLs based on CPEs for given CVEs
			for (Entry<String, ArrayList<String>> cpe : cpes.entrySet()) {
				currentCPE = cpe;
				parseURL();
				i++;
				if (i % 100 == 0) {
					logger.info(i + " CPEs Parsed!");
				}
			}
		}

		logger.info("PatchFinder Finished!");

	}

	/**
	 * Gets a URL via a specified CVE and parses and tests
	 * 
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void parseURLByCVE(String cve_id) throws IOException, InterruptedException {

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpe = db.getCPEsByCVE(cve_id);

		for (Entry<String, ArrayList<String>> entry : cpe.entrySet()) {
			currentCPE = entry;
			parseURL();
		}

	}

	/**
	 * Gets a URL via a specified product Id and parses and tests
	 * 
	 * @param product_id
	 * @throws InterruptedException
	 * @throws IOException
	 */
	public static void parseURLByProductId(int product_id) throws IOException, InterruptedException {
		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpe = db.getCPEById(product_id);
		for (Entry<String, ArrayList<String>> entry : cpe.entrySet()) {
			currentCPE = entry;
			parseURL();
		}
	}

	/**
	 * Parses URL with github.com base and cpe keywords tests connection and inserts
	 * into DB if so.
	 * 
	 * @param cpe
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private static void parseURL() throws IOException, InterruptedException {

		advanceSearchCheck = true;
		String[] wordArr = currentCPE.getKey().split(":");
		ArrayList<String> newAddresses = null;

		// Parse keywords from CPE to create links for github, bitbucket and gitlab
		// Also checks if the keywords are the same as the previous, indicating the link
		// is already used
		if (!wordArr[3].equals("*") && !keyword1.equals(wordArr[3])) {

			keyword1 = wordArr[3];
			HashSet<String> addresses = initializeAddresses();

			for (String address : addresses) {

				if (!wordArr[4].equals("*")) {

					keyword2 = wordArr[4];
					address += keyword2;

					newAddresses = testConnection(address);

				} else {
					newAddresses = testConnection(address);
				}

				if (checkAddressLst(newAddresses)) {
					break;
				}

			}

		} else if (!wordArr[4].equals("*") && !keyword2.equals(wordArr[4])) {

			keyword2 = wordArr[4];

			for (String base : ADDRESS_BASES) {

				String address = base + keyword2;

				newAddresses = testConnection(address);

				if (checkAddressLst(newAddresses)) {
					break;
				}

			}
		}

	}

	/**
	 * Repeated method used to check if a list of collected addresses is empty or
	 * not If so, perform an advanced search for correct repo URLs. If not, insert
	 * the following
	 * 
	 * @param addresses
	 * @throws InterruptedException
	 */
	private static boolean checkAddressLst(ArrayList<String> addresses) throws InterruptedException {
		// Place all successful links in DB
		if (!addresses.isEmpty()) {
			insertPatchURLs(addresses);
			return true;
		} else {
			addresses = advanceParseSearch();
			if (!addresses.isEmpty()) {
				insertPatchURLs(addresses);
				return true;
			} else {
				logger.info("No Repo Found");
			}
		}

		return false;
	}

	/**
	 * Inistializes the address set with additional addresses based on cpe keywords
	 */
	private static HashSet<String> initializeAddresses() {
		HashSet<String> addresses = new HashSet<>();

		for (String base : ADDRESS_BASES) {
			addresses.add(base + keyword1 + "/");
			addresses.add(base + keyword1 + "_");
			addresses.add(base + keyword1 + "-");
			addresses.add(base + keyword1);
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
	 * @throws InterruptedException
	 */
	private static ArrayList<String> testConnection(String address) throws IOException, InterruptedException {

		logger.info("Testing Connection for address: " + address);
		ArrayList<String> urlList = new ArrayList<String>();

		URL url = new URL(address);
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		int response = urlConnection.getResponseCode();
		Thread.sleep(2000);

		// Check if the url leads to an actual GitHub repo
		// If so, push the source link into the DB
		if (response == HttpURLConnection.HTTP_OK) {
			urlConnection.connect();

			// Get correct URL in case of redirection
			InputStream is = urlConnection.getInputStream();
			String newURL = urlConnection.getURL().toString();

			urlConnection.disconnect();
			is.close();

			LsRemoteCommand lsCmd = new LsRemoteCommand(null);

			lsCmd.setRemote(newURL + ".git");

			try {
				lsCmd.call();
				logger.info("Successful Git Remote Connection at: " + newURL);
				urlList.add(newURL);
			} catch (Exception e) {
				// If unsuccessful on git remote check, perform a advaced search, assuming the
				// link instead leads to
				// a github company home page
				logger.error(e.getMessage());
				return searchForRepos(newURL);
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
	 * @throws InterruptedException
	 */
	private static ArrayList<String> searchForRepos(String newURL) throws InterruptedException {
		logger.info("Grabbing repos from github user page...");

		ArrayList<String> urls = new ArrayList<String>();

		// Obtain all linls from the current company github page
		try {
			Document doc = Jsoup.connect(newURL).timeout(0).get();
			Thread.sleep(2000);

			Elements links = doc.select("a[href]");

			// Loop through all links to find the repo page link (repo tab)
			for (Element link : links) {
				if (link.attr("href").contains("repositories")) {

					newURL = ADDRESS_BASES[0] + link.attr("href").substring(1);

					Document reposPage = Jsoup.connect(newURL).timeout(0).get();

					Elements repoLinks = reposPage.select("li.Box-row a.d-inline-block[href]");

					// Loop through all repo links in the repo tab page and test for git clone
					// verification
					// Return the list of all successful links afterwards
					urls = testLinks(repoLinks);

					// Check if the list is empty, if so it could be because the wrong html element
					// was pulled for repoLinks. In this case, try again with a different element
					// assuming the link redirects to a github profile page instead of a company
					// page
					if (urls.isEmpty()) {
						repoLinks = reposPage.select("div.d-inline-block a[href]");
						urls = testLinks(repoLinks);
					}
				}
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}

		return urls;

	}

	/**
	 * Method to loop through given repo links and verify git connection, returns
	 * list of all successful links
	 * 
	 * @return
	 */
	private static ArrayList<String> testLinks(Elements repoLinks) {
		ArrayList<String> urls = new ArrayList<String>();
		String repoURL;

		for (Element repoLink : repoLinks) {
			logger.info("Found possible repo at:" + repoLink.attr("abs:href"));

			repoURL = repoLink.attr("abs:href");
			String innerText = repoLink.text();

			if (verifyGitRemote(repoURL, innerText)) {
				urls.add(repoURL);
			}
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
	 * @throws InterruptedException
	 */
	private static ArrayList<String> advanceParseSearch() throws InterruptedException {

		String searchParams = ADDRESS_BASES[0] + "search?q=";
		ArrayList<String> urls = new ArrayList<String>();

		if (advanceSearchCheck) {

			logger.info("Conducting Advanced Search...");

			if (!keyword1.equals("*")) {
				searchParams += keyword1;
			}

			if (!keyword2.equals("*")) {
				searchParams += "+" + keyword2;
			}

			// Perform search on github using query strings in the url
			// Loop through the results and return a list of all verified repo links that
			// match with the product

			try {
				Document searchPage = Jsoup.connect(searchParams + "&type=repositories").timeout(0).get();

				Elements searchResults = searchPage.select("li.repo-list-item a[href]");

				for (Element searchResult : searchResults) {

					if (!searchResult.attr("href").isEmpty()) {

						String newURL = searchResult.attr("abs:href");
						String innerText = searchResult.text();

						if (verifyGitRemote(newURL, innerText)) {
							urls.add(newURL);
						}
					}

				}

				advanceSearchCheck = false;
			} catch (IOException e) {
				logger.error(e.getMessage());
			}
		}
		return urls;
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
	private static boolean verifyGitRemote(String repoURL, String innerText) {

		// Verify if the repo is correlated to the product by checking if the keywords
		// lie in the inner text of the html link via regex
		if (Pattern.compile(Pattern.quote(keyword1), Pattern.CASE_INSENSITIVE).matcher((CharSequence) innerText).find()
				|| Pattern.compile(Pattern.quote(keyword2), Pattern.CASE_INSENSITIVE).matcher((CharSequence) innerText)
						.find()) {

			if (!repoURL.equals(previousURL)) {

				previousURL = repoURL;

				LsRemoteCommand lsCmd = new LsRemoteCommand(null);

				lsCmd.setRemote(repoURL + ".git");

				try {
					lsCmd.call();
					logger.info("Successful Git Remote Connection at: " + repoURL);
					return true;
				} catch (Exception e) {
					logger.error(e.getMessage());
				}
			}
		}
		return false;
	}

	/**
	 * Inserts a successfully connected Patch URL to the DB
	 */
	private static void insertPatchURLs(ArrayList<String> addresses) {
		for (String address : addresses) {

			try {
				logger.info("Inserting Patch Source for URL: " + address);

				int urlId = db.getPatchSourceId(address);

				if (urlId == -1) {
					db.insertPatchSourceURL(Integer.parseInt(currentCPE.getValue().get(0)), address);
				}

			} catch (Exception e) {
				logger.error(e.getMessage());
			}

		}
	}

}
