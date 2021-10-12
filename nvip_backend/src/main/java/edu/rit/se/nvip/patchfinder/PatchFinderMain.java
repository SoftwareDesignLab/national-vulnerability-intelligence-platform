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

import edu.rit.se.nvip.db.DatabaseHelper;

/**
 * Start patch finder for a given repository list (as .csv)
 * 
 * @author 15854
 *
 */
public class PatchFinderMain {

	private static DatabaseHelper db;
	private static final String[] ADDRESS_BASES = { "https://github.com/", "https://bitbucket.org/" };

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

		// Create github URLs based on CPEs for given CVEs
		for (Entry<String, ArrayList<String>> cpe : cpes.entrySet()) {
			parseURL(cpe);
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
		Map<String, ArrayList<String>> cpe = db.getCPEByCVE(cve_id);

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

		if (!wordArr[3].equals("*")) {

			HashSet<String> addresses = initializeAddresses(wordArr[3]);

			for (String address : addresses) {

				if (!wordArr[4].equals("*"))
					address += wordArr[4];

				String newAddress = testConnection(address, cpe);

				if (!newAddress.isEmpty()) {
					insertPatchURL(newAddress, cpe);
					break;
				}

			}

		} else if (!wordArr[4].equals("*")) {

			for (String base : ADDRESS_BASES) {
				String newAddress = testConnection(base + wordArr[4], cpe);
				if (!newAddress.isEmpty()) {
					insertPatchURL(newAddress, cpe);
					break;
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
	 * Tests connetion of a crafted URL, If successful, insert in DB
	 * 
	 * @param address
	 * @param cpe
	 * @return
	 * @throws IOException
	 */
	private static String testConnection(String address, Entry<String, ArrayList<String>> cpe) throws IOException {

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

			return newURL;
		}
		return "";
	}

	/**
	 * 
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
