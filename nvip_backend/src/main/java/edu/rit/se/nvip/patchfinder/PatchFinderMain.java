package edu.rit.se.nvip.patchfinder;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
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

	public static void main(String[] args) throws IOException {

		System.out.println("PatchFinder Started!");

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpes = db.getCPECVE();

		// Create github URLs based on CPEs for given CVEs
		for (Entry<String, ArrayList<String>> cpe : cpes.entrySet()) {
			parseURL(cpe);
		}

		System.out.println("PatchFinder Finished!");

	}

	private static void parseURL(Entry<String, ArrayList<String>> cpe) throws IOException {

		String addressBase = "https://github.com/";

		String[] addresses = null;

		String[] wordArr = cpe.getKey().split(":");

		if (!wordArr[3].equals("*")) {

			String address = addressBase + wordArr[3];
			addresses = new String[] { address + "/", address + "_", address + "-", address };

			for (int i = 0; i < addresses.length; i++) {

				if (!wordArr[4].equals("*"))
					addresses[i] += wordArr[4];

				if (testConnection(addresses[i], cpe))
					break;

			}

		} else if (!wordArr[4].equals("*")) {
			testConnection(addressBase + wordArr[4], cpe);
		}

	}

	private static boolean testConnection(String address, Entry<String, ArrayList<String>> cpe) throws IOException {

		URL url = new URL(address);
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		int response = urlConnection.getResponseCode();

		// Check if the url leads to an actual GitHub repo
		// If so, push the source link into the DB
		if (response == HttpURLConnection.HTTP_OK) {
			try {
				urlConnection.connect();
				InputStream is = urlConnection.getInputStream();

				db.deletePatch(cpe.getValue().get(0));
				db.insertPatch(cpe.getValue().get(0), cpe.getValue().get(1), urlConnection.getURL().toString(), null,
						null);
				urlConnection.disconnect();
			} catch (SQLException e) {
				e.printStackTrace();
			}

			return true;

		}
		return false;
	}

}
