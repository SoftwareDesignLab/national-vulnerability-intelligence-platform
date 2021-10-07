package edu.rit.se.nvip.patchfinder;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map.Entry;

import edu.rit.se.nvip.db.DatabaseHelper;

/**
 * Start patch finder for a given repository list (as .csv)
 * 
 * @author 15854
 *
 */
public class PatchFinderMain {

	public static void main(String[] args) throws IOException {

		DatabaseHelper db = DatabaseHelper.getInstance();
		HashMap<String, String> cpes = (HashMap<String, String>) db.getCPECVE();

		// Create github URLs based on CPEs for given CVEs
		for (Entry<String, String> cpe : cpes.entrySet()) {
			String address = "https://github.com/";

			String[] wordArr = cpe.getKey().split(":");

			if (!wordArr[3].equals("*"))
				address += wordArr[3];

			if (!wordArr[4].equals("*"))
				address += "/" + wordArr[4];

			URL url = new URL(address);
			HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
			int response = urlConnection.getResponseCode();

			// Check if the url leads to an actual GitHub repo
			// If so, push the source link into the DB
			if (response == HttpURLConnection.HTTP_OK) {
				try {
					db.insertPatch(cpe.getValue(), address, null, null);
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}

		}

	}

}
