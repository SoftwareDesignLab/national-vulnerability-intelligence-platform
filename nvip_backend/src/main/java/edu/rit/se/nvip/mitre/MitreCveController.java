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
package edu.rit.se.nvip.mitre;

import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.GitController;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * Pulls CVEs from the local git repo
 * 
 * @author axoeec
 *
 */
public class MitreCveController {
	private final Logger logger = LogManager.getLogger(MitreCveController.class);

	public MitreCveController() {
		Map<Integer, Integer> recentCveYearsMap = new HashMap<>();
		int currentYear = Calendar.getInstance().get(Calendar.YEAR);
		int lookYearsBack = 5;
		for (int year = currentYear; year > currentYear - lookYearsBack; year--)
			recentCveYearsMap.put(year, year);
	}

	/**
	 * get Mitre CVEs. Checks if a local git repo exists for Mitre CVEs. If not
	 * clones the remote Git repo. If a local repo exists then it pulls the latest
	 * updates if any. Then it recursively loads all json files in the local repo,
	 * parses them and creates a CSV file at the output path.
	 */
	public HashMap<String, CompositeVulnerability> getMitreCVEsFromGitRepo(String localPath, String remotePath, String outputCSVpath) {

		GitController gitController = new GitController(localPath, remotePath);
		logger.info("Checking local Git CVE repo...");

		File f = new File(localPath);
		boolean pullDir = false;
		try {
			pullDir = f.exists() && (f.list().length > 1); // dir exists and there are some files in it!
		} catch (Exception e) {
		}

		if (pullDir) {
			if (gitController.pullRepo())
				logger.info("Pulled git repo at: {} to: {}, now parsing each CVE...", remotePath, localPath);
			else {
				logger.error("Could not pull git repo at: {} to: {}", remotePath, localPath);
			}
		} else {
			if (gitController.cloneRepo())
				logger.info("Cloned git repo at: {} to: {}, now parsing each CVE...", remotePath, localPath);
			else {
				logger.error("Could not clone git repo at: {} to: {}", remotePath, localPath);
			}
		}

		logger.info("Now parsing MITRE CVEs at {} directory", localPath);

		// create json object from .json files
		ArrayList<JsonObject> list = new ArrayList<>();
		list = getJSONFilesFromGitFolder(new File(localPath), list);
		logger.info("Collected {} JSON files at {}", list.size(), localPath);

		// parse individual json objects
		MitreCveParser mitreCVEParser = new MitreCveParser();
		List<String[]> cveData = mitreCVEParser.parseCVEJSONFiles(list);
		logger.info("Parsed {} JSON files at {}", list.size(), localPath);

		// log CVEs
		int count = new CsvUtils().writeListToCSV(cveData, outputCSVpath, false);
		logger.info("Wrote *** {} **** MITRE CVE items to {}", count, outputCSVpath);

		// add all CVEs to a map
		HashMap<String, CompositeVulnerability> gitHubCveMap = new HashMap<>();
		for (String[] cve : cveData) {
			String cveId = cve[0];
			String sourceUrl = remotePath;
			String date = UtilHelper.longDateFormat.format(new Date());
			String description = cve[1];
			CompositeVulnerability vuln = new CompositeVulnerability(0, sourceUrl, cveId, "N/A", date, date, description, null);
			gitHubCveMap.put(cveId, vuln);
		}

		return gitHubCveMap;

	}

	/**
	 * Recursively get all JSON files in the <folder>
	 * 
	 * @param folder
	 * @param jsonList
	 * @return
	 */
	public ArrayList<JsonObject> getJSONFilesFromGitFolder(final File folder, ArrayList<JsonObject> jsonList) {
		for (final File fileEntry : folder.listFiles()) {
			if (fileEntry.isDirectory()) {
				// skip git folders
				if (!fileEntry.getName().contains(".git"))
					getJSONFilesFromGitFolder(fileEntry, jsonList);
			} else {
				try {

					String filename = fileEntry.getName();
					String extension = filename.substring(filename.lastIndexOf(".") + 1);
					if (extension.equalsIgnoreCase("json")) {
							String sJsonContent = FileUtils.readFileToString(fileEntry);
							JsonObject json = JsonParser.parseString(sJsonContent).getAsJsonObject();
							jsonList.add(json);
					}
				} catch (Exception e) {
					logger.error("Error while getting JSON files at " + folder.getAbsolutePath() + ": " + e);

				}
			}
		}

		logger.info("Parsed " + jsonList.size() + " CVEs in " + folder);
		return jsonList;
	}

}
