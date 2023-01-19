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
package edu.rit.se.nvip.nvd;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.rit.se.nvip.nlp.StanfordCoreNlp;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.UrlUtils;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * The main class for NVD feed reader
 * 
 * @author axoeec
 *
 */

public class NvdCveController {
	private final Logger logger = LogManager.getLogger(NvdCveController.class);

	// Parameters
	private static final int START_YEAR = 2002, END_YEAR = Calendar.getInstance().get(Calendar.YEAR);
	private static final String nvdJsonFeedUrl = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-YYYY.json.zip";
	String[] header = new String[] { "CVE-ID", "Description", "BaseScore", "BaseSeverity", "ImpactScore", "ExploitabilityScore", "CWE", "Advisory", "Patch", "Exploit" };

	boolean logCPEInfo = true;

	/**
	 * Main method of NVD_CVE_Reader
	 * 
	 * @param filepath
	 */
	public int pullNvdCve(String filepath, boolean extractNamedEntities) {
		CsvUtils csvLogger = new CsvUtils(); // create output CSV file and append header
		StanfordCoreNlp coreNLP = null;

		// delete existing?
		File file = new File(filepath);
		if (file.exists())
			file.delete(); // delete

		// get root path from command line
		logger.info("The output CSV will be at: " + filepath);

		if (extractNamedEntities) {
			// initialize StanfordCoreNLPAnnotator
			logger.info("Initializing StanfordCoreNLPAnnotator...");
			coreNLP = new StanfordCoreNlp();
			logger.info("\tDONE! Initialized StanfordCoreNLPAnnotator");
			UtilHelper.printMemory(); // check memory after NLP engine initialization
			header = new String[] { "CVE-ID", "Annotated Description" };
		}

		csvLogger.writeHeaderToCSV(filepath, header, false);

		// Pull yearly CVE data from NVD
		NvdCveParser myCVEParser = new NvdCveParser(); // init parser
		int totCount = 0;

		Map<String, Integer> nvdRefUrlHash = new HashMap<>();
		Map<String, List<String>> nvdCveCpeHashMap = new HashMap<>();

		for (int year = START_YEAR; year <= END_YEAR; year++) {

			// pull and parse CVE feeds from NVD
			logger.info("\tPulling CVEs for " + year + "...");

			try {
				// get all CVEs
				ArrayList<JsonObject> jsonList = pullCVEs(year);
				List<String[]> listCVEData = myCVEParser.parseCVEs(jsonList);
				logger.info("\tDONE! Pulled " + listCVEData.size() + " CVEs");

				if (extractNamedEntities) {
					// annotate
					logger.info("\tAnnotating " + listCVEData.size() + " CVEs for year " + year);
					listCVEData = coreNLP.annotateCVEList(listCVEData);
					logger.info("\tDONE! Annotated " + listCVEData.size() + " CVEs");
				}

				// write annotated descriptions to CSV
				int count = csvLogger.writeListToCSV(listCVEData, filepath, true);
				totCount += count;
				if (count > 0) {
					logger.info("\tWrote " + count + " entries to CSV file: " + filepath);
				}

				// add references from this json list
				nvdRefUrlHash.putAll(myCVEParser.getCveReferences(jsonList));

				// add references from this json list
				nvdCveCpeHashMap.putAll(myCVEParser.getCPEs(jsonList));
			} catch (Exception e) {
				String url = nvdJsonFeedUrl.replaceAll("YYYY", year + "");
				logger.error("Error pulling NVD CVES for year {}, url: (), error: {}", year, url, e);
			}
		}

		logger.info("\n\tWrote a total of *** " + totCount + " *** entries to CSV file: " + filepath);

		// process&store references
		processCVeReferences(nvdRefUrlHash, filepath);

		logCPEInfo(filepath, nvdCveCpeHashMap);

		return totCount;
	}

	/**
	 * Process Nvd reference URLs
	 * 
	 * @param nvdRefUrlHash
	 * @param filepath
	 */
	private void processCVeReferences(Map<String, Integer> nvdRefUrlHash, String filepath) {
		UrlUtils urlUtils = new UrlUtils();
		int count = 0;
		Map<String, Integer> nvdBaseRefUrlHash = new HashMap<>();
		List<String> listFullRefUrls = new ArrayList<>();
		try {
			for (String sUrl : nvdRefUrlHash.keySet()) {
				String sBaseUrl = urlUtils.getBaseUrl(sUrl);
				if (sBaseUrl != null) {
					listFullRefUrls.add(sUrl);
					nvdBaseRefUrlHash.put(sBaseUrl, 0);
				}

				count++;
				if (count % 10000 == 0)
					logger.info("Processed " + count + " URLs...");

			}

			List<String> listBaseRefUrls = new ArrayList<>();
			listBaseRefUrls.addAll(nvdBaseRefUrlHash.keySet());

			filepath = filepath.replace(".csv", "");
			filepath = filepath.substring(0, filepath.lastIndexOf("/")) + "/url-sources/";
			String sFullReferencePath = filepath + "nvd-cve-full-references.csv";
			String sBaseReferencePath = filepath + "nvd-cve-base-references.csv";
			FileUtils.writeLines(new File(sFullReferencePath), listFullRefUrls, false);
			FileUtils.writeLines(new File(sBaseReferencePath), listBaseRefUrls, false);

			int totInvalid = nvdRefUrlHash.keySet().size() - listFullRefUrls.size();
			logger.info("\nScraped " + count + " total NVD full-reference URLs." + "\nThe # of invalid full-references: " + totInvalid + "\nThe # of recorded full-references " + listFullRefUrls.size()
					+ "\nTotal # of unique base URLs: " + nvdBaseRefUrlHash.keySet().size() + "\nReference URLs are stored at: " + sFullReferencePath + " and " + sBaseReferencePath);
		} catch (IOException e) {
			logger.error("Error while processing NVD references! " + e);
		}
	}

	/**
	 * get CVEs as JSON object from NVD for <year>
	 * 
	 * @param year <year> as a 4 digit int
	 * 
	 * @return list of JSON objects (one json object for each json file in the zip)
	 */
	private ArrayList<JsonObject> pullCVEs(int year) {
		String sURL = nvdJsonFeedUrl.replaceAll("YYYY", year + "");
		ArrayList<JsonObject> jsonList = new ArrayList<>();
		StringBuffer sBuilder;

		try {
			URL url = new URL(sURL);
			HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
			httpURLConnection.setRequestMethod("GET");
			InputStream inputStream = httpURLConnection.getInputStream();
			ZipInputStream zipInputStream = new ZipInputStream(inputStream);

			ZipEntry zipEntry = zipInputStream.getNextEntry();

			while (zipEntry != null) {
				if (!zipEntry.isDirectory()) {

					// get contents of the entry
					char[] buffer = new char[4096];
					sBuilder = new StringBuffer();
					Reader reader = new InputStreamReader(zipInputStream, StandardCharsets.UTF_8);
					int charsRead;
					while ((charsRead = reader.read(buffer, 0, buffer.length)) > 0) {
						sBuilder.append(buffer, 0, charsRead);
					}

					logger.info("\tExtracted " + zipEntry.getName() + " FROM " + sURL);

					// parse entry contents
					logger.info("\tParsing " + zipEntry.getName());
					String sJsonContent = sBuilder.toString();
					JsonObject json = JsonParser.parseString(sJsonContent).getAsJsonObject();
					jsonList.add(json);
					logger.info("\tDONE! Parsed " + zipEntry.getName());
				}
				zipEntry = zipInputStream.getNextEntry(); // next entry?
			}
			zipInputStream.close(); // close zip stream

		} catch (Exception e) {
			logger.error("Exception while reading feed from :" + sURL + "\tDetails:" + e);
		}

		return jsonList; // the list includes a json object for each json file in the zip
	}

	/**
	 * log CPE info
	 * 
	 * @param cpeMap
	 */
	private void logCPEInfo(String filepath, Map<String, List<String>> cpeMap) {
		if (logCPEInfo) {
			filepath += "-CPE.csv";
			// new file object
			File file = new File(filepath);

			try (BufferedWriter bf = new BufferedWriter(new FileWriter(file))) {
				for (Map.Entry<String, List<String>> entry : cpeMap.entrySet()) {
					StringBuilder sCpe = new StringBuilder();
					for (String cpe : entry.getValue()) {
						sCpe.append(cpe.replace(",", "")).append(" ");
					}
					bf.write(entry.getKey() + "," + sCpe);
					bf.newLine();
				}
				bf.flush();
			} catch (IOException e) {
				logger.error("Error logging CPE: " + e);
			}
		}
	}

}
