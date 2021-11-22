/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.nvd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * 
 * NvdCveParser class parses Common Vulnerabilities and Exposures (CVE) from the
 * National Vulnerability Database (NVD).
 * 
 * @author axoeec
 *
 */
public class NvdCveParser {
	private Logger logger = LogManager.getLogger(NvdCveParser.class);

	public NvdCveParser() {
	}

	/**
	 * Parse all CVEs for a given year
	 * 
	 * @param year <year> as a 4 digit int
	 * @return list of CVE IDs and Descriptions
	 */
	public List<String[]> parseCVEs(ArrayList<JsonObject> jsonList) {
		List<String[]> allData = new ArrayList<String[]>();
		// parse all CVEs in all JSONs (if multiple)
		for (JsonObject json : jsonList) {
			// parse json
			List<String[]> data = parseCveJson(json);
			allData.addAll(data);
		}

		return allData;
	}

	/**
	 * Parse CVEs in a given <json> and return CVE IDs and Descriptions.
	 * 
	 * @param json a <json> object for CVEs
	 * @return list of CVE IDs and Descriptions
	 */
	private List<String[]> parseCveJson(JsonObject json) {

		List<String[]> allData = new ArrayList<String[]>();
		JsonArray items = (JsonArray) json.getAsJsonArray("CVE_Items");
		Iterator<JsonElement> iterator = items.iterator();

		while (iterator.hasNext()) {
			JsonObject jsonCVE = (JsonObject) iterator.next();
			String sID = jsonCVE.getAsJsonObject("cve").getAsJsonObject("CVE_data_meta").get("ID").getAsString();
			sID = sID.replace("\"", "");

			JsonArray descriptions = jsonCVE.getAsJsonObject("cve").getAsJsonObject("description").getAsJsonArray("description_data");
			String sDescription = ((JsonObject) descriptions.get(0)).get("value").getAsString();

			// clear content: replace <Operating System Command> (OSC) and â€" etc
			sDescription = sDescription.replaceAll("[^\\p{Print}]", " ");
			sDescription = sDescription.replaceAll("[ ,|'|\\\"|â€�|\\|]", " ");

			String baseScore = "?", baseSeverity = "?";
			String impactScore = "?", exploitabilityScore = "?";
			try {

				JsonObject scoreJson;
				JsonObject cvssJson;
				try {
					scoreJson = jsonCVE.getAsJsonObject("impact").getAsJsonObject("baseMetricV3");
					cvssJson = scoreJson.getAsJsonObject("cvssV3");
					baseSeverity = cvssJson.get("baseSeverity").getAsString();

				} catch (Exception e1) {
					scoreJson = jsonCVE.getAsJsonObject("impact").getAsJsonObject("baseMetricV2");
					cvssJson = scoreJson.getAsJsonObject("cvssV2");
					baseSeverity = scoreJson.get("severity").getAsString();
				}

				try {
					baseScore = cvssJson.get("baseScore").getAsString();
				} catch (Exception e) {
				}

				impactScore = scoreJson.get("impactScore").getAsString();
				exploitabilityScore = scoreJson.get("exploitabilityScore").getAsString();
			} catch (Exception e) {
			}

			// get CWE
			String associatedCwes = "";
			StringBuilder sbCwe = new StringBuilder();
			try {
				JsonObject cweObj = jsonCVE.getAsJsonObject("cve").getAsJsonObject("problemtype");
				if (cweObj != null) {
					JsonArray problemtype_data_arr = cweObj.getAsJsonArray("problemtype_data");
					if (problemtype_data_arr != null) {
						JsonArray description_arr = problemtype_data_arr.get(0).getAsJsonObject().getAsJsonArray("description");
						if (description_arr != null) {
							for (JsonElement element : description_arr) {
								String item = ((JsonObject) element).get("value").getAsString();
								sbCwe.append(item + ";");
							}

						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (sbCwe.toString().length() > 0) {
					associatedCwes = sbCwe.toString();
					associatedCwes = associatedCwes.substring(0, associatedCwes.length() - 1); // remove last;
				}
			}

			// get advisories/patches/exploits
			StringBuilder sbPatches = new StringBuilder();
			StringBuilder sbAdvisories = new StringBuilder();
			StringBuilder sbExploits = new StringBuilder();
			try {

				JsonArray advisories = jsonCVE.getAsJsonObject("cve").getAsJsonObject("references").getAsJsonArray("reference_data");
				for (JsonElement element : advisories) {
					JsonObject obj = (JsonObject) element;
					JsonArray jsonArr = obj.get("tags").getAsJsonArray();

					if (jsonArr.size() == 0)
						continue;

					// get tags
					String tags = "";
					for (JsonElement tag : jsonArr)
						tags += tag + ";";

					// url
					String url = obj.get("url").getAsString();

					if (tags.contains("Advisory"))
						sbAdvisories.append(url + ";");

					if (tags.contains("Patch"))
						sbPatches.append(url + ";");
					
					if (tags.contains("Exploit"))
						sbExploits.append(url + ";");
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			allData.add(new String[] { sID, sDescription, baseScore, baseSeverity, impactScore, exploitabilityScore, associatedCwes, sbAdvisories.toString(), sbPatches.toString(), sbExploits.toString() });
		}

		return allData;

	}

	/**
	 * get CVE references from json list
	 * 
	 * @param jsonList
	 * @return
	 */
	public Map<String, Integer> getCveReferences(ArrayList<JsonObject> jsonList) {
		Map<String, Integer> refUrlHash = new HashMap<String, Integer>();

		for (JsonObject json : jsonList) {
			JsonArray items = (JsonArray) json.getAsJsonArray("CVE_Items");
			Iterator<JsonElement> iterator = items.iterator();
			while (iterator.hasNext()) {
				try {
					JsonObject jsonCVE = (JsonObject) iterator.next();
					JsonObject jsonObj = jsonCVE.getAsJsonObject("cve");

					JsonArray jsonArray = jsonObj.getAsJsonObject("references").getAsJsonArray("reference_data");
					for (JsonElement element : jsonArray) {
						String sUrl = element.getAsJsonObject().get("url").getAsString();
						refUrlHash.put(sUrl, 0);
					}
				} catch (Exception e) {
					// logger.error(e.toString());
				}
			}
		}

		return refUrlHash;
	}

	/**
	 * get CPEs from CVE list
	 * 
	 * @param jsonList
	 * @return
	 */
	public Map<String, List<String>> getCPEs(ArrayList<JsonObject> jsonList) {
		Map<String, List<String>> cpeMap = new HashMap<String, List<String>>();

		for (JsonObject json : jsonList) {
			JsonArray items = (JsonArray) json.getAsJsonArray("CVE_Items");
			Iterator<JsonElement> iterator = items.iterator();
			while (iterator.hasNext()) {
				JsonObject jsonCVE = (JsonObject) iterator.next();

				String sCveId = jsonCVE.getAsJsonObject("cve").getAsJsonObject("CVE_data_meta").get("ID").getAsString();

				JsonArray nodes = jsonCVE.getAsJsonObject("configurations").getAsJsonArray("nodes");
				if (nodes.size() > 0) {
					List<String> cpeList = new ArrayList<String>();
					JsonArray cpe_matches = nodes.get(0).getAsJsonObject().getAsJsonArray("cpe_match");
					if (cpe_matches != null) {
						// pick CPEs
						for (int i = 0; i < cpe_matches.size(); i++) {
							try {
								JsonObject object = cpe_matches.get(i).getAsJsonObject();
								String vulnerable = object.get("vulnerable").getAsString().trim();
								String cpe23Uri = object.get("cpe23Uri").getAsString().trim();

								if (vulnerable.equals("true")) {
									cpeList.add(cpe23Uri);
								}
							} catch (Exception e) {
								// logger.error(e.toString());
							}
						}

					} // if (cpe_matches != null) {
					cpeMap.put(sCveId, cpeList);
				}
			}
		}

		return cpeMap;
	}

}
