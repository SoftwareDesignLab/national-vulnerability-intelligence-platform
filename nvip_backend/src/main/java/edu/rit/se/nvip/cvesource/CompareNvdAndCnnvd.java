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
package edu.rit.se.nvip.cvesource;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author axoeec
 *
 */
public class CompareNvdAndCnnvd {
	private static Logger logger = LogManager.getLogger(UpdateNvipSourceUrlList.class);

	public static void main(String[] args) {
		/**
		 * load properties file first
		 */

		CompareNvdAndCnnvd diffBetweenCnnvdAndNvd = new CompareNvdAndCnnvd();
		String cnnvdPath = "data/url-sources/cnnvd-cve-base-references.csv";
		String nvdPath = "data/url-sources/nvd-cve-base-references.csv";
		diffBetweenCnnvdAndNvd.diffBetweenNvdAndCnnvd(cnnvdPath, nvdPath);
	}

	/**
	 * Extract EXTRA and MISSING source URLs of NVD, when compared to CNNVD
	 * 
	 * @param cnnvdPath
	 * @param nvdPath
	 */
	private void diffBetweenNvdAndCnnvd(String cnnvdPath, String nvdPath) {
		try {
			List<String> nvdUrls = FileUtils.readLines(new File(nvdPath), "UTF-8");
			List<String> cnnvdUrls = FileUtils.readLines(new File(cnnvdPath), "UTF-8");

			Map<String, Integer> cnnvdHash = new HashMap<String, Integer>();
			for (String sUrl : cnnvdUrls)
				cnnvdHash.put(sUrl.trim(), 0);

			Map<String, Integer> nvdHash = new HashMap<String, Integer>();
			for (String sUrl : nvdUrls)
				nvdHash.put(sUrl.trim(), 0);

			List<String> extraUrls = new ArrayList<String>();
			for (String sUrl : nvdUrls) {
				if (!cnnvdHash.containsKey(sUrl.trim()))
					extraUrls.add(sUrl);
			}
			nvdPath = nvdPath.replace("csv", "");
			nvdPath = nvdPath.substring(0, nvdPath.lastIndexOf("/")) + "/";
			String path = nvdPath + "nvd-sources-not-in-cnnvd.csv";
			FileUtils.writeLines(new File(path), extraUrls, false);

			List<String> missingUrls = new ArrayList<String>();
			for (String sUrl : cnnvdUrls) {
				if (!nvdHash.containsKey(sUrl.trim()))
					missingUrls.add(sUrl);
			}
			nvdPath = nvdPath.replace("csv", "");
			nvdPath = nvdPath.substring(0, nvdPath.lastIndexOf("/")) + "/";
			path = nvdPath + "nvd-sources-missing-from-cnnvd.csv";
			FileUtils.writeLines(new File(path), missingUrls, false);

			logger.info("\nCompared " + nvdUrls.size() + " NVD base URLs against " + cnnvdUrls.size() + " CNNVD base URLs.\nNVD has " + extraUrls.size() + " EXTRA URLs (that do not exist in CNNVD),\nMISSING " + missingUrls.size()
					+ " URLs (that exist in CNNVD)!");
			logger.info("\n" + FileUtils.readFileToString(new File(path)));

		} catch (Exception e) {
			logger.error("Error while comparing NVD and CNNVD URLs. Check your path for inpu files! " + e.toString());
		}
	}

}
