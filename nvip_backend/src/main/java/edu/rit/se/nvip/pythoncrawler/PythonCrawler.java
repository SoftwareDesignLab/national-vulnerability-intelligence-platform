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
package edu.rit.se.nvip.pythoncrawler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

/**
 * 
 * Invoke Python crawler/extractor modules
 * 
 * @author axoeec
 *
 */
public class PythonCrawler {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Call python script to crawl urls at sInputFile
	 * 
	 * @param sRootDir
	 * @param sInputFile
	 * @param sqLiteDbName
	 * @return
	 */
	public int crawl(String sRootDir, String sInputFile, String sqLiteDbName) {
		int count = -1;
		String sCrawlerScript = "CrawlWrapper.py";
		String sCommand = "python " + sCrawlerScript + " " + sInputFile + " " + sqLiteDbName;

		// change to the sRootDir and execute sCommand
		ExternalRuntimeProcess process = new ExternalRuntimeProcess(sRootDir, sCommand);
		String sOutput = process.exec();
		if (sOutput == null) {
			logger.error("Error invoking crawler!");
			return count;
		}

		// parse Crawler output json
		try {
			JsonObject json = new Gson().fromJson(sOutput, JsonObject.class);
			count = json.get("cve_count").getAsInt();
			logger.info("Crawler has returned " + count + " new CVEs");
		} catch (Exception e) {
			logger.error("Error in Crawler output: " + sOutput);
		}

		return count;
	}
}
