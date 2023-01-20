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
package edu.rit.se.nvip.utils;

import java.io.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import edu.rit.se.nvip.model.NvipConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * Implementation of some commonly used utilities
 * 
 * @author axoeec
 *
 */
public class UtilHelper {
	static Logger logger = LogManager.getLogger(UtilHelper.class);
	public static final DateFormat longDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	public static final DateFormat shortDateFormat = new SimpleDateFormat("yyyy/MM/dd");
	public static final DateFormat kbCertDateFormat = new SimpleDateFormat("yyyy-MM-dd");

	/**
	 * Print total/free/used memory
	 */
	public static void printMemory() {
		long total = Runtime.getRuntime().totalMemory() / 1000000;
		long free = Runtime.getRuntime().freeMemory() / 1000000;
		long used = total - free;
		logger.info("Memory (MB), Total: " + total + ", Used: " + used + ", Used %:" + ((int) ((used * 1.0) / total * 100)));
	}

	public static void setProperties(MyProperties properties) {
	}


	public static Date getPastDate(Calendar cal, int days) {
		cal.add(Calendar.DATE, -days);
		return cal.getTime();
	}

	public static String getPastDayAsShortDate(Calendar cal, int days) {
		DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
		return dateFormat.format(getPastDate(cal, days));
	}

	public static void initLog4j(Properties config) {
		logger.info("log4j Log Level is: " + LogManager.getRootLogger());
	}

	public static synchronized void addBadUrl(String url, String reason) {

		String text = url + ", " + reason;
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter("logs/UrlsMissingInfo.txt", true));
			writer.newLine();
			writer.write(text);
			writer.close();
		} catch (IOException e) {
		}
	}

	public static boolean isDelayedUrl(String url) {
		List<String> listUrl = NvipConstants.getDelayedURLs();
		for (String s : listUrl)
			if (url.contains(s))
				return true;
		return false;
	}

}
