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
package edu.rit.se.nvip.utils;

import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import edu.rit.se.nvip.model.NvipConstants;
import edu.rit.se.nvip.model.Product;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

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
	public static final DateFormat longDateFormatMySQL = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	private static Map<String, Product> productMap = null;

	private static MyProperties properties;

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
		UtilHelper.properties = properties;
	}

	/**
	 * get directory name from command line
	 * 
	 * @param args
	 * @return
	 */
	public static String getPathFromCommandLine(String[] args) {
		String path = null;
		if (args.length > 0) {
			try {
				path = args[0];
				File file = new File(path);

				// full path?
				if (file.exists() && file.isDirectory()) {
					logger.error("Please enter a valid FULL output CSV path! Cannot use " + path + ". Example: C:/Temp/results.csv");
					System.exit(1);
				}

				// can create?
				if (!file.exists()) {
					if (file.createNewFile()) {
						file.delete(); // delete
					}
				}

			} catch (Exception e) {
				logger.error("Cannot set the output path to '" + path + "'. " + e.getMessage());
				System.exit(1);
			}
		} else {
			logger.error("Please enter a valid output path!");
			System.exit(1);
		}
		return path;
	}


	public static Date getPastDate(Calendar cal, int days) {
		cal.add(Calendar.DATE, -days);
		return cal.getTime();
	}

	public static String getPastDayAsShortDate(Calendar cal, int days) {
		DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
		return dateFormat.format(getPastDate(cal, days));
	}

	public static File getFileNameFromDialog() {
		// create file chooser
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setCurrentDirectory(new File("src/main/resources/cvesources"));
		fileChooser.setDialogTitle("Select the txt file that stores CVE URLs");
		fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY); // set filter

		fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("CSV Files", "csv"));
		fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("Text Documents", "txt"));
		fileChooser.setAcceptAllFileFilterUsed(false);
		int result = fileChooser.showOpenDialog(null);
		if (result == JFileChooser.CANCEL_OPTION) {
			logger.error("Please select the source url input file!");
			System.exit(1);
		}
		return fileChooser.getSelectedFile();
	}

	public static void initLog4j(Properties config) {
		logger.info("log4j Log Level is: " + LogManager.getRootLogger());
	}

	public static String getDateTime(long time) {
		SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
		Date date = new Date(time);
		return formatter.format(date);
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

	public static List<String> readByJava8(String fileName) throws IOException {
		List<String> result;
		try (Stream<String> lines = Files.lines(Paths.get(fileName), Charset.forName("UTF-8"))) {
			result = lines.collect(Collectors.toList());
		}
		return result;

	}

}
