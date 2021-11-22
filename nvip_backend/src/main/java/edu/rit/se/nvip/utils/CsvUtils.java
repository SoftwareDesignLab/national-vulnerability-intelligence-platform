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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.opencsv.CSVParser;
import com.opencsv.CSVParserBuilder;
import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;
import com.opencsv.CSVWriter;

import edu.rit.se.nvip.model.CnnvdVulnerability;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.VdoCharacteristic;
import edu.rit.se.nvip.model.Vulnerability;

/**
 * 
 * CSV Logger uses com.opencsv (Maven lib) to generate an output CSV file.
 * 
 * @author axoeec
 *
 */
public class CsvUtils {
	final static Logger logger = LogManager.getLogger(CsvUtils.class);

	private char mySeparatorChar = '|';

	/**
	 * Write list to the CSV file
	 * 
	 * @param allData    list of annotations
	 * @param filepath   full path of the output CSV
	 * @param appendMode set true in the append mode
	 */
	public int writeListToCSV(List<String[]> allData, String filepath, boolean appendMode) {
		try {

			FileWriter fileWriter = new FileWriter(new File(filepath), appendMode);
			CSVWriter writer = new CSVWriter(fileWriter, mySeparatorChar, CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
			writer.writeAll(allData);
			writer.close();
		} catch (IOException e) {
			logger.error("Exception while writing list to CSV file!" + e.toString());
			return 0;
		}

		return allData.size();
	}

	/**
	 * Write a list of objects to CSV
	 * 
	 * @param allData
	 * @param filepath
	 * @param appendMode
	 * @return
	 */
	public int writeObjectListToCSV(List<Object> allData, String filepath, boolean appendMode) {
		try {

			List<String[]> arr = new ArrayList<String[]>();

			for (Object obj : allData)
				if (obj instanceof CompositeVulnerability) {
					CompositeVulnerability vuln = (CompositeVulnerability) obj;
					try {

						if (vuln.getDescription() == null)
							continue; // ignore CVEs with no description

						String description = vuln.getDescription().replace(mySeparatorChar + "", "").replace("\n", "");
						String sourceUrl = Arrays.deepToString(vuln.getSourceURL().toArray());

						String vdoCharacteristic = "";
						String vdoConfidence = "";
						if (vuln.getVdoCharacteristic().size() > 0) {
							for (VdoCharacteristic vdo : vuln.getVdoCharacteristic()) {
								vdoCharacteristic += (vdo.getVdoLabelId() + ",");
								vdoConfidence += (vdo.getVdoConfidence() + ",");
							}
						}

						arr.add(new String[] { vuln.getCveId(), vuln.getPlatform(), description, sourceUrl, vdoCharacteristic, vdoConfidence, vuln.getNvdSearchResult(), vuln.getMitreSearchResult(), vuln.getNvipNote() });
					} catch (Exception e) {
						logger.error("Error while adding Vulnerability to list!" + " Vuln: " + vuln.toString() + ". " + e.toString());
					}
				}
			FileWriter fileWriter = new FileWriter(new File(filepath), appendMode);
			CSVWriter writer = new CSVWriter(fileWriter, mySeparatorChar, CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
			writer.writeAll(arr);
			writer.close();
		} catch (Exception e) {
			logger.error("Exception while writing List<Vulnerability> to CSV!" + e.toString());
			return 0;
		}

		return allData.size();
	}

	/**
	 * Write CSV header to the <filepath>
	 * 
	 * @param filepath   full path of the output CSV
	 * @param appendMode set true in the append mode
	 */
	public boolean writeHeaderToCSV(String filepath, String[] header, boolean appendMode) {
		try {

			FileWriter fileWriter = new FileWriter(new File(filepath), appendMode);
			CSVWriter writer = new CSVWriter(fileWriter, mySeparatorChar, CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
			writer.writeNext(header);
			writer.close();
		} catch (IOException e) {
			logger.error("Exception while writing header to CSV file!" + e.toString());
			return false;
		}
		return true;
	}

	public String getSeparatorCharAsRegex() {
		return "[" + mySeparatorChar + "]";
	}

	public char getMySeparatorChar() {
		return mySeparatorChar;
	}
	
	public List<String[]> getDataFromCsv(String dataPath, char separatorChar){
		this.mySeparatorChar = separatorChar;
		return getDataFromCsv(dataPath);
	}

	/**
	 * read csv
	 * 
	 * @param dataPath
	 * @return
	 */
	public List<String[]> getDataFromCsv(String dataPath) {
		List<String[]> data = new ArrayList<String[]>();
		try {
			CSVParser csvParser = new CSVParserBuilder().withSeparator(mySeparatorChar).build();
			CSVReader reader = new CSVReaderBuilder(new FileReader(dataPath)).withCSVParser(csvParser).build();

			String[] nextLine;
			while ((nextLine = reader.readNext()) != null) {
				if (nextLine != null) {
					data.add(nextLine);
				}
			}
		} catch (Exception e) {
			logger.error("Error while reading csv file at: {}, {}", dataPath, e.toString());
			return null;
		}
		return data;
	}

}
