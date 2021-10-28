package edu.rit.se.nvip.patchfinder.collector;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.opencsv.CSVReader;

import edu.rit.se.nvip.patchfinder.utils.HttpDownloadUtility;

/**
 * This class loads commits from a given CSV file and download the corresponding
 * patch.
 *
 * @author Joanna C. S. Santos <jds5109@rit.edu>
 */
public class CVEDataCollector {

	private final File inputCsvFile;

	private final String GITHUB_PATCH_URL = "https://github.com/%s/commit/%s.patch";
	private final String CSV_OUTPUT_FILE = "%s_affected-files.csv";

	public CVEDataCollector(String csvFilePath) {
		inputCsvFile = new File(csvFilePath);
	}

	/**
	 * Load commits from a CSV file.
	 *
	 * @throws FileNotFoundException
	 */
	private List<String> loadCommitsFromCsv() throws FileNotFoundException, IOException {
		CSVReader reader = new CSVReader(new FileReader(inputCsvFile));
		List<String> commitsSha = new ArrayList<>();
		List<String[]> rows = reader.readAll();

		for (int i = 1; i < rows.size(); i++) {
			System.out.println(rows.get(i)[2]);
			commitsSha.add(rows.get(i)[1]);
		}

		return commitsSha;
	}

	/**
	 *
	 * @param repo
	 * @param outputDir
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public void downloadPatches(String repo, String outputDir) throws FileNotFoundException, IOException {

		List<String> commitsSha = loadCommitsFromCsv();
		for (String sha : commitsSha) {
			String downloadUrl = String.format(GITHUB_PATCH_URL, repo, sha);
			System.out.println("Downloading from " + downloadUrl);
			HttpDownloadUtility.downloadFile(downloadUrl, outputDir);
		}
	}
}
