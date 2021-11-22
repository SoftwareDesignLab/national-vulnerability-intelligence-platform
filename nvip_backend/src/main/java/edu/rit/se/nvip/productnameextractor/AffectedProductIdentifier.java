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
package edu.rit.se.nvip.productnameextractor;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.AffectedRelease;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Product;
import edu.rit.se.nvip.utils.PrepareDataForWebUi;
import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * @author axoeec
 *
 */
public class AffectedProductIdentifier extends Thread implements Runnable {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private final int maxDescLengthWords = 100;

	private List<CompositeVulnerability> vulnList;

	public AffectedProductIdentifier(List<CompositeVulnerability> vulnList) {
		this.vulnList = vulnList;
	}

	/**
	 * insert CPE products identified by the loader into the database
	 */
	private int insertNewCpeItemsIntoDatabase() {
		CpeLookUp cpeLookUp = CpeLookUp.getInstance();
		try {
			Collection<Product> products = cpeLookUp.getProductsToBeAddedToDatabase().values();
			DatabaseHelper db = DatabaseHelper.getInstance();
			return db.insertCpeProducts(products);
		} catch (Exception e) {
			logger.error("Error while adding " + cpeLookUp.getProductsToBeAddedToDatabase().size() + " new products!");
			return -1;
		}

	}

	// run process
	public void run() {
		identifyAffectedReleases(vulnList, false);
	}

	public int identifyAffectedReleases(List<CompositeVulnerability> vulnList, boolean isUnitTest) {
		logger.info("Starting to identify affected products for " + vulnList.size() + " CVEs.");
		long start = System.currentTimeMillis();

		DetectProducts productNameDetector = null;
		try {
			productNameDetector = DetectProducts.getInstance();
		} catch (Exception e1) {
			logger.error("Severe Error! Could not initialize the models for product name/version extraction! Skipping affected release identification step! {}", e1.toString());
			return -1;
		}

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();
		int numOfProductsMappedToCpe = 0;
		int numOfProductsNotMappedToCPE = 0;
		int counterOfProcessedNERs = 0;
		int counterOfProcessedCPEs = 0;
		int counterOfProcessedCVEs = 0;
		int counterOfSkippedCVEs = 0;
		int counterOfBadDescriptionCVEs = 0;
		long totalNERtime = 0;
		long totalCPEtime = 0;
		long totalCVEtime = 0;

		int totalCVEtoProcess = vulnList.size();

		logger.info("Starting product name extraction process... # CVEs to be processed: {}", totalCVEtoProcess);

		for (CompositeVulnerability vulnerability : vulnList) {

			String description = vulnerability.getDescription();

			if (description == null || description.length() == 0) {
				counterOfBadDescriptionCVEs++;
				continue; // skip the ones without a description
			}

			// if a CVE did did change, no need to extract products, assuming they are
			// already in DB!!
			if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE) {
				counterOfSkippedCVEs++;
				continue;
			}

			counterOfProcessedCVEs++;
			
			/**
			 * The product name extraction is a time consuming process, limiting the # of
			 * CVEs per run to 1000! This should not happen except the very first run, or a
			 * run after a long delay!
			 */
			if (counterOfProcessedCVEs > 1000) 
				break;
			

			long startCVETime = System.currentTimeMillis();
			try {
				// LIMIT to 100 words
				String descriptionWords[] = WhitespaceTokenizer.INSTANCE.tokenize(description);

				if (descriptionWords.length > maxDescLengthWords) {
					String[] subStringArray = new String[maxDescLengthWords];
					for (int i = 0; i < maxDescLengthWords; i++) {
						subStringArray[i] = descriptionWords[i];
					}
					descriptionWords = subStringArray;
				}

				// if no products found by crawlers, use AI/ML model to extract product/version
				// from text
				if (vulnerability.getAffectedReleases().isEmpty()) {

					// Time measurement
					long startNERTime = System.currentTimeMillis();

					// get products from AI/ML model
					List<ProductItem> productList = productNameDetector.getProductItems(descriptionWords);

					long nerTime = System.currentTimeMillis() - startNERTime;
					counterOfProcessedNERs++;
					totalNERtime = totalNERtime + nerTime;

					// map identified products/version to CPE
					StringBuilder sPlatform = new StringBuilder();
					for (ProductItem productItem : productList) {

						/**
						 * when the productFromDomain method is called, AffectedReleaseLoader adds the
						 * product to its hash map that is used to update the products in database.
						 * AffectedReleaseLoader is using singleton DP!
						 */
						long startCPETime = System.currentTimeMillis();
						List<String> productIDs = cpeLookUp.getCPEids(productItem);
						long cpeTime = System.currentTimeMillis() - startCPETime;
						totalCPEtime = totalCPEtime + cpeTime;
						counterOfProcessedCPEs++;

						if (productIDs == null || productIDs.isEmpty()) {
							numOfProductsNotMappedToCPE++;
							long averageCPEtime = 0;
							if (counterOfProcessedCPEs > 0) {
								averageCPEtime = totalCPEtime / counterOfProcessedCPEs;
							}
							long averageNERtime = 0;
							if (counterOfProcessedNERs > 0) {
								averageNERtime = totalNERtime / counterOfProcessedNERs;
							}
							long averageCVEtime = 0;
							if (counterOfProcessedCVEs > 0) {
								averageCVEtime = totalCVEtime / counterOfProcessedCVEs;
							}
							logger.warn("CVEs processed: " + Integer.toString(counterOfProcessedCVEs) + " out of " + Integer.toString(totalCVEtoProcess) + "; Average NER time (ms): "
									+ Long.toString(averageNERtime) + "; Average CPE time (ms): " + Float.toString(averageCPEtime) + "; Average CVE time (ms): " + Long.toString(averageCVEtime)
									+ "; Current NER time (ms): " + Long.toString(nerTime) + "; Not mapped to CPE: " + Integer.toString(numOfProductsNotMappedToCPE) + "; Mapped to CPE: "
									+ Integer.toString(numOfProductsMappedToCpe) + "; The product name (" + productItem.toString()
									+ ") predicted by AI/ML model could not be found in the CPE dictionary!\tCVE-ID: " + vulnerability.getCveId() + "\tDescription: " + vulnerability.getDescription());
							continue;
						}
						// if CPE identified, add it as affected release
						for (String itemID : productIDs) {
							vulnerability.getAffectedReleases().add(new AffectedRelease(0, vulnerability.getCveId(), itemID, null, CpeLookUp.getVersionFromCPEid(itemID)));
							numOfProductsMappedToCpe++;
						}
					}

					// set platform string
					vulnerability.setPlatform(sPlatform.toString());

				} // if (vuln.getAffectedReleases().size() == 0) {

			} catch (Exception e) {
				logger.error("Error {} while extracting affected releases! Processed: {} out of {} CVEs; CVE: {}", e, Integer.toString(counterOfProcessedCVEs), Integer.toString(totalCVEtoProcess),
						vulnerability.toString());
			}

			totalCVEtime = totalCVEtime + (System.currentTimeMillis() - startCVETime);

			if (counterOfProcessedCVEs % 100 == 0) {
				double percent = (counterOfProcessedCVEs + counterOfBadDescriptionCVEs + counterOfSkippedCVEs) / 1.0 * totalCVEtoProcess * 100;
				logger.info("Extracted product(s) for {} out of {} CVEs so far! {} CVEs skipped (not-changed or bad description), {}% done.", counterOfProcessedCVEs, totalCVEtoProcess,
						(counterOfBadDescriptionCVEs + counterOfSkippedCVEs), percent);
			}
		} // for (CompositeVulnerability vuln : vulnList) {

		logger.info("Extracted product(s) for {} out of {} CVEs so far! {} CVEs skipped, bc they are flagged as 'not-changed' by reconciliation process", counterOfProcessedCVEs, totalCVEtoProcess,
				counterOfSkippedCVEs);

		// refresh db conn, it might be timed out if the process takes so much time!
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

		/**
		 * at this point all vulnerabilities either have a product/name scraped from
		 * Web, or one that is predicted by AI/ML model. Update vulnerabilities in the
		 * database.
		 * 
		 * First insert any products that are newly identified and do not exist in DB.
		 * BC, AffectedReleases has product ID as foreign key
		 */
		int productCount = insertNewCpeItemsIntoDatabase();

		// get all identified affected releases
		List<AffectedRelease> listAllAffectedReleases = new ArrayList<>();
		for (CompositeVulnerability vulnerability : vulnList) {
			if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE)
				continue; // skip the ones that are not changed!
			listAllAffectedReleases.addAll(vulnerability.getAffectedReleases());
		}

		// delete existing affected release info in db ( for CVEs in the list)
		databaseHelper.deleteAffectedReleases(listAllAffectedReleases);

		// now insert affected releases (referenced products are already in db)
		databaseHelper.insertAffectedReleasesV2(listAllAffectedReleases);

		long elapsedTime = (System.currentTimeMillis() - start) / 1000;
		logger.info("Done! Identified affected products for {} CVEs! Elapsed time : {} seconds.", vulnList.size(), elapsedTime);
		logger.info("# of new CPE products identified: {}. # of products extracted from CVE descriptions and mapped to CPE items: {}", productCount, numOfProductsMappedToCpe);

		// prepare CVE summary table for Web UI
		logger.info("Preparing CVE summary table for Web UI...");
		PrepareDataForWebUi cveDataForWebUi = new PrepareDataForWebUi();
		cveDataForWebUi.prepareDataforWebUi();

		databaseHelper.shutdown();

		return numOfProductsMappedToCpe;

	}

}
