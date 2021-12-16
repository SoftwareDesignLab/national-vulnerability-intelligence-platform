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
package edu.rit.se.nvip;

import java.io.File;
import java.io.IOException;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.crawler.CveCrawlController;
import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.crawler.github.GithubScraper;
import edu.rit.se.nvip.cveprocess.CveLogDiff;
import edu.rit.se.nvip.cveprocess.CveProcessor;
import edu.rit.se.nvip.cvereconcile.AbstractCveReconciler;
import edu.rit.se.nvip.cvereconcile.CveReconcilerFactory;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.DbParallelProcessor;
import edu.rit.se.nvip.exploit.ExploitIdentifier;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.CompositeVulnerability.CveReconcileStatus;
import edu.rit.se.nvip.model.DailyRun;
import edu.rit.se.nvip.model.NvipSource;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.model.VulnerabilityAttribsForUpdate;
import edu.rit.se.nvip.nvd.PullNvdCveMain;
import edu.rit.se.nvip.productnameextractor.AffectedProductIdentifier;
import edu.rit.se.nvip.utils.PrepareDataForWebUi;
import edu.rit.se.nvip.utils.CveUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.NlpUtil;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * NVIP Main class, crawl CVEs from the provided source url list file
 * 
 * if you want to run nvip locally provide the path of the file that includes
 * source urls from the command line: Right click and then go to Run As->Run
 * Configurations->Arguments and enter a path, i.e.,
 * src/test/resources/cve-source-2URLs.txt
 * 
 * Otherwise, it will load the urls from the database
 * 
 * 
 * @author axoeec
 *
 */
public class NVIPMain {
	private static Logger logger = LogManager.getLogger(NVIPMain.class);

	// pull most recent CVEs from NVD
	boolean refreshNvdCveList = true;

	protected NumberFormat formatter = new DecimalFormat("#0.00");
	static String[] commandLineArgs = null;

	public static void main(String[] args) {

		commandLineArgs = args;

		// start nvip
		NVIPMain nvipMain = new NVIPMain();
		nvipMain.startNvip(); // run once now
	}

	/**
	 * if you want to run nvip locally provide the path of the file that includes
	 * source urls from the command line: In Eclipse Right click and then go to Run
	 * As->Run Configurations->Arguments and enter a path, i.e.,
	 * src/test/resources/cve-source-2URLs.txt
	 * 
	 * If you are running the jar file, provide the file path as parameter
	 * 
	 * 
	 * Otherwise, it will load source urls from the database
	 */
	public void startNvip() {
		try {
			// load properties file
			MyProperties propertiesNvip = new MyProperties();
			propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
			UtilHelper.initLog4j(propertiesNvip);

			printProperties(propertiesNvip); // print system params

			// check required data directories
			checkDataDirs(propertiesNvip);

			// get sources from the file or the database
			DatabaseHelper db = DatabaseHelper.getInstance();
			List<String> urls = new ArrayList<String>();

			if (!db.testDbConnection()) {
				String configFile = "src/main/resources/db-" + propertiesNvip.getDatabaseType() + ".properties";
				logger.error("Error in database connection! Please check if the database configured in {} is up and running!", configFile);
				System.exit(1);
			}

			if (commandLineArgs.length > 0) {
				urls = FileUtils.readLines(new File(commandLineArgs[0]));
				logger.info("Loaded {} source URLs from file {}, running NVIP in test mode!", urls.size(), commandLineArgs[0]);
			} else {
				List<NvipSource> sources = db.getNvipCveSources();
				if (sources.isEmpty())
					logger.error("No source URLs in the database to crawl! Please make sure to include at least one source URL in the 'nvipsourceurl' table!");

				for (NvipSource nvipSource : sources)
					urls.add(nvipSource.getUrl());
				logger.info("Loaded {} source URLs from database!", urls.size());
			}

			UtilHelper.setProperties(propertiesNvip);

			// start nvip crawlers
			startNvipProcesses(propertiesNvip, urls);
		} catch (IOException e) {
			logger.error("Error while starting NVIP: {}", e.toString());
		}
	}

	public void printProperties(MyProperties prop) {
		StringBuilder sb = new StringBuilder();

		for (Object key : prop.keySet()) {

			sb.append(String.format("%-40s", key) + "\t->\t" + prop.getProperty(key.toString()) + "\n");
		}

		logger.info("\n*** Parameters from Config File *** \n{}", sb.toString());
	}

	/**
	 * Merge CVES derived from the Git repo and CNAs. If a CVE exists at both
	 * sources, take the one at Git (overwrite). If a CVE exists at both sources and
	 * is reserved at Git, then, add a note to the description to indicate that.
	 * 
	 * The description of a reserved CVE on MITRE: ** RESERVED ** This candidate has
	 * been reserved by an organization or individual that will use it when
	 * announcing a new security problem. When the candidate has been publicized,
	 * the details for this candidate will be provided.
	 * 
	 * @param cveHashMapGithub
	 * @param cveHashMapScrapedFromCNAs
	 * @return
	 */
	private HashMap<String, CompositeVulnerability> mergeCVEsDerivedFromCNAsAndGit(HashMap<String, CompositeVulnerability> cveHashMapGithub,
			HashMap<String, CompositeVulnerability> cveHashMapScrapedFromCNAs) {

		logger.info("Merging {} scraped CVEs with {} Github", cveHashMapScrapedFromCNAs.size(), cveHashMapGithub.size());
		final String reservedStr = "** RESERVED **";
		HashMap<String, CompositeVulnerability> cveHashMapAll = new HashMap<>(); // merged CVEs
		cveHashMapAll.putAll(cveHashMapScrapedFromCNAs); // include all CVEs from CNAs

		NlpUtil nlpUtil = new NlpUtil();

		int cveCountReservedInGit = 0;
		int cveCountFoundOnlyInGit = 0;
		// iterate over CVEs from Git
		for (String cveId : cveHashMapGithub.keySet()) {
			// if a CVE derived from Git does not exist among the CVEs derived from CNAs,
			// then include it as is.
			CompositeVulnerability vulnGit = cveHashMapGithub.get(cveId);
			if (!cveHashMapAll.containsKey(cveId)) {
				cveHashMapAll.put(cveId, vulnGit);
				cveCountFoundOnlyInGit++;
			} else {
				/**
				 * Git CVE already exists among CVEs derived from CNAs, then look at
				 * descriptions!
				 */
				CompositeVulnerability vulnCna = cveHashMapAll.get(cveId);
				String newDescr = "";

				// if (vulnGit.getDescription().contains(reservedStr)) {
				if (CveUtils.isCveReservedEtc(vulnGit.getDescription())) {
					/**
					 * CVE is reserved/rejected etc in Mitre but nvip found a description for it.
					 */
					newDescr = reservedStr + " - NVIP Description: " + vulnCna.getDescription();
					cveCountReservedInGit++;

					// did we find garbage or valid description?
					if (nlpUtil.sentenceDetect(vulnCna.getDescription()) != null)
						vulnCna.setFoundNewDescriptionForReservedCve(true);
				} else {
					newDescr = vulnGit.getDescription(); // overwriting, assuming Git descriptions are worded better!
				}
				vulnCna.setDescription(newDescr);// update description

				// merge sources
				for (String sUrl : vulnGit.getSourceURL())
					vulnCna.addSourceURL(sUrl);

				cveHashMapAll.put(cveId, vulnCna); // update existing CVE
			}
		}

		logger.info("***Merged CVEs! Out of {} Git CVEs, CVEs that exist only in Git (Not found at any available CNAs): {}, CVEs that are reserved in Git (But found at CNAs): {}",
				cveHashMapGithub.size(), cveCountFoundOnlyInGit, cveCountReservedInGit);
		return cveHashMapAll;
	}

	/**
	 * crawl, reconcile, characterize, store CVEs
	 * 
	 * @param propertiesNvip
	 * @param urls
	 */
	private void startNvipProcesses(MyProperties propertiesNvip, List<String> urls) {

		// initialize logger, characterizer
		CveLogDiff cveLogger = new CveLogDiff(propertiesNvip);
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], propertiesNvip.getCveCharacterizationApproach(),
				propertiesNvip.getCveCharacterizationMethod(), false);

		if (refreshNvdCveList) {
			logger.info("Refreshing NVD feeds before running NVIP...");
			PullNvdCveMain.main(null); // update nvd CVEs
		}

		/**
		 * scrape CVEs from CVE Automation Working Group Git Pilot
		 */
		GithubScraper githubScraper = new GithubScraper();
		HashMap<String, CompositeVulnerability> cveHashMapGithub = githubScraper.scrapeGithub();

		/**
		 * Scrape CVE summary pages (frequently updated CVE providers)
		 */
		int count = 0;
		QuickCveCrawler crawler = new QuickCveCrawler();
		List<CompositeVulnerability> list = crawler.getCVEsfromKnownSummaryPages();
		for (CompositeVulnerability vuln : list)
			if (!cveHashMapGithub.containsKey(vuln.getCveId())) {
				count++;
				cveHashMapGithub.put(vuln.getCveId(), vuln);
			}
		logger.info("{} of {} CVEs found in the CNA summary pages did not exist in the Mitre GitHub repo.", count, list.size());

		/**
		 * crawl CVE from CNAs
		 */
		logger.info("Starting the NVIP crawl process now to look for CVEs at {} locations with {} threads...", urls.size(), propertiesNvip.getNumberOfCrawlerThreads());
		CveCrawlController crawlerController = new CveCrawlController(propertiesNvip);
		long crawlStartTime = System.currentTimeMillis();
		HashMap<String, CompositeVulnerability> cveHashMapScrapedFromCNAs = crawlerController.crawl(urls);
		long crawlEndTime = System.currentTimeMillis();

		// merge CVEs from two sources (CNAs and Github repo)
		HashMap<String, CompositeVulnerability> cveHashMapAll = mergeCVEsDerivedFromCNAsAndGit(cveHashMapGithub, cveHashMapScrapedFromCNAs);

		// process
		logger.info("Comparing CVES against NVD & MITRE..");
		String cveDataPathNvd = propertiesNvip.getDataDir() + "/nvd-cve.csv";
		String cveDataPathMitre = propertiesNvip.getDataDir() + "/mitre-cve.csv";
		CveProcessor cveProcessor = new CveProcessor(cveDataPathNvd, cveDataPathMitre);
		HashMap<String, List<Object>> cveListMap = cveProcessor.checkAgainstNvdMitre(cveHashMapAll); // CVEs not in Nvd, Mitre

		// Identify NEW CVEs. Reconcile for Characterization and DB processes
		List<CompositeVulnerability> crawledVulnerabilityList = cveListMap.get("all").stream().map(e -> (CompositeVulnerability) e).collect(Collectors.toList());
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
		identifyNewOrUpdatedCve(crawledVulnerabilityList, databaseHelper, propertiesNvip);

		// characterize
		logger.info("Characterizing and scoring NEW CVEs...");
		crawledVulnerabilityList = cveCharacterizer.characterizeCveList(crawledVulnerabilityList, databaseHelper); // characterize

		DailyRun dailyRunStats = insertStats(databaseHelper, crawledVulnerabilityList, cveListMap.get("nvd").size(), cveListMap.get("mitre").size(), cveListMap.get("nvd-mitre").size());
		int runId = dailyRunStats.getRunId();

		// insert/update CVEs in the NVIP database
		double dbTime = 0;
		try {
			long databaseStoreStartTime = System.currentTimeMillis();
			logger.info("Storing crawled {} CVEs into the NVIP database with run id: {}", crawledVulnerabilityList.size(), runId);
			new DbParallelProcessor().executeInParallel(crawledVulnerabilityList, runId);
			dbTime = (System.currentTimeMillis() - databaseStoreStartTime) / 60000.0;
			logger.info("Spent {} minutes to store {} vulnerabilties.", formatter.format(dbTime), crawledVulnerabilityList.size());
		} catch (Exception e) {
			logger.error("Error occurred while storing CVEs: {}", e.toString());
		}

		// log .csv files
		logger.info("Creating output CSV files...");
		cveLogger.logAndDiffCVEs(crawlStartTime, crawlEndTime, cveListMap, databaseHelper, runId);

		// record additional available stats
		recordAdditionalStats(databaseHelper, runId, dailyRunStats, crawlStartTime, crawlEndTime, dbTime);

		// Extract and save exploits
		if (propertiesNvip.isExploitScrapingEnabled()) {
			logger.info("Identifying exploits for {} exploits...", crawledVulnerabilityList.size());
			extractExploits(crawledVulnerabilityList, databaseHelper);
		}

		// save affected releases
		// this should be the last process, it is shutting down db connections!
		spawnProcessToIdentifyAndStoreAffectedReleases(crawledVulnerabilityList);

		logger.info("Done!");
	}

	/**
	 * Insert a stats record to db
	 * 
	 * @param databaseHelper
	 * @param totalCve
	 * @param totNotInNvd
	 * @param totNotInMitre
	 * @param totNotInBoth
	 * @return
	 */
	private DailyRun insertStats(DatabaseHelper databaseHelper, List<CompositeVulnerability> crawledVulnerabilityList, int totNotInNvd, int totNotInMitre, int totNotInBoth) {
		// insert a record to keep track of daily run history
		DailyRun dailyRunStats = new DailyRun();
		try {
			dailyRunStats.setRunDateTime(UtilHelper.longDateFormat.format(new Date()));
			dailyRunStats.setTotalCveCount(crawledVulnerabilityList.size());
			dailyRunStats.setNotInNvdCount(totNotInNvd);
			dailyRunStats.setNotInMitreCount(totNotInMitre);
			dailyRunStats.setNotInBothCount(totNotInBoth);

			// Count added/updated CVEs
			int addedCveCount = 0, updatedCveCount = 0;
			for (CompositeVulnerability vuln : crawledVulnerabilityList) {
				if (vuln.getCveReconcileStatus().equals(CveReconcileStatus.INSERT))
					addedCveCount++;
				else if (vuln.getCveReconcileStatus().equals(CveReconcileStatus.UPDATE))
					updatedCveCount++;
			}
			dailyRunStats.setAddedCveCount(addedCveCount);
			dailyRunStats.setUpdatedCveCount(updatedCveCount);

			int runId = databaseHelper.insertDailyRun(dailyRunStats);
			dailyRunStats.setRunId(runId);
		} catch (Exception e1) {
			logger.error("Error while recording stats! Could not get a run ID! - {}", e1.toString());
			System.exit(1);
		}
		return dailyRunStats;
	}

	/**
	 * Record additional stats
	 * 
	 * @param databaseHelper
	 * @param runId
	 * @param dailyRunStats
	 * @param crawlStartTime
	 * @param crawlEndTime
	 * @param dbTime
	 */
	private void recordAdditionalStats(DatabaseHelper databaseHelper, int runId, DailyRun dailyRunStats, long crawlStartTime, long crawlEndTime, double dbTime) {
		// calculate crawl time
		dailyRunStats.setCrawlTimeMin((float) ((crawlEndTime - crawlStartTime) / (1000.0 * 60)));
		dailyRunStats.setDatabaseTimeMin(dbTime);
		databaseHelper.updateDailyRun(runId, dailyRunStats);
	}

	/**
	 * This method checks if there are any exploits for the provided CVEs. It checks
	 * the CVE-->Exploit map in the NVIP exploit repository to retrieve associated
	 * exploits if any, and records them.
	 * 
	 * @param crawledVulnerabilityList
	 * @param databaseHelper
	 */
	private void extractExploits(List<CompositeVulnerability> crawledVulnerabilityList, DatabaseHelper databaseHelper) {
		ExploitIdentifier exploitIdentifier = new ExploitIdentifier(crawledVulnerabilityList, databaseHelper);
		int count = exploitIdentifier.identifyAndSaveExploits(crawledVulnerabilityList);
		logger.info("Extracted exploits for {} CVEs!", count);
	}

	/**
	 * This method spawns a background process to identify affected product(s) for
	 * each scraped CVE.
	 * 
	 * There are two options:
	 * 
	 * (1) The affected product(s) that is/are already mapped to CPE item(s) could
	 * be already derived from the CVE publisher (by crawlers). The process will
	 * simply add the product(s) to the database.
	 * 
	 * 
	 * (2) The affected product name could be predicted by the previously trained
	 * product name extraction model (LSTM). In that case the predicted product name
	 * (string) should be mapped to a CPE item first. After that, it will be added
	 * to the database.
	 * 
	 * @param crawledVulnerabilityList
	 */
	private void spawnProcessToIdentifyAndStoreAffectedReleases(List<CompositeVulnerability> crawledVulnerabilityList) {
		AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(crawledVulnerabilityList);
		affectedProductIdentifier.start();
	}

	/**
	 * Identify new CVEs in the crawled CVE list, to determine which ones to
	 * characterize. We do not want to characterize all crawled CVEs. The output of
	 * this method is used while storing CVEs into the DB as well. DatabaseHelper
	 * will update/insert new CVEs only!
	 * 
	 * 
	 * @param crawledVulnerabilityList
	 * @param databaseHelper
	 * @return
	 */
	private List<CompositeVulnerability> identifyNewOrUpdatedCve(List<CompositeVulnerability> crawledVulnerabilityList, DatabaseHelper databaseHelper, MyProperties propertiesNvip) {

		logger.info("Reconciling {} CVEs...", crawledVulnerabilityList.size());
		long startTime = System.currentTimeMillis();
		CveReconcilerFactory reconcileFactory = new CveReconcilerFactory();
		AbstractCveReconciler cveReconciler = reconcileFactory.createReconciler(propertiesNvip.getCveReconciliationMethod());

		Map<String, Vulnerability> existingVulnMap = databaseHelper.getExistingVulnerabilities();

		int countUpdate = 0, countInsert = 0;
		for (int index = 0; index < crawledVulnerabilityList.size(); index++) {
			CompositeVulnerability vuln = crawledVulnerabilityList.get(index);

			// does CVE exist in the DB?
			if (existingVulnMap.containsKey(vuln.getCveId())) {
				Vulnerability existingAttribs = existingVulnMap.get(vuln.getCveId());
				String existingDescription = existingAttribs.getDescription(); // get existing description

				// do we need to update it?
				if (cveReconciler.reconcileDescriptions(existingDescription, vuln.getDescription(), null, vuln.getSourceDomainName(), false)) {
					countUpdate++;
					vuln.setCveReconcileStatus(CveReconcileStatus.UPDATE);
				} else {
					vuln.setCveReconcileStatus(CveReconcileStatus.DO_NOT_CHANGE); // no significant change
					continue;
				}

			} else {
				vuln.setCveReconcileStatus(CveReconcileStatus.INSERT); // does not exist, need to insert CVE
				countInsert++;
			}

			crawledVulnerabilityList.set(index, vuln); // update list
		}
		double minutes = (System.currentTimeMillis() - startTime) / 60.0 * 60 * 1000; // get elapsed minutes
		logger.info("Reconciling done! Identified {} new CVEs. {} and {} CVEs will be inserted and updated on the DB, respectively. Time{min} elapsed: {} ", (countInsert + countUpdate), countInsert,
				countUpdate, minutes);

		return crawledVulnerabilityList;
	}

	/**
	 * check required data dirs before run
	 */
	private void checkDataDirs(MyProperties propertiesNvip) {
		String dataDir = propertiesNvip.getDataDir();

		if (!new File(dataDir).exists()) {
			logger.error("The data dir is not configured properly, check the 'dataDir' key in the nvip.properties file, currently configured data dir is {}", dataDir);
			System.exit(1);
		}

		String characterizationDir = dataDir + "/characterization";
		if (!new File(characterizationDir).exists()) {
			logger.error("No training data for CVE characterization! Make sure you have the directory {} that includes required training data for CVE characterization!", characterizationDir);
			System.exit(1);
		}

		String cvssDir = dataDir + "/cvss";
		if (!new File(cvssDir).exists()) {
			logger.error("Make sure you have the directory {} that is required for CVSS scoring!", cvssDir);
			System.exit(1);
		}

		String productExtrcationDir = dataDir + "/productnameextraction";
		if (!new File(productExtrcationDir).exists()) {
			logger.error("No training data for CPE extraction! Make sure you have the directory {}!", productExtrcationDir);
			System.exit(1);
		}
	}

}
