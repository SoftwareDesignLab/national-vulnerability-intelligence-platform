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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * FirstCommitWithCVE class finds first commits within open-source software where the given CVE was introduced
 * 
 * @author Igor Khokhlov
 *
 */

public class FirstCommitWithCVE {
	
	static private final Logger logger = LogManager.getLogger(UtilHelper.class);
	private HashMap<String, RepoFullNameWithTags> reposDataset;

	/** singleton instance of class */
	private static FirstCommitWithCVE firstCommitWithCVE = null;

	/**
	 * Thread safe singleton implementation
	 * 
	 * @return
	 */
	public static synchronized FirstCommitWithCVE getInstance() {
		if (firstCommitWithCVE == null)
			firstCommitWithCVE = new FirstCommitWithCVE();

		return firstCommitWithCVE;
	}

	/**
	 * Class constructor
	 */
	private FirstCommitWithCVE() {
		initialize();
	}

	/**
	 * Initializer
	 */
	private void initialize() {
		
		try {
			logger.info("Loading Repositories dataset...");
			MyProperties properties = new MyProperties();
			properties = new PropertyLoader().loadConfigFile(properties);

			String filename = properties.getDataDir() + "/repositoriesdata/githubdata.ser";
			reposDataset = loadRepoWithTagsSerialization(filename);
		}
		catch (Exception e) {
			logger.error("Error while initializing FirstCommitWithCVE, exception detail {}", e.toString());
		}
		
	}
	/**
	 * Looks for the repository and version (tag)
	 * 
	 * @param cpeItem String, cpeID
	 * @return information an=bout the repository and tag associated with the version, or NULL if did not find anything
	 */
	
	public FirstCommitSearchResult getFirstCommit(String cpeItem) {
		FirstCommitSearchResult result;
		
		// parse CPE id to elements
		String[] cpeIDelements = cpeItem.split(":");
		
		String vendor = cpeIDelements[3];
		String name = cpeIDelements[4];
		String version = cpeIDelements[5];
		String key = vendor + ":" + name;
		
		RepoFullNameWithTags repository = reposDataset.get(key);
		
		if (repository == null) {
			return null;
		}
		
		result = new FirstCommitSearchResult();
		result.setExactMatch();
		
		if(repository.getTags()!=null && repository.getTags().size()>0 && !version.equalsIgnoreCase("*")) {
			for (RepoTag tag:repository.getTags()) {
				if (tag.getName().contains(version.toLowerCase())) {
					result.fillFromTag(tag);
				}
			}
		}
		
		return result;
	}
	
	/**
	 * Saves HashMap of the dataset to a file
	 * 
	 * @param openSourceBase destination filename
	 * @param mapfilename dataset
	 */
	static void saveMapWithTags(String mapfilename, HashMap<String, RepoFullNameWithTags> openSourceBase) {
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(mapfilename);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
	        oos.writeObject(openSourceBase);
	        oos.close();
		} catch (Exception e) {
			logger.error(e.toString());
		}
	}
	
	/**
	 * Loads HashMap dataset from a file
	 * 
	 * @param mapfilename destination filename
	 * @return HashMap<String, > dataset
	 */
	public static HashMap<String, RepoFullNameWithTags> loadRepoWithTagsSerialization(String mapfilename) {

		HashMap<String, RepoFullNameWithTags> repoMap = null;

		FileInputStream fis;
		try {
			fis = new FileInputStream(mapfilename);
			ObjectInputStream ois = new ObjectInputStream(fis);
			repoMap = (HashMap<String, RepoFullNameWithTags>) ois.readObject();
			ois.close();
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return repoMap;
	}

}
