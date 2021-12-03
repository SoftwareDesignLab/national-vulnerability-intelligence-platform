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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;

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
	
	static private Logger logger = LogManager.getLogger(UtilHelper.class);
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
	 * @return FirstCommitSearchResult information an=bout the repository and tag associated with the version, or NULL if did not find anything
	 */
	
	public FirstCommitSearchResult getFirstCommit(String cpeItem) {
		FirstCommitSearchResult result = null;
		
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
		
		result = new FirstCommitSearchResult(repository.getUrl(), repository.getFullName(), repository.getCpeName(), repository.getCpeID(), repository.getHtmlUrl());
		result.setExactMatch(repository.isExactMatch());
		
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
	 * @param String destination filename
	 * @param HashMap<String, RepoFullNameWithTags> dataset
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
	 * @param String destination filename
	 * @return HashMap<String, RepoFullNameWithTags> dataset
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
	
	/**
	 * Converts JSON file to HashMap dataset and saves it to a file
	 * 
	 * @param String source filename (JSON)
	 * @param String destination filename
	 */
	public static void convertJSONtoDataset(String jsonPath, String datasetPath) {
		File f = new File(jsonPath);
		JSONObject json = null;
        if (f.exists()){
            InputStream is;
			try {
				is = new FileInputStream(jsonPath);
				String jsonTxt = IOUtils.toString(is, "UTF-8");
				json = new JSONObject(jsonTxt); 
			} catch (Exception e) {
				logger.error(e.toString());
			}
        }
        
        if (json==null) {
        	logger.error("Repositories JSON is NULL! JSON file path is {}", jsonPath);
        	return;
        }
        
        HashMap<String, RepoFullNameWithTags> repoMap = new HashMap<String, RepoFullNameWithTags>();
        
        Iterator<String> keys = json.keys();
        while(keys.hasNext()) {
            String key = keys.next();
            repoMap.put(key, new RepoFullNameWithTags(json.getJSONObject(key)));
        }
        
        saveMapWithTags(datasetPath, repoMap);
	}
}
