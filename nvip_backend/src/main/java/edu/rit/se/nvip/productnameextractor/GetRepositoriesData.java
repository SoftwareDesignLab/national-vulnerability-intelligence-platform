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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import edu.rit.se.nvip.utils.UtilHelper;

/**
 * This class is for GitHub repositories dataset generation
 * @author Igor Khokhlov
 *
 */

public class GetRepositoriesData {
	
	static private Logger logger = LogManager.getLogger(UtilHelper.class);
	
	private static String myToken = "";
	private static String login = "";
	
	private static boolean removeRepoFlag = false;
	
	/**
	 * Gets data from GitHub
	 * @param String path to the intermediate repositories file (without tags)
	 * @param String path to the final repositories file (with tags)
	 * @param String user token (for GitHub)
	 * @param String user login (for GitHub)
	 */		

	public static void main(String[] args) {
		
		String mapFileName = args[0];
		String mapWithTagsFileName = args[1];
		
		myToken = args[2];
		login = args[3];
		
		HashMap<String, RepoFullName> openSourceBase = new HashMap<String, RepoFullName>(); 
			
		boolean getTags = true;
		boolean formRepoMap = true;
				
		int requestsPerMinute = 30;
		int delayInSeconds = 60/requestsPerMinute;

		String encodedString = Base64.getEncoder().encodeToString((login+":"+myToken).getBytes());
		String authString = "Basic " + encodedString;
		
		final HttpClient httpClient = new DefaultHttpClient();
		
		if(formRepoMap) {
			HashMap<String, CpeGroup> cpeMap = (HashMap<String, CpeGroup>)CpeLookUp.getInstance().getCpeMap();
			formRepoFullMap(mapFileName, openSourceBase, cpeMap, delayInSeconds, authString, httpClient);
		}
		
		if (getTags) {
			formRepoFullWithTagsMap(mapWithTagsFileName, openSourceBase, 100, authString, httpClient);
		}
		
	}
	
	private static HashMap<String, RepoFullNameWithTags> formRepoFullWithTagsMap(String mapFileName, HashMap<String, RepoFullName> openSourceBase,
			int delayInMs, String authString, final HttpClient httpClient) {
		
		logger.info("Starting getting tags...");
		
		HashMap<String, RepoFullNameWithTags> reposWithTags = new HashMap<String, RepoFullNameWithTags>();
		
		int counter = 0;
		int numSaved = 0;
		
		for (Map.Entry<String, RepoFullName> entry : openSourceBase.entrySet()) {
			removeRepoFlag = false;
			RepoFullNameWithTags repoObject = getRepoWithTags(httpClient, authString, entry.getValue(), delayInMs);
			
			counter++;
			
			if (repoObject!=null && !removeRepoFlag) {
				reposWithTags.put(entry.getKey(), repoObject);
			}
			
			if (counter%50==0) {
				int percentage = (int) (((float)counter)/((float)openSourceBase.size())*100);
				logger.info("Processed " + Integer.toString(counter) + " CPE items out of " + Integer.toString(openSourceBase.size()) + ", which is " + Integer.toString(percentage) + "%. Found " + Integer.toString(openSourceBase.size()) + " items.");
				
				if(numSaved!=reposWithTags.size()) {
					FirstCommitWithCVE.saveMapWithTags(mapFileName, reposWithTags);
					numSaved = reposWithTags.size();
					logger.info("Intermediate results are saved!");
				}				
			}
		}
		
		logger.info("Done! Found " + Integer.toString(reposWithTags.size()) + " items.");
		FirstCommitWithCVE.saveMapWithTags(mapFileName, reposWithTags);
		logger.info("Results are saved!");
		
		return reposWithTags;
		
	}

	private static void formRepoFullMap(String mapFileName, HashMap<String, RepoFullName> openSourceBase,
			HashMap<String, CpeGroup> cpeMap, int delayInSeconds, String authString, final HttpClient httpClient) {
		int counter = 0;
		int numSaved = 0;
		
		for (Map.Entry<String, CpeGroup> entry : cpeMap.entrySet()) {
			RepoFullName repoObject = checkGroup(entry.getValue(), httpClient, authString, 0);
			
			counter++;
			
			if (repoObject!=null) {
				openSourceBase.put(entry.getKey(), repoObject);
			}
			
			if (counter%50==0) {
				int percentage = (int) (((float)counter)/((float)cpeMap.size())*100);
				logger.info("Processed " + Integer.toString(counter) + " CPE items out of " + Integer.toString(cpeMap.size()) + ", which is " + Integer.toString(percentage) + "%. Found " + Integer.toString(openSourceBase.size()) + " items.");
				
				if(numSaved!=openSourceBase.size()) {
					saveMap(mapFileName, openSourceBase);
					numSaved = openSourceBase.size();
					logger.info("Intermediate results are saved!");
				}				
			}
			
			try {
				TimeUnit.SECONDS.sleep(delayInSeconds);
			} catch (InterruptedException e) {
				logger.error(e.toString());
			}
		}
		
		logger.info("Done! Found " + Integer.toString(openSourceBase.size()) + " items.");
		saveMap(mapFileName, openSourceBase);
		logger.info("Results are saved!");
	}
	
	static ArrayList<RepoTag> getTagsPage(HttpClient httpClient, String authString, int itemsPerPage, int currentPage, int tryNum, RepoFullName repoToCheck){
		ArrayList<RepoTag> tagsList = new ArrayList<RepoTag>();
		
		int numOfTries = 10;
		
		if (tryNum>=numOfTries) {
			logger.info("Reached max number of tries. Exiting recursion.");
			return null;
		}
		
		String apiURL = repoToCheck.getUrl() + "/tags";
		
		String rateLimit = "API rate limit exceeded";
		
		final HttpGet httpGet = new HttpGet(apiURL);

		try {
			URI uri = new URIBuilder(httpGet.getURI()).addParameter("per_page", Integer.toString(itemsPerPage)).addParameter("page", Integer.toString(currentPage)).build();
			httpGet.setURI(uri);
		} catch (URISyntaxException e) {
			logger.error(e.toString());
		}
		
		httpGet.addHeader("Authorization", authString);
		
		logger.info("Page: " + Integer.toString(currentPage) + " For: " + apiURL);

		HttpResponse response = null;
		try {
		    response = httpClient.execute(httpGet);
		} catch (IOException ex) {
			logger.error(ex.toString());
		}
		
		BufferedReader reader = null;
		try {
		    reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		} catch (IOException ex) {
			logger.error(ex.toString());
		}
		
		String line = "";
		JSONObject answerJSON = null;
		JSONArray answerJSONarray = null;
		
		if(response.getStatusLine().getStatusCode()==404) {
			HttpEntity enty = response.getEntity();
	        if (enty != null)
				try {
					enty.consumeContent();
				} catch (IOException e) {
					logger.error(e.toString());
				}
			removeRepoFlag = true;
			return null;
		}
		
		while (true) {
		    try {
		        if (!((line = reader.readLine()) != null)) break;
		    } catch (IOException ex) {
		    	logger.error(ex.toString());
		    }
		    try {
		    	answerJSONarray = new JSONArray(line);
		    } catch (Exception e) {
		    	logger.error(e.toString());
		    }
		    if (answerJSONarray==null) {
		    	try {
			    	answerJSON = new JSONObject(line);
			    } catch (Exception e) {
			    	logger.error(e.toString());
			    }
		    }
		}
		
		if (answerJSONarray==null) {
			if (answerJSON == null) {
				return null;
			}
			
			if (answerJSON.has("message") && answerJSON.getString("message").contains(rateLimit)) {
				try {
					TimeUnit.SECONDS.sleep(10);
				} catch (InterruptedException e) {
					logger.error(e.toString());
				}
				tryNum++;
				logger.info("Request rate limit is reached. Try number: " + Integer.toString(tryNum));
				tagsList = getTagsPage(httpClient, authString, itemsPerPage, currentPage, tryNum, repoToCheck);
				return tagsList;
			}
		}
		
		
		
		int numOfResults = answerJSONarray.length();
		
		for(int i=0; i<numOfResults; i++) {
			JSONObject tagObject = answerJSONarray.getJSONObject(i);
			
			if (tagObject!=null) {
				JSONObject commitObject = tagObject.getJSONObject("commit");
				String name=null, url=null, nodeID=null, sha=null;
				name = tagObject.getString("name");
				nodeID = tagObject.getString("node_id");
				if (commitObject!=null) {
					url = commitObject.getString("url");
					sha = commitObject.getString("sha");
				}
				tagsList.add(new RepoTag(name, url, nodeID, sha));
			}
		}
				
		return tagsList;
	}
	
	static RepoFullNameWithTags getRepoWithTags(HttpClient httpClient, String authString, RepoFullName repoToCheck, int delayInMs) {
		
		RepoFullNameWithTags repoWithTags = new RepoFullNameWithTags(repoToCheck);
		
		ArrayList<RepoTag> tags = new ArrayList<RepoTag>();
		
		int itemsPerPage = 100;
		int currentPage = 1;
		
		while(true) {
			
			ArrayList<RepoTag> tagsFromPage = getTagsPage(httpClient, authString, itemsPerPage, currentPage, 0, repoToCheck);
			
			if(tagsFromPage!=null && tagsFromPage.size()>0) {
				tags.addAll(tagsFromPage);
			}
			
			if (tagsFromPage==null || tagsFromPage.size()<itemsPerPage) {
				break;
			}
			
			currentPage++;
			
			try {
				TimeUnit.MILLISECONDS.sleep(delayInMs);
			} catch (InterruptedException e) {
				logger.error(e.toString());
			}
		}
		
		repoWithTags.setTags(tags);
		return repoWithTags;
	}

	static RepoFullName checkGroup(CpeGroup cpeGroup, HttpClient httpClient, String authString, int tryNum) {
		
//		String request = "https://api.github.com/search/repositories?q=" + cpeGroup.getCommonTitle();
		
		int numOfTries = 10;
		
		if (tryNum>=numOfTries) {
			logger.info("Reached max number of tries. Exiting recursion.");
			return null;
		}
		
		String apiURL = "https://api.github.com/search/repositories";
		
		String rateLimit = "API rate limit exceeded";
		
		final HttpGet httpGet = new HttpGet(apiURL);

		try {
			URI uri = new URIBuilder(httpGet.getURI()).addParameter("q", cpeGroup.getCommonTitle()).build();
			httpGet.setURI(uri);
		} catch (URISyntaxException e) {
			logger.error(e.toString());
		}
		
		httpGet.addHeader("Authorization", authString);

		HttpResponse response = null;
		try {
		    response = httpClient.execute(httpGet);
		} catch (IOException ex) {
			logger.error(ex.toString());
		}
		
		BufferedReader reader = null;
		try {
		    reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		} catch (IOException ex) {
			logger.error(ex.toString());
		}
		
		String line = "";
		JSONObject answerJSON = null;
		while (true) {
		    try {
		        if (!((line = reader.readLine()) != null)) break;
		    } catch (IOException ex) {
		    	logger.error(ex.toString());
		    }
//		    logger.info(cpeGroup.getCommonTitle() + " RESULTS:  " + line);
		    answerJSON = new JSONObject(line);
		}
		
		if (answerJSON==null) {
			return null;
		}
		
		if (answerJSON.has("message") && answerJSON.getString("message").contains(rateLimit)) {
			try {
				TimeUnit.SECONDS.sleep(10);
			} catch (InterruptedException e) {
				logger.error(e.toString());
			}
			tryNum++;
			logger.info("Request rate limit is reached. Try number: " + Integer.toString(tryNum));
			RepoFullName repoObject = checkGroup(cpeGroup, httpClient, authString, tryNum);
			return repoObject;
		}
		
		int numOfResults = 0;
		
		try {
			numOfResults = answerJSON.getInt("total_count");
		} catch (Exception e) {
			logger.error(e.toString());
		}
		
		if (numOfResults<=0) {
			return null;
		}
		
		RepoFullName repoObject = processResponse(answerJSON, cpeGroup);
		
		return repoObject;
	}
	
	static RepoFullName processResponse(JSONObject responseJSON, CpeGroup cpeGroup) {
		
		JSONArray responseItems = responseJSON.getJSONArray("items");
		
		String productTitle = cpeGroup.getProduct().toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");
		String productVendor = cpeGroup.getVendor().toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");
		
		RepoFullName repoObject = null;
		
		for (int i=0; i<10 && i<responseItems.length(); i++) {
			String repoName = responseItems.getJSONObject(i).getString("name");
			repoName = repoName.toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");
			
			if (productTitle.equals(repoName)) {
				repoObject = new RepoFullName();
				repoObject.setCpeID(cpeGroup.getGroupID());
				repoObject.setCpeName(cpeGroup.getCommonTitle());
				repoObject.setFullName(responseItems.getJSONObject(i).getString("full_name"));
				repoObject.setUrl(responseItems.getJSONObject(i).getString("url"));
				repoObject.setHtmlUrl(responseItems.getJSONObject(i).getString("html_url"));
				
				String owner = responseItems.getJSONObject(i).getJSONObject("owner").getString("login");
				owner = owner.toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");
				
				if (productVendor.equals(owner)) {
					repoObject.setExactMatch(true);
//					break;
				}
				break;
			}
		}
		
		return repoObject;
	}
	
	static void saveMap(String mapfilename, HashMap<String, RepoFullName> openSourceBase) {
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
	
	public static HashMap<String, RepoFullName> loadRepoSerialization(String mapfilename) {

		HashMap<String, RepoFullName> repoMap = null;

		FileInputStream fis;
		try {
			fis = new FileInputStream(mapfilename);
			ObjectInputStream ois = new ObjectInputStream(fis);
			repoMap = (HashMap<String, RepoFullName>) ois.readObject();
			ois.close();
		} catch (Exception e) {
			logger.error(e.toString());
		} 

		return repoMap;
	}
	
}


