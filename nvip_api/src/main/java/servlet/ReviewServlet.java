/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package servlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import dao.LocalDateSerializer;
import dao.ReviewDAO;
import dao.SearchDAO;
import dao.UserDAO;
import model.CVSSupdate;
import model.User;
import model.VDOupdateInfo;
import model.Vulnerability;
import model.VulnerabilityDetails;
import model.VulnerabilityForReviewList;
import serializer.GsonUtil;
import util.TwitterApi;

@WebServlet("/reviewServlet")

public class ReviewServlet extends HttpServlet {

	private static final Logger logger = LogManager.getLogger(LoginServlet.class);
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handleRequestGet(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handleRequestPost(req, resp);
	}

	public void handleRequestPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException {

		GsonBuilder gsonBuilder = new GsonBuilder();
		gsonBuilder.registerTypeAdapter(LocalDate.class, new LocalDateSerializer());
		Gson gson = gsonBuilder.setPrettyPrinting().create();

		boolean complexUpdate = Boolean.parseBoolean(req.getParameter("complexUpdate"));
		boolean atomicUpdate = Boolean.parseBoolean(req.getParameter("atomicUpdate"));
		boolean updateDailyTable = Boolean.parseBoolean(req.getParameter("updateDailyTable"));

		String userName = req.getParameter("username");
		String token = req.getParameter("token");

		if (userName == null || token == null)
			ServletUtil.setResponse(resp, 401, "Unauthorized user!");

		User user = UserDAO.getRoleIDandExpirationDate(userName, token);

		if (user == null || user.getRoleId() < 1 || user.getRoleId() > 2) 
			ServletUtil.setResponse(resp, 401, "Unauthorized user!");
		
		//Info needed for twitter
		boolean isTweet = false;
		String cveDescriptionTweet = null;
		
		String cveID = req.getParameter("cveID");
		
		if (atomicUpdate) {
			int statusID = Integer.parseInt(req.getParameter("statusID"));
			int userID = user.getUserID();

			int vulnID = Integer.parseInt(req.getParameter("vulnID"));
			String info = req.getParameter("info");
			ReviewDAO.atomicUpdateVulnerability(statusID, vulnID, userID, cveID, info);
			
			if (statusID==4) {
				
				isTweet = Boolean.parseBoolean(req.getParameter("tweet"));
				StringBuilder stringBuilder = new StringBuilder();
				BufferedReader bufferedReader = null;

				try {
					bufferedReader = req.getReader();
					String line;
					while ((line = bufferedReader.readLine()) != null) {
						stringBuilder.append(line);
						stringBuilder.append(System.lineSeparator());
					}
				} catch (IOException e) {
					e.printStackTrace();
				}

				cveDescriptionTweet = stringBuilder.toString();
				
			}

		} else if (complexUpdate) {

			boolean updateDescription = Boolean.parseBoolean(req.getParameter("updateDescription"));
			boolean updateVDO = Boolean.parseBoolean(req.getParameter("updateVDO"));
			boolean updateCVSS = Boolean.parseBoolean(req.getParameter("updateCVSS"));
			boolean updateAffRel = Boolean.parseBoolean(req.getParameter("updateAffRel"));

			int statusID = Integer.parseInt(req.getParameter("statusID"));
			int userID = user.getUserID();
			int vulnID = Integer.parseInt(req.getParameter("vulnID"));

			StringBuilder stringBuilder = new StringBuilder();
			BufferedReader bufferedReader = null;

			try {
				bufferedReader = req.getReader();
				String line;
				while ((line = bufferedReader.readLine()) != null) {
					stringBuilder.append(line);
					stringBuilder.append(System.lineSeparator());
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

			String dataString = stringBuilder.toString();
			if (dataString == null)
				return;

			JSONObject dataJSON = new JSONObject(dataString);

			String descriptionToUpdate = dataJSON.getString("descriptionToUpdate");

			String cveDescription = null;
			VDOupdateInfo vdoUpdate = null;
			CVSSupdate cvssUpdate = null;
			int[] productsToRemove = null;

			if (updateDescription) {
				cveDescription = dataJSON.getString("description");
			}

			if (updateVDO) {
				vdoUpdate = new VDOupdateInfo(dataJSON.getJSONObject("vdoUpdates"));
			}

			if (updateCVSS) {
				cvssUpdate = new CVSSupdate(dataJSON.getJSONObject("cvss"));
			}

			if (updateAffRel) {
				JSONArray jsonArray = dataJSON.getJSONArray("prodToRemove");
				productsToRemove = new int[jsonArray.length()];
				for (int i = 0; i < jsonArray.length(); i++) {
					productsToRemove[i] = jsonArray.getInt(i);
				}
			}

			ReviewDAO.complexUpdate(updateDescription, updateVDO, updateCVSS, updateAffRel, statusID, vulnID, userID, cveID, descriptionToUpdate, cveDescription, vdoUpdate, cvssUpdate,
					productsToRemove);

		} else if (updateDailyTable) {
			int out = ReviewDAO.updateDailyVulnerability(3);

			try {
				resp.setContentType("text/html");
				resp.setCharacterEncoding("UTF-8");
				resp.getWriter().write(Integer.toString(out));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		/**
		 * Enable to tweet approved CVEs. <cveDescription> should be set to the approved
		 * CVE description
		 */
		if (isTweet && cveDescriptionTweet!=null && cveDescriptionTweet.length()>0) {
			TwitterApi twitterApi = new TwitterApi();
			twitterApi.postTweet(cveID, cveDescriptionTweet, false);
		}

	}

	public void handleRequestGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
		GsonBuilder gsonBuilder = new GsonBuilder();
		gsonBuilder.registerTypeAdapter(LocalDate.class, new LocalDateSerializer());
		Gson gson = gsonBuilder.setPrettyPrinting().create();

		String userName = req.getParameter("username");
		String token = req.getParameter("token");

		if (userName == null || token == null) 
			ServletUtil.setResponse(resp, 401, "Unauthorized user!");

		User user = UserDAO.getRoleIDandExpirationDate(userName, token);

		if (user == null || user.getRoleId() < 1 || user.getRoleId() > 2) 
			ServletUtil.setResponse(resp, 401, "Unauthorized user by id get!");

		String cveID = req.getParameter("cveID");

		String jObj = null;

		if (cveID != null) {
			VulnerabilityDetails vulnDetails = ReviewDAO.getVulnerabilityDetails(cveID);
			jObj = gson.toJson(vulnDetails);
		} else {
			LocalDate searchDate = req.getParameter("searchDate") == null ? null : LocalDate.parse(req.getParameter("searchDate"));

			boolean crawled = req.getParameter("crawled") == null ? false : Boolean.parseBoolean(req.getParameter("crawled"));
			boolean rejected = req.getParameter("rejected") == null ? false : Boolean.parseBoolean(req.getParameter("rejected"));
			boolean accepted = req.getParameter("accepted") == null ? false : Boolean.parseBoolean(req.getParameter("accepted"));
			boolean reviewed = req.getParameter("reviewed") == null ? false : Boolean.parseBoolean(req.getParameter("reviewed"));

			List<VulnerabilityForReviewList> searchResults = ReviewDAO.getSearchResults(searchDate, crawled, rejected, accepted, reviewed);

			int totalCount = searchResults.size();

			// Preferred implementation but searchResults fails to get passed for some
			// reason
			/*
			 * map = new JsonObject(); map.add("searchResults", GsonUtil.toJsonArray(gson,
			 * searchResults.get(totalCount), List.class)); map.addProperty("totalCount",
			 * totalCount);
			 */

			// Places the total count at the end of the array of vulnerabilities. Count is
			// popped off the end of the array in the controller
			JsonArray arr = GsonUtil.toJsonArray(gson, searchResults, List.class);
			arr.add(totalCount);
			jObj = gson.toJson(arr);
		}

		try {
			resp.setContentType("text/html");
			resp.setCharacterEncoding("UTF-8");
			resp.getWriter().write(jObj);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}