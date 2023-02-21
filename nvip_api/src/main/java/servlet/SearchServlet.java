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

import java.io.IOException;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import dao.LocalDateSerializer;
import dao.SearchDAO;
import dao.UserDAO;
import model.User;
import model.Vulnerability;
import serializer.GsonUtil;

@WebServlet("/searchServlet")

public class SearchServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger logger = LogManager.getLogger(SearchServlet.class);

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handleRequest(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handleRequest(req, resp);
	}

	public void handleRequest(HttpServletRequest req, HttpServletResponse resp) throws ServletException {

		String userName = req.getParameter("username");
		String token = req.getParameter("token");

		if (userName == null || token == null)
			ServletUtil.setResponse(resp, 401, "Unauthorized user!");

		User user = UserDAO.getRoleIDandExpirationDate(userName, token);

		if (user == null)
			ServletUtil.setResponse(resp, 401, "Unauthorized user!");

		GsonBuilder gsonBuilder = new GsonBuilder();
		gsonBuilder.registerTypeAdapter(LocalDate.class, new LocalDateSerializer());
		Gson gson = gsonBuilder.setPrettyPrinting().create();

		boolean searchInfo = Boolean.parseBoolean(req.getParameter("searchInfo"));

		JsonObject map = null;

		// Section for Search Form info. Used when Search Form is initialized
		if (searchInfo) {
			Map<String, Map<String, String[]>> searchMap = SearchDAO.getSearchInfo();
			map = new JsonObject();

			String jObj = gson.toJson(searchMap);

			generateResp(jObj, resp);

			return; // End the method
		}

		String keyword = req.getParameter("keyword") == null ? null : req.getParameter("keyword").split(" ")[0];
		String cve_id = req.getParameter("cve_id") == null ? null : req.getParameter("cve_id").split(" ")[0];
		// If there is no keyword or cve_id, do not query the database

		// Retrieve the results from the most recent search (Used for back button on
		// vulnerability)

		if (cve_id != null) {
			Map<Integer, List<Vulnerability>> searchResults = SearchDAO.getSearchResultsByID(cve_id);
			int totalCount = 1;

			JsonArray arr = GsonUtil.toJsonArray(gson, searchResults.get(totalCount), List.class);
			arr.add(totalCount);
			String jObj = gson.toJson(arr);

			generateResp(jObj, resp);
		}

		else if (keyword != null) {

			int vulnId = req.getParameter("vulnId") == null ? 0 : Integer.parseInt(req.getParameter("vulnId"));
			LocalDate startDate = req.getParameter("startDate") == null ? null
					: LocalDate.parse(req.getParameter("startDate"));
			LocalDate endDate = req.getParameter("endDate") == null ? null
					: LocalDate.parse(req.getParameter("endDate"));
			String[] cvssScores = req.getParameterValues("cvssScores") == null ? null
					: req.getParameterValues("cvssScores");
			String[] vdoLabels = req.getParameterValues("vdoLabels") == null ? null
					: req.getParameterValues("vdoLabels");
			int limitCount = req.getParameter("limitCount") == null ? 0
					: Integer.parseInt(req.getParameter("limitCount"));
			String product = req.getParameter("product") == null ? null : req.getParameter("product");

			Map<Integer, List<Vulnerability>> searchResults = SearchDAO.getSearchResults(vulnId, keyword, startDate,
					endDate, cvssScores, vdoLabels, limitCount, product);

			int totalCount = searchResults.entrySet().stream().findFirst().get().getKey();

			// Preferred implementation but searchResults fails to get passed for some
			// reason
			// TODO: Let's see if we can get this working

			/*
			 * map = new JsonObject(); map.add("searchResults", GsonUtil.toJsonArray(gson,
			 * searchResults.get(totalCount), List.class)); map.addProperty("totalCount",
			 * totalCount);
			 */

			// Places the total count at the end of the array of vulnerabilities. Count is
			// popped off the end of the array in the controller

			JsonArray arr = GsonUtil.toJsonArray(gson, searchResults.get(totalCount), List.class);
			arr.add(totalCount);
			String jObj = gson.toJson(arr);

			generateResp(jObj, resp);
		} else {
			// Default search for vulnerabilities
			generateResp("", resp);
		}

	}

	/**
	 * Helper function for generating Http responses
	 * 
	 * @param jObj
	 * @param resp
	 */
	private void generateResp(String jObj, HttpServletResponse resp) {
		try {

			resp.setContentType("text/html");
			resp.setCharacterEncoding("UTF-8");
			resp.getWriter().write(jObj);
		} catch (IOException e) {
			logger.error(e.toString());
		}
	}
}