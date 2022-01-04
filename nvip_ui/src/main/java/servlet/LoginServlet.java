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

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;

import com.google.gson.Gson;

import dao.UserDAO;
import model.User;
import util.TwitterApi;

@WebServlet("/loginServlet")

/**
 * Handles Login/user-creation request within the web API,
 * All requests are submitted via user creation or login forms
 * @author RIT
 *
 */
public class LoginServlet extends HttpServlet {
	private static final Logger logger = LogManager.getLogger(LoginServlet.class);
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handleRequest(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handleRequestPost(req, resp);
	}

	/**
	 * Handles POST requests for creating a user
	 * Checks and verifies the inputed data before adding the user
	 * If an error exists, an HTML response will be sent
	 * @param req
	 * @param resp
	 * @throws ServletException
	 */
	public void handleRequestPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException {

		boolean createUser = Boolean.parseBoolean(req.getParameter("createUser"));

		if (createUser) {

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
				//TODO Auto-generated catch block
				e.printStackTrace();
			}

			String dataString = stringBuilder.toString();
			if (dataString == null) 
				ServletUtil.setResponse(resp, 500, "Something is wrong!");

			JSONObject userData = new JSONObject(dataString);

			String userName = userData.getString("username").toLowerCase();
			String password = userData.getString("password");
			String fname = userData.getString("fname");
			String lname = userData.getString("lname");
			String email = userData.getString("email");

			User user = new User(null, userName, fname, lname, email, 2);

			int rs = UserDAO.createUser(user, password);

			if (rs == -2) 
				ServletUtil.setResponse(resp, 409, "User already exists!");

			if (rs == -1) 
				ServletUtil.setResponse(resp, 500, "Something is wrong!");

			logger.info("Nvip UI user created login for {}", userName);

		}
	}

	/**
	 * Handles GET Requests for logging in
	 * Verifies username and password before logging in
	 * @param req
	 * @param resp
	 * @throws ServletException
	 */
	public void handleRequest(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
		String userName = req.getParameter("userName") == null ? "" : req.getParameter("userName");
		String passwordHash = req.getParameter("passwordHash") == null ? "" : req.getParameter("passwordHash");
		String jObj = null;
		JSONObject map = null;

		logger.info("Nvip UI user login for {}", userName);
		if (userName != null && passwordHash != null) {
			User user = null;

			user = UserDAO.login(userName, passwordHash);

			if (user != null) {
				jObj = new Gson().toJson(user);
			} else {
				ServletUtil.setResponse(resp, 404, "Login or Password is incorrect!");
				return;
			}
		}

		try {
			resp.setContentType("text/html");
			resp.setCharacterEncoding("UTF-8");
			resp.getWriter().write(jObj);
		} catch (IOException e) {
			logger.error(e.toString());
		}
	}
	
	
	
	
}
