package servlet;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;

public class ServletUtil {
	
	/**
	 * Helper function for setting an HTMl response
	 * All responses are displayed via pop up if there's an HTML error
	 * @param resp
	 * @param code
	 * @param message
	 * @throws ServletException
	 */
	public static void setResponse(HttpServletResponse resp, int code, String message) throws ServletException {
		try {
			resp.setStatus(code);
			resp.setContentType("text/html");
			resp.setCharacterEncoding("UTF-8");
			resp.getWriter().write(message);
			return;
		} catch (IOException e) {
			LogManager.getLogger(LoginServlet.class).error(e.toString());
		}
	}
}
