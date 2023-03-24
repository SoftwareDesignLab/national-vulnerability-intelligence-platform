package servlet;

import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import static org.mockito.Mockito.*;

public class ReviewServletTest{

    @Test
    public void testDoGetUnauthorizedUser() {
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        //Note database username/password must be set in dbUser and dbPass
        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        when(req.getParameter("username")).thenReturn("testUsername");
        when(req.getParameter("token")).thenReturn(null);

        //Setup mock writer for response
        PrintWriter printMock = mock(PrintWriter.class);
        try {
            when(resp.getWriter()).thenReturn(printMock);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        ReviewServlet reviewServlet = new ReviewServlet();
        try {
            reviewServlet.doGet(req, resp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        verify(resp, times(2)).setStatus(401);
        verify(printMock).write("Unauthorized user!");
        verify(printMock).write("Unauthorized user by id get!");
    }
}