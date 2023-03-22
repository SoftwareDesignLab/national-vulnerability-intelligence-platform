package servlet;

import dao.UserDAO;
import model.User;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import static org.junit.Assert.assertEquals;

import static org.mockito.Mockito.*;

public class LoginServletTest {

    @Test
    public void testDoGetNoUser() {
        //Get the current db username/password
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("userName")).thenReturn("testNoUser");
        when(request.getParameter("passwordHash")).thenReturn("testPass");

        try {
            when(response.getWriter()).thenReturn(new PrintWriter(System.out));
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        LoginServlet loginServlet = new LoginServlet();

        //Note database username/password must be set in dbUser and dbPass
        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        try {
            loginServlet.handleRequest(request, response);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        //Verify user cannot log in due to not having an account
        verify(response).setStatus(404);
    }

    @Test
    public void testDoGet() {
        //Get the current db username/password
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("userName")).thenReturn("testUser");
        when(request.getParameter("passwordHash")).thenReturn("testPass");

        //Create user to ensure successful login
        User user = new User(null, "testUser", "testFirstName", "testLastName", "testEmail", 2);
        UserDAO.createUser(user, "testPass");

        try {
            when(response.getWriter()).thenReturn(new PrintWriter(System.out));
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        LoginServlet loginServlet = new LoginServlet();

        //Note database username/password must be set in dbUser and dbPass
        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        try {
            loginServlet.doGet(request, response);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        assertEquals(0, response.getStatus());
    }

    @Test
    public void testDoPostNoCreate() {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getParameter("createUser")).thenReturn("false");

        LoginServlet loginServlet = new LoginServlet();

        try {
            loginServlet.doPost(req, resp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        //Make sure if createUser is set to false, there are no other interactions with the response/request
        verify(req).getParameter("createUser");
        verifyNoMoreInteractions(req);
        verifyNoInteractions(resp);
        assertEquals(0, resp.getStatus());
    }
}