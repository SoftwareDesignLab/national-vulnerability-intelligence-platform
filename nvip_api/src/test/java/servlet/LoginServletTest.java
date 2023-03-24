/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package servlet;

import dao.UserDAO;
import data.DBConnect;
import model.User;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
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

        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

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

        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

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

    @Test
    public void testDoPostExistingUser() {
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

        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpServletRequest req = mock(HttpServletRequest.class);

        when (req.getParameter("createUser")).thenReturn("true");

        //Mock the request's reader
        BufferedReader buffMock = mock(BufferedReader.class);
        try {
            //Set mocked buffered reader as requests reader
            when(req.getReader()).thenReturn(buffMock);
            //Insert test arguments
            when(buffMock.readLine()).thenReturn("{username:testUser, password:testPass, fname:testFirstName, lname:testLastName, email:testEmail@rit.edu}", null);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        //Mock the responses writer
        PrintWriter printMock = mock(PrintWriter.class);
        try {
            when(resp.getWriter()).thenReturn(printMock);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        LoginServlet loginServlet = new LoginServlet();

        //Create test user to ensure user is already created when trying to log in
        User testUser = new User(null, "testUser", "testFirstName", "testLastName", "testEmail@rit.edu", 2);
        UserDAO.createUser(testUser, "testPass");

        try {
            loginServlet.doPost(req, resp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        verify(resp).setStatus(409);
        verify(printMock).write("User already exists!");

    }

    @Test
    public void testDoPostNewUser() {
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

        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpServletRequest req = mock(HttpServletRequest.class);

        when (req.getParameter("createUser")).thenReturn("true");

        //Mock the request's reader
        BufferedReader buffMock = mock(BufferedReader.class);
        try {
            //Set mocked buffered reader as requests reader
            when(req.getReader()).thenReturn(buffMock);
            //Insert test arguments
            when(buffMock.readLine()).thenReturn("{username:testUserNew, password:testPass, fname:testFirstNameNew, lname:testLastNameNew, email:testEmailNew@rit.edu}", null);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        //Remove user if they exist in the table to allow for new user creation
        try {
            Connection conn = DBConnect.getConnection();
            PreparedStatement statement = conn.prepareStatement("DELETE FROM user WHERE (user_name = 'testusernew') AND (first_name = 'testFirstNameNew') AND (last_name = 'testLastNameNew')");
            statement.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        LoginServlet loginServlet = new LoginServlet();

        try {
            loginServlet.doPost(req, resp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        verifyNoInteractions(resp);
        assertEquals(0, resp.getStatus());

    }
}